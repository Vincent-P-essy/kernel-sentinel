package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	apiServer "github.com/Vincent-P-essy/kernel-sentinel/internal/api"
	"github.com/Vincent-P-essy/kernel-sentinel/internal/detection"
	"github.com/Vincent-P-essy/kernel-sentinel/internal/enrich"
	"github.com/Vincent-P-essy/kernel-sentinel/internal/pipeline"
	"github.com/Vincent-P-essy/kernel-sentinel/internal/probe"
	"github.com/Vincent-P-essy/kernel-sentinel/internal/source"
	"github.com/Vincent-P-essy/kernel-sentinel/internal/store"
)

const version = "0.1.0"

type config struct {
	source      string
	replayPath  string
	replaySpeed float64
	rulesPath   string
	listen      string
	alertPath   string
	behavioral  bool
	exitOnEOF   bool
	healthcheck string
	showVersion bool
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "kernel-sentinel:", err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	configuration, err := parseFlags(arguments)
	if err != nil {
		return err
	}
	if configuration.showVersion {
		fmt.Println("kernel-sentinel", version)
		return nil
	}
	if configuration.healthcheck != "" {
		return checkHealth(configuration.healthcheck)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	rules, err := detection.LoadRules(configuration.rulesPath)
	if err != nil {
		return err
	}
	eventSource, enricher, err := buildSource(configuration)
	if err != nil {
		return err
	}
	alertWriter, closeWriter, err := openAlertWriter(configuration.alertPath)
	if err != nil {
		eventSource.Close()
		return err
	}
	defer closeWriter()

	eventStore := store.New(5000, 2000)
	if provider, ok := eventSource.(store.ProbeStatsProvider); ok {
		eventStore.SetProbeStatsProvider(provider)
	}
	engine := detection.NewEngine(rules, configuration.behavioral)
	processing := &pipeline.Pipeline{
		Source:   eventSource,
		Engine:   engine,
		Store:    eventStore,
		Enricher: enricher,
		Alerts:   alertWriter,
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	pipelineResult := make(chan error, 1)
	go func() { pipelineResult <- processing.Run(ctx) }()
	var apiResult chan error
	if configuration.listen != "" {
		apiResult = make(chan error, 1)
		server := apiServer.NewServer(configuration.listen, eventStore, rules, logger)
		go func() { apiResult <- server.Run(ctx) }()
	}

	logger.Info("runtime engine started", "source", configuration.source, "rules", len(rules), "behavioral", configuration.behavioral)
	for {
		select {
		case pipelineErr := <-pipelineResult:
			if pipelineErr != nil {
				cancel()
				return pipelineErr
			}
			if configuration.exitOnEOF || configuration.listen == "" {
				cancel()
				return nil
			}
			logger.Info("event source completed; API remains available")
			pipelineResult = nil
		case apiErr := <-apiResult:
			if apiErr != nil {
				cancel()
				return fmt.Errorf("alert API: %w", apiErr)
			}
			apiResult = nil
		case <-ctx.Done():
			return nil
		}
	}
}

func parseFlags(arguments []string) (config, error) {
	flags := flag.NewFlagSet("kernel-sentinel", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configuration := config{}
	flags.StringVar(&configuration.source, "source", "replay", "event source: replay or live")
	flags.StringVar(&configuration.replayPath, "replay", "lab/events/attack-suite.jsonl", "JSONL replay path or - for stdin")
	flags.Float64Var(&configuration.replaySpeed, "speed", 0, "replay speed multiplier; zero runs without delay")
	flags.StringVar(&configuration.rulesPath, "rules", "rules", "rule file or directory")
	flags.StringVar(&configuration.listen, "listen", "127.0.0.1:8081", "dashboard/API listen address; empty disables")
	flags.StringVar(&configuration.alertPath, "alerts", "-", "alert JSONL output path or - for stdout")
	flags.BoolVar(&configuration.behavioral, "behavioral", true, "enable decaying behavioral risk scoring")
	flags.BoolVar(&configuration.exitOnEOF, "exit-on-eof", false, "exit after replay input is exhausted")
	flags.StringVar(&configuration.healthcheck, "healthcheck", "", "probe an HTTP health endpoint and exit")
	flags.BoolVar(&configuration.showVersion, "version", false, "print version and exit")
	if err := flags.Parse(arguments); err != nil {
		return config{}, err
	}
	return configuration, nil
}

func buildSource(configuration config) (source.Source, pipeline.Enricher, error) {
	switch configuration.source {
	case "replay":
		replay, err := source.NewReplay(configuration.replayPath, configuration.replaySpeed)
		return replay, nil, err
	case "live":
		live, err := probe.NewLive()
		if err != nil {
			return nil, nil, fmt.Errorf("initialize live probe: %w", err)
		}
		return live, enrich.NewProcEnricher(os.Getenv("SENTINEL_PROC_ROOT")), nil
	default:
		return nil, nil, fmt.Errorf("unsupported source %q", configuration.source)
	}
}

func openAlertWriter(path string) (io.Writer, func(), error) {
	if path == "-" {
		return os.Stdout, func() {}, nil
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, func() {}, fmt.Errorf("open alert output: %w", err)
	}
	return file, func() { _ = file.Close() }, nil
}

func checkHealth(url string) error {
	client := &http.Client{
		Timeout: 2 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("health endpoint returned %s", response.Status)
	}
	return nil
}
