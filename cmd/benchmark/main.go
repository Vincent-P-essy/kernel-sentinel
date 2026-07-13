package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/Vincent-P-essy/kernel-sentinel/internal/benchmark"
	"github.com/Vincent-P-essy/kernel-sentinel/internal/detection"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "benchmark:", err)
		os.Exit(1)
	}
}

func run() error {
	rulesPath := flag.String("rules", "rules", "rule file or directory")
	attackPath := flag.String("events", "lab/events/attack-suite.jsonl", "attack event JSONL")
	benignPath := flag.String("benign", "lab/events/benign-suite.jsonl", "benign event JSONL")
	truthPath := flag.String("truth", "lab/ground-truth.yaml", "ground-truth YAML")
	outputPath := flag.String("out", "reports", "output directory")
	liveAlertsPath := flag.String("live-alerts", "", "evaluate an emitted live-alert JSONL file instead of replaying events")
	settleTime := flag.Duration("settle", 0, "wait before reading a live-alert file (useful while the collector flushes final alerts)")
	printMarkdown := flag.Bool("print-markdown", false, "print the generated Markdown matrix to stdout")
	minimumRecall := flag.Float64("fail-under", 1, "minimum scenario recall or live expected-rule coverage")
	maximumFalsePositives := flag.Int("max-false-positives", 0, "maximum benign alert count")
	flag.Parse()
	if *settleTime < 0 {
		return fmt.Errorf("settle duration cannot be negative")
	}

	rules, err := detection.LoadRules(*rulesPath)
	if err != nil {
		return err
	}
	var report benchmark.Report
	if *liveAlertsPath != "" {
		if *settleTime > 0 {
			time.Sleep(*settleTime)
		}
		report, err = benchmark.RunLiveAlerts(len(rules), *liveAlertsPath, *truthPath)
	} else {
		report, err = benchmark.Run(rules, *attackPath, *benignPath, *truthPath)
	}
	if err != nil {
		return err
	}
	paths, err := benchmark.Write(report, *outputPath)
	if err != nil {
		return err
	}
	for _, kind := range []string{"json", "csv", "markdown"} {
		fmt.Printf("%s: %s\n", kind, paths[kind])
	}
	if *printMarkdown {
		content, readErr := os.ReadFile(paths["markdown"])
		if readErr != nil {
			return fmt.Errorf("read generated Markdown: %w", readErr)
		}
		fmt.Printf("\n%s", content)
	}
	if report.Summary.Recall < *minimumRecall {
		return fmt.Errorf("recall %.3f is below %.3f", report.Summary.Recall, *minimumRecall)
	}
	if *liveAlertsPath == "" && report.Summary.FalsePositives > *maximumFalsePositives {
		return fmt.Errorf("false positives %d exceed %d", report.Summary.FalsePositives, *maximumFalsePositives)
	}
	return nil
}
