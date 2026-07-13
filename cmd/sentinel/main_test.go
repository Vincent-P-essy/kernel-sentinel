package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestParseFlagsAndBuildReplaySource(t *testing.T) {
	configuration, err := parseFlags([]string{"-source", "replay", "-speed", "2", "-listen", ""})
	if err != nil {
		t.Fatal(err)
	}
	if configuration.source != "replay" || configuration.replaySpeed != 2 || configuration.listen != "" {
		t.Fatalf("unexpected config: %#v", configuration)
	}
	source, enricher, err := buildSource(configuration)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if enricher != nil {
		t.Fatal("replay unexpectedly uses proc enrichment")
	}
	configuration.source = "invalid"
	if _, _, err := buildSource(configuration); err == nil {
		t.Fatal("invalid source accepted")
	}
	if _, err := parseFlags([]string{"-unknown"}); err == nil {
		t.Fatal("unknown flag accepted")
	}
}

func TestOpenAlertWriterAndHealthcheck(t *testing.T) {
	path := filepath.Join(t.TempDir(), "alerts.jsonl")
	writer, closeWriter, err := openAlertWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte("alert\n")); err != nil {
		t.Fatal(err)
	}
	closeWriter()
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("alert file mode: %v %v", info, err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	if err := checkHealth(server.URL); err != nil {
		t.Fatal(err)
	}
	failing := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer failing.Close()
	if err := checkHealth(failing.URL); err == nil {
		t.Fatal("unhealthy endpoint accepted")
	}
	stdout, closeStdout, err := openAlertWriter("-")
	if err != nil || stdout != io.Writer(os.Stdout) {
		t.Fatalf("stdout writer: %v %v", stdout, err)
	}
	closeStdout()
}

func TestRunReplayEndToEnd(t *testing.T) {
	alertPath := filepath.Join(t.TempDir(), "alerts.jsonl")
	err := run([]string{
		"-source", "replay",
		"-replay", "../../lab/events/attack-suite.jsonl",
		"-rules", "../../rules",
		"-listen", "",
		"-alerts", alertPath,
		"-behavioral=false",
		"-exit-on-eof",
	})
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(alertPath)
	if err != nil || len(content) == 0 {
		t.Fatalf("alerts not written: %v", err)
	}
}
