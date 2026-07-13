package source

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Vincent-P-essy/kernel-sentinel/internal/model"
)

func TestReplayReadsBlankLinesAndAssignsDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.jsonl")
	content := `{"timestamp":"2026-07-12T10:00:00Z","kind":"process.exec","process":{"pid":1},"container":{},"outcome":{"success":true,"return_code":0}}

{"timestamp":"2026-07-12T10:00:01Z","kind":"file.open","process":{"pid":2},"container":{},"outcome":{"success":true,"return_code":0}}
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	replay, err := NewReplay(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	output := make(chan model.Event, 2)
	if err := replay.Run(context.Background(), output); err != nil {
		t.Fatal(err)
	}
	if len(output) != 2 {
		t.Fatalf("got %d events", len(output))
	}
	event := <-output
	if event.ID == "" || event.ObservedAt.IsZero() || event.SchemaVersion != "1.0" {
		t.Fatalf("defaults missing: %#v", event)
	}
}

func TestReplayRejectsBadInputs(t *testing.T) {
	if _, err := NewReplay("ignored", -1); err == nil {
		t.Fatal("negative speed accepted")
	}
	directory := t.TempDir()
	tests := map[string]string{
		"invalid":   "not-json\n",
		"timestamp": `{"kind":"process.exec"}` + "\n",
		"unordered": `{"timestamp":"2026-07-12T10:00:01Z","kind":"process.exec"}` + "\n" + `{"timestamp":"2026-07-12T10:00:00Z","kind":"process.exec"}` + "\n",
	}
	for name, content := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(directory, name+".jsonl")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			replay, _ := NewReplay(path, 0)
			if err := replay.Run(context.Background(), make(chan model.Event, 4)); err == nil {
				t.Fatal("invalid replay accepted")
			}
		})
	}
	replay, _ := NewReplay(filepath.Join(directory, "missing"), 0)
	if err := replay.Run(context.Background(), make(chan model.Event, 1)); err == nil || !strings.Contains(err.Error(), "open replay") {
		t.Fatalf("unexpected missing-file error: %v", err)
	}
}
