package pipeline

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Vincent-P-essy/kernel-sentinel/internal/detection"
	"github.com/Vincent-P-essy/kernel-sentinel/internal/model"
	"github.com/Vincent-P-essy/kernel-sentinel/internal/store"
)

type fakeSource struct {
	events []model.Event
	err    error
	closed bool
}

func (source *fakeSource) Run(ctx context.Context, output chan<- model.Event) error {
	for _, event := range source.events {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case output <- event:
		}
	}
	return source.err
}

func (source *fakeSource) Close() error {
	source.closed = true
	return nil
}

type hostEnricher struct{}

func (hostEnricher) Enrich(event *model.Event) { event.Host = "enriched" }

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("full") }

func testRule() detection.Rule {
	return detection.Rule{
		ID: "KS-TEST-001", Title: "test", Description: "test", Severity: "high", Score: 80,
		MITRE: []string{"T1000"}, Match: &detection.MatchBlock{All: []detection.Condition{{Field: "kind", Op: "eq", Value: "process.exec"}}},
	}
}

func TestPipelineNormalizesDetectsAndWrites(t *testing.T) {
	source := &fakeSource{events: []model.Event{{ID: "one", Timestamp: time.Now(), Kind: model.EventExec}}}
	eventStore := store.New(10, 10)
	var output bytes.Buffer
	pipeline := Pipeline{
		Source: source, Engine: detection.NewEngine([]detection.Rule{testRule()}, false),
		Store: eventStore, Enricher: hostEnricher{}, Alerts: &output,
	}
	if err := pipeline.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !source.closed || eventStore.Stats().SourceStatus != "complete" || eventStore.Stats().AlertCount != 1 {
		t.Fatalf("pipeline state incorrect: %#v", eventStore.Stats())
	}
	if !bytes.Contains(output.Bytes(), []byte(`"rule_id":"KS-TEST-001"`)) {
		t.Fatalf("alert output missing: %s", output.String())
	}
	if events := eventStore.RecentEvents(1); events[0].Host != "enriched" {
		t.Fatalf("enricher not applied: %#v", events)
	}
}

func TestPipelinePropagatesSourceAndWriterErrors(t *testing.T) {
	eventStore := store.New(10, 10)
	sourceFailure := &fakeSource{err: errors.New("source failed")}
	pipeline := Pipeline{Source: sourceFailure, Engine: detection.NewEngine(nil, false), Store: eventStore}
	if err := pipeline.Run(context.Background()); err == nil || eventStore.Stats().SourceStatus != "error" {
		t.Fatalf("source error not propagated: %v %#v", err, eventStore.Stats())
	}

	writerFailure := &fakeSource{events: []model.Event{{Timestamp: time.Now(), Kind: model.EventExec}}}
	pipeline = Pipeline{
		Source: writerFailure, Engine: detection.NewEngine([]detection.Rule{testRule()}, false),
		Store: store.New(10, 10), Alerts: failingWriter{},
	}
	if err := pipeline.Run(context.Background()); err == nil {
		t.Fatal("writer error not propagated")
	}
}

func TestPipelineRequiresComponents(t *testing.T) {
	if err := (&Pipeline{}).Run(context.Background()); err == nil {
		t.Fatal("empty pipeline accepted")
	}
}
