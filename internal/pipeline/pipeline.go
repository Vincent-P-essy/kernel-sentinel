package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/Vincent-P-essy/kernel-sentinel/internal/detection"
	"github.com/Vincent-P-essy/kernel-sentinel/internal/model"
	"github.com/Vincent-P-essy/kernel-sentinel/internal/source"
	"github.com/Vincent-P-essy/kernel-sentinel/internal/store"
)

type Enricher interface {
	Enrich(*model.Event)
}

type Pipeline struct {
	Source   source.Source
	Engine   *detection.Engine
	Store    *store.Store
	Enricher Enricher
	Alerts   io.Writer
}

func (pipeline *Pipeline) Run(ctx context.Context) error {
	if pipeline.Source == nil || pipeline.Engine == nil || pipeline.Store == nil {
		return fmt.Errorf("source, engine and store are required")
	}
	pipeline.Store.SetSourceStatus("active")
	events := make(chan model.Event, 1024)
	sourceResult := make(chan error, 1)
	go func() {
		sourceResult <- pipeline.Source.Run(ctx, events)
		close(events)
	}()
	defer pipeline.Source.Close()

	var encoder *json.Encoder
	if pipeline.Alerts != nil {
		encoder = json.NewEncoder(pipeline.Alerts)
	}
	for event := range events {
		if pipeline.Enricher != nil {
			pipeline.Enricher.Enrich(&event)
		}
		pipeline.Store.AddEvent(event)
		alerts := pipeline.Engine.Process(event)
		if len(alerts) == 0 {
			continue
		}
		pipeline.Store.AddAlerts(alerts...)
		if encoder != nil {
			for _, alert := range alerts {
				if err := encoder.Encode(alert); err != nil {
					pipeline.Store.SetSourceStatus("error")
					return fmt.Errorf("write alert: %w", err)
				}
			}
		}
	}
	err := <-sourceResult
	if err != nil && !errors.Is(err, context.Canceled) {
		pipeline.Store.SetSourceStatus("error")
		return err
	}
	pipeline.Store.SetSourceStatus("complete")
	return nil
}
