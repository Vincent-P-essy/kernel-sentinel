package store

import (
	"strings"
	"testing"
	"time"

	"github.com/Vincent-P-essy/kernel-sentinel/internal/model"
)

type fixedProbeStats struct {
	stats model.ProbeStats
}

func (provider fixedProbeStats) ProbeStats() model.ProbeStats {
	return provider.stats
}

func TestStoreBoundsRecordsAndPublishesAlerts(t *testing.T) {
	eventStore := New(2, 2)
	alerts, unsubscribe := eventStore.Subscribe(1)
	defer unsubscribe()
	for index := 1; index <= 3; index++ {
		eventStore.AddEvent(model.Event{ID: string(rune('0' + index)), Kind: model.EventExec})
	}
	alert := model.Alert{ID: "a", RuleID: "KS-TEST", Severity: "high", DetectionLatency: int64(2 * time.Millisecond)}
	eventStore.AddAlerts(alert)

	if got := eventStore.RecentEvents(10); len(got) != 2 || got[0].ID != "3" || got[1].ID != "2" {
		t.Fatalf("unexpected bounded events: %#v", got)
	}
	select {
	case received := <-alerts:
		if received.ID != "a" {
			t.Fatalf("wrong alert: %#v", received)
		}
	default:
		t.Fatal("subscriber did not receive alert")
	}
	stats := eventStore.Stats()
	if stats.EventCount != 3 || stats.AlertCount != 1 || stats.P95DetectionLatencyMS != 2 {
		t.Fatalf("unexpected stats: %#v", stats)
	}
	metrics := eventStore.Prometheus()
	if !strings.Contains(metrics, `kernel_sentinel_alerts_total{rule_id="KS-TEST"} 1`) {
		t.Fatalf("metrics missing alert: %s", metrics)
	}
}

func TestStoreAppliesMinimumCapacityAndLimit(t *testing.T) {
	eventStore := New(0, 0)
	eventStore.AddEvent(model.Event{ID: "one"})
	eventStore.AddEvent(model.Event{ID: "two"})
	if got := eventStore.RecentEvents(-1); len(got) != 0 {
		t.Fatalf("negative limit returned values: %#v", got)
	}
	if got := eventStore.RecentEvents(10); len(got) != 1 || got[0].ID != "two" {
		t.Fatalf("minimum bound failed: %#v", got)
	}
}

func TestBoundedRingWrapsWithoutReordering(t *testing.T) {
	ring := newBoundedRing[int](3)
	for value := 1; value <= 5; value++ {
		ring.Add(value)
	}
	newest := ring.Newest(10)
	if len(newest) != 3 || newest[0] != 5 || newest[1] != 4 || newest[2] != 3 {
		t.Fatalf("newest = %#v", newest)
	}
	values := ring.Values()
	if len(values) != 3 || values[0] != 3 || values[1] != 4 || values[2] != 5 {
		t.Fatalf("values = %#v", values)
	}
}

func TestStoreExposesProbeHealth(t *testing.T) {
	eventStore := New(1, 1)
	eventStore.SetProbeStatsProvider(fixedProbeStats{stats: model.ProbeStats{
		Available:                true,
		EventsEmitted:            42,
		RingBufferOutputFailures: 2,
		PendingLookupMisses:      1,
		DecodeFailures:           3,
	}})

	stats := eventStore.Stats()
	if !stats.Probe.Available || stats.Probe.EventsEmitted != 42 || stats.Probe.RingBufferOutputFailures != 2 {
		t.Fatalf("unexpected probe stats: %#v", stats.Probe)
	}
	metrics := eventStore.Prometheus()
	for _, expected := range []string{
		"kernel_sentinel_probe_available 1",
		"kernel_sentinel_probe_events_emitted_total 42",
		"kernel_sentinel_probe_ring_buffer_output_failures_total 2",
		"kernel_sentinel_probe_pending_lookup_misses_total 1",
		"kernel_sentinel_probe_decode_failures_total 3",
	} {
		if !strings.Contains(metrics, expected) {
			t.Fatalf("metrics missing %q:\n%s", expected, metrics)
		}
	}
}
