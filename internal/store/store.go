package store

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Vincent-P-essy/kernel-sentinel/internal/model"
)

type Stats struct {
	StartedAt             time.Time        `json:"started_at"`
	SourceStatus          string           `json:"source_status"`
	EventCount            uint64           `json:"event_count"`
	AlertCount            uint64           `json:"alert_count"`
	EventsByKind          map[string]int   `json:"events_by_kind"`
	AlertsBySeverity      map[string]int   `json:"alerts_by_severity"`
	AlertsByRule          map[string]int   `json:"alerts_by_rule"`
	P95DetectionLatencyMS float64          `json:"p95_detection_latency_ms"`
	Probe                 model.ProbeStats `json:"probe"`
}

type ProbeStatsProvider interface {
	ProbeStats() model.ProbeStats
}

type Store struct {
	mu               sync.RWMutex
	events           boundedRing[model.Event]
	alerts           boundedRing[model.Alert]
	eventCount       uint64
	alertCount       uint64
	eventsByKind     map[string]int
	alertsByRule     map[string]int
	alertsBySeverity map[string]int
	latencies        boundedRing[int64]
	sourceStatus     string
	startedAt        time.Time
	subscribers      map[uint64]chan model.Alert
	nextSubscriber   uint64
	probeStats       ProbeStatsProvider
}

func (store *Store) SetProbeStatsProvider(provider ProbeStatsProvider) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.probeStats = provider
}

func New(maxEvents, maxAlerts int) *Store {
	if maxEvents < 1 {
		maxEvents = 1
	}
	if maxAlerts < 1 {
		maxAlerts = 1
	}
	return &Store{
		events:           newBoundedRing[model.Event](maxEvents),
		alerts:           newBoundedRing[model.Alert](maxAlerts),
		latencies:        newBoundedRing[int64](2048),
		eventsByKind:     make(map[string]int),
		alertsByRule:     make(map[string]int),
		alertsBySeverity: make(map[string]int),
		sourceStatus:     "starting",
		startedAt:        time.Now().UTC(),
		subscribers:      make(map[uint64]chan model.Alert),
	}
}

func (store *Store) SetSourceStatus(status string) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.sourceStatus = status
}

func (store *Store) AddEvent(event model.Event) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.eventCount++
	store.eventsByKind[string(event.Kind)]++
	store.events.Add(event)
}

func (store *Store) AddAlerts(alerts ...model.Alert) {
	store.mu.Lock()
	defer store.mu.Unlock()
	for _, alert := range alerts {
		store.alertCount++
		store.alertsByRule[alert.RuleID]++
		store.alertsBySeverity[alert.Severity]++
		store.latencies.Add(alert.DetectionLatency)
		store.alerts.Add(alert)
		for _, subscriber := range store.subscribers {
			select {
			case subscriber <- alert:
			default:
			}
		}
	}
}

func (store *Store) RecentEvents(limit int) []model.Event {
	store.mu.RLock()
	defer store.mu.RUnlock()
	return store.events.Newest(limit)
}

func (store *Store) RecentAlerts(limit int) []model.Alert {
	store.mu.RLock()
	defer store.mu.RUnlock()
	return store.alerts.Newest(limit)
}

func (store *Store) Stats() Stats {
	store.mu.RLock()
	latencies := store.latencies.Values()
	sort.Slice(latencies, func(left, right int) bool { return latencies[left] < latencies[right] })
	p95 := int64(0)
	if len(latencies) > 0 {
		index := int(float64(len(latencies)-1) * 0.95)
		p95 = latencies[index]
	}
	stats := Stats{
		StartedAt:             store.startedAt,
		SourceStatus:          store.sourceStatus,
		EventCount:            store.eventCount,
		AlertCount:            store.alertCount,
		EventsByKind:          cloneMap(store.eventsByKind),
		AlertsBySeverity:      cloneMap(store.alertsBySeverity),
		AlertsByRule:          cloneMap(store.alertsByRule),
		P95DetectionLatencyMS: float64(p95) / float64(time.Millisecond),
	}
	provider := store.probeStats
	store.mu.RUnlock()
	if provider != nil {
		stats.Probe = provider.ProbeStats()
	}
	return stats
}

func (store *Store) Subscribe(buffer int) (<-chan model.Alert, func()) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.nextSubscriber++
	id := store.nextSubscriber
	channel := make(chan model.Alert, buffer)
	store.subscribers[id] = channel
	return channel, func() {
		store.mu.Lock()
		defer store.mu.Unlock()
		if existing, ok := store.subscribers[id]; ok {
			delete(store.subscribers, id)
			close(existing)
		}
	}
}

func (store *Store) Prometheus() string {
	stats := store.Stats()
	var builder strings.Builder
	builder.WriteString("# HELP kernel_sentinel_events_total Normalized runtime events.\n")
	builder.WriteString("# TYPE kernel_sentinel_events_total counter\n")
	for _, key := range sortedKeys(stats.EventsByKind) {
		fmt.Fprintf(&builder, "kernel_sentinel_events_total{kind=%q} %d\n", key, stats.EventsByKind[key])
	}
	builder.WriteString("# HELP kernel_sentinel_alerts_total Detection alerts.\n")
	builder.WriteString("# TYPE kernel_sentinel_alerts_total counter\n")
	for _, key := range sortedKeys(stats.AlertsByRule) {
		fmt.Fprintf(&builder, "kernel_sentinel_alerts_total{rule_id=%q} %d\n", key, stats.AlertsByRule[key])
	}
	builder.WriteString("# HELP kernel_sentinel_detection_latency_p95_milliseconds Rolling p95 detection latency.\n")
	builder.WriteString("# TYPE kernel_sentinel_detection_latency_p95_milliseconds gauge\n")
	fmt.Fprintf(&builder, "kernel_sentinel_detection_latency_p95_milliseconds %.6f\n", stats.P95DetectionLatencyMS)
	builder.WriteString("# HELP kernel_sentinel_probe_available Whether live probe counters are available.\n")
	builder.WriteString("# TYPE kernel_sentinel_probe_available gauge\n")
	available := 0
	if stats.Probe.Available {
		available = 1
	}
	fmt.Fprintf(&builder, "kernel_sentinel_probe_available %d\n", available)
	writeProbeCounter(&builder, "events_emitted", "Kernel events successfully submitted to the ring buffer.", stats.Probe.EventsEmitted)
	writeProbeCounter(&builder, "ring_buffer_output_failures", "Kernel events rejected by ring-buffer output.", stats.Probe.RingBufferOutputFailures)
	writeProbeCounter(&builder, "pending_update_failures", "Syscall entries that could not be stored in the pending map.", stats.Probe.PendingUpdateFailures)
	writeProbeCounter(&builder, "pending_lookup_misses", "Syscall exits without a matching pending entry.", stats.Probe.PendingLookupMisses)
	writeProbeCounter(&builder, "pending_type_mismatches", "Syscall exits whose pending event had an unexpected type.", stats.Probe.PendingTypeMismatches)
	writeProbeCounter(&builder, "pending_delete_failures", "Pending entries that could not be deleted.", stats.Probe.PendingDeleteFailures)
	writeProbeCounter(&builder, "decode_failures", "Ring records that user space could not decode.", stats.Probe.DecodeFailures)
	writeProbeCounter(&builder, "normalization_failures", "Decoded records rejected during normalization.", stats.Probe.NormalizationFailures)
	writeProbeCounter(&builder, "reader_failures", "Unexpected ring-buffer reader failures.", stats.Probe.ReaderFailures)
	writeProbeCounter(&builder, "stats_read_failures", "Failures while reading per-CPU probe counters.", stats.Probe.StatsReadFailures)
	return builder.String()
}

func writeProbeCounter(builder *strings.Builder, name, help string, value uint64) {
	fmt.Fprintf(builder, "# HELP kernel_sentinel_probe_%s_total %s\n", name, help)
	fmt.Fprintf(builder, "# TYPE kernel_sentinel_probe_%s_total counter\n", name)
	fmt.Fprintf(builder, "kernel_sentinel_probe_%s_total %d\n", name, value)
}

type boundedRing[T any] struct {
	values []T
	next   int
	size   int
}

func newBoundedRing[T any](capacity int) boundedRing[T] {
	return boundedRing[T]{values: make([]T, capacity)}
}

func (ring *boundedRing[T]) Add(value T) {
	ring.values[ring.next] = value
	ring.next = (ring.next + 1) % len(ring.values)
	if ring.size < len(ring.values) {
		ring.size++
	}
}

func (ring boundedRing[T]) Newest(limit int) []T {
	if limit < 0 {
		limit = 0
	}
	if limit > ring.size {
		limit = ring.size
	}
	result := make([]T, limit)
	for index := 0; index < limit; index++ {
		position := (ring.next - 1 - index + len(ring.values)) % len(ring.values)
		result[index] = ring.values[position]
	}
	return result
}

func (ring boundedRing[T]) Values() []T {
	result := make([]T, ring.size)
	oldest := (ring.next - ring.size + len(ring.values)) % len(ring.values)
	for index := range result {
		result[index] = ring.values[(oldest+index)%len(ring.values)]
	}
	return result
}

func cloneMap(values map[string]int) map[string]int {
	result := make(map[string]int, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

func sortedKeys(values map[string]int) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
