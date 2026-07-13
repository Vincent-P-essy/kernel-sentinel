package model

// ProbeStats exposes cumulative health counters for the live kernel collector.
// Available is false for sources, such as replay, that do not have a kernel probe.
type ProbeStats struct {
	Available                bool   `json:"available"`
	EventsEmitted            uint64 `json:"events_emitted"`
	RingBufferOutputFailures uint64 `json:"ring_buffer_output_failures"`
	PendingUpdateFailures    uint64 `json:"pending_update_failures"`
	PendingLookupMisses      uint64 `json:"pending_lookup_misses"`
	PendingTypeMismatches    uint64 `json:"pending_type_mismatches"`
	PendingDeleteFailures    uint64 `json:"pending_delete_failures"`
	DecodeFailures           uint64 `json:"decode_failures"`
	NormalizationFailures    uint64 `json:"normalization_failures"`
	ReaderFailures           uint64 `json:"reader_failures"`
	StatsReadFailures        uint64 `json:"stats_read_failures"`
}
