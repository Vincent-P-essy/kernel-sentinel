//go:build linux

package probe

import (
	"encoding/binary"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/Vincent-P-essy/kernel-sentinel/internal/model"
	"golang.org/x/sys/unix"
)

func TestNormalizeKernelEvents(t *testing.T) {
	reference := time.Date(2026, 7, 12, 10, 0, 0, 0, time.UTC)
	live := &Live{wallReference: reference, monoReference: time.Second, host: "node-a"}
	tests := []struct {
		name string
		raw  bpfEvent
		kind model.EventKind
	}{
		{"exec", bpfEvent{TimestampNs: uint64(2 * time.Second), EventType: kernelEventExec, Pid: 10, Tid: 11, Retval: 0, Path: int8Array256("/tmp/tool"), Comm: int8Array16("tool"), Argc: 2, Argv: int8Argv("tool", "--safe")}, model.EventExec},
		{"fork", bpfEvent{TimestampNs: uint64(2 * time.Second), EventType: kernelEventFork, Pid: 12, Tid: 12, Ppid: 10, Retval: 0, Comm: int8Array16("child"), ParentComm: int8Array16("parent")}, model.EventFork},
		{"file", bpfEvent{TimestampNs: uint64(2 * time.Second), EventType: kernelEventFileOpen, Pid: 10, Retval: 3, Flags: 65, Path: int8Array256("/etc/shadow")}, model.EventFileOpen},
		{"setuid", bpfEvent{TimestampNs: uint64(2 * time.Second), EventType: kernelEventSetUID, Pid: 10, Retval: 0, Flags: 0}, model.EventSetUID},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			event, err := live.normalize(test.raw)
			if err != nil {
				t.Fatal(err)
			}
			if event.Kind != test.kind || event.ID == "" || event.Host != "node-a" || !event.Outcome.Success {
				t.Fatalf("unexpected event: %#v", event)
			}
			if !event.Timestamp.Equal(reference.Add(time.Second)) {
				t.Fatalf("timestamp = %s", event.Timestamp)
			}
		})
	}
}

func TestNormalizeForkParentAndChild(t *testing.T) {
	live := &Live{wallReference: time.Now()}
	event, err := live.normalize(bpfEvent{
		EventType:  kernelEventFork,
		Pid:        4201,
		Tid:        4201,
		Ppid:       4100,
		Comm:       int8Array16("child-worker"),
		ParentComm: int8Array16("parent-worker"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if event.Kind != model.EventFork || event.Process.PID != 4201 || event.Process.TID != 4201 || event.Process.PPID != 4100 {
		t.Fatalf("fork identifiers not normalized: %#v", event)
	}
	if event.Process.Name != "child-worker" || event.Process.ParentName != "parent-worker" {
		t.Fatalf("fork names not normalized: %#v", event.Process)
	}
}

func TestNormalizeExecArguments(t *testing.T) {
	live := &Live{wallReference: time.Now()}
	raw := bpfEvent{
		EventType: kernelEventExec,
		Retval:    0,
		Path:      int8Array256("/tmp/tool"),
		Argc:      8,
		Argv:      int8Argv("tool", "--mode", "audit", "", "--limit", "6"),
	}
	event, err := live.normalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	expected := []string{"tool", "--mode", "audit", "", "--limit", "6"}
	if !reflect.DeepEqual(event.Process.Arguments, expected) {
		t.Fatalf("arguments = %#v, want %#v", event.Process.Arguments, expected)
	}
	if event.Process.CommandLine != "tool --mode audit  --limit 6" {
		t.Fatalf("command line = %q", event.Process.CommandLine)
	}
}

func TestNormalizeIPv4AndUnknownEvent(t *testing.T) {
	live := &Live{wallReference: time.Now(), monoReference: 0}
	encoded := make([]byte, 4)
	copy(encoded, net.ParseIP("203.0.113.8").To4())
	raw := bpfEvent{EventType: kernelEventConnect, Family: 2, AddressV4: binary.NativeEndian.Uint32(encoded), Port: 443, Retval: -111}
	event, err := live.normalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	if event.Network == nil || event.Network.Address != "203.0.113.8" || event.Outcome.Success {
		t.Fatalf("unexpected network event: %#v", event)
	}
	raw.Retval = -int64(unix.EINPROGRESS)
	event, err = live.normalize(raw)
	if err != nil || !event.Outcome.Success {
		t.Fatalf("in-progress connection was not accepted: %#v, %v", event, err)
	}
	if _, err := live.normalize(bpfEvent{EventType: 99}); err == nil {
		t.Fatal("unknown event accepted")
	}
}

func TestNormalizeIPv6Connection(t *testing.T) {
	live := &Live{wallReference: time.Now()}
	raw := bpfEvent{
		EventType: kernelEventConnect,
		Family:    unix.AF_INET6,
		AddressV6: int8IPv6("2001:db8::8"),
		Port:      8443,
		Retval:    0,
	}
	event, err := live.normalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	if event.Network == nil || event.Network.Family != "ipv6" || event.Network.Address != "2001:db8::8" || event.Network.Port != 8443 {
		t.Fatalf("unexpected IPv6 event: %#v", event)
	}
}

func TestInt8StringStopsAtNull(t *testing.T) {
	if value := int8String([]int8{'o', 'k', 0, 'x'}); value != "ok" {
		t.Fatalf("value = %q", value)
	}
}

func TestEmbeddedBPFObjectContainsExpectedProgramsAndMaps(t *testing.T) {
	spec, err := loadBpf()
	if err != nil {
		t.Fatal(err)
	}
	if len(spec.Programs) != 9 || spec.Programs["trace_sched_process_fork"] == nil {
		t.Fatalf("program count = %d", len(spec.Programs))
	}
	if spec.Maps["events"] == nil || spec.Maps["pending_events"] == nil || spec.Maps["scratch_events"] == nil || spec.Maps["probe_stats"] == nil {
		t.Fatalf("required maps missing: %#v", spec.Maps)
	}
	eventSize := binary.Size(bpfEvent{})
	if eventSize != 1152 || spec.Maps["pending_events"].ValueSize != uint32(eventSize) || spec.Maps["scratch_events"].ValueSize != uint32(eventSize) {
		t.Fatalf("event layout mismatch: Go=%d pending=%d scratch=%d", eventSize, spec.Maps["pending_events"].ValueSize, spec.Maps["scratch_events"].ValueSize)
	}
	statsSize := binary.Size(bpfProbeStats{})
	if statsSize != 48 || spec.Maps["probe_stats"].ValueSize != uint32(statsSize) {
		t.Fatalf("probe stats layout mismatch: Go=%d BPF=%d", statsSize, spec.Maps["probe_stats"].ValueSize)
	}
}

func TestAggregateBPFProbeStatsAndUserSpaceFailures(t *testing.T) {
	values := []bpfProbeStats{
		{EventsEmitted: 7, RingbufOutputFailures: 1, PendingLookupMisses: 2},
		{EventsEmitted: 5, PendingUpdateFailures: 3, PendingTypeMismatches: 4, PendingDeleteFailures: 1},
	}
	live := &Live{}
	live.decodeFailures.Add(2)
	live.normalizationFailures.Add(3)
	live.readerFailures.Add(1)
	live.statsReadFailures.Add(4)

	stats := live.withUserSpaceStats(aggregateBPFProbeStats(values))
	if !stats.Available || stats.EventsEmitted != 12 || stats.RingBufferOutputFailures != 1 || stats.PendingUpdateFailures != 3 || stats.PendingLookupMisses != 2 || stats.PendingTypeMismatches != 4 || stats.PendingDeleteFailures != 1 {
		t.Fatalf("unexpected kernel counters: %#v", stats)
	}
	if stats.DecodeFailures != 2 || stats.NormalizationFailures != 3 || stats.ReaderFailures != 1 || stats.StatsReadFailures != 4 {
		t.Fatalf("unexpected user-space counters: %#v", stats)
	}
}

func int8Array16(value string) [16]int8 {
	var result [16]int8
	for index, character := range []byte(value) {
		result[index] = int8(character)
	}
	return result
}

func int8Array256(value string) [256]int8 {
	var result [256]int8
	for index, character := range []byte(value) {
		result[index] = int8(character)
	}
	return result
}

func int8IPv6(value string) [16]uint8 {
	var result [16]uint8
	copy(result[:], net.ParseIP(value).To16())
	return result
}

func int8Argv(values ...string) [6][128]int8 {
	var result [6][128]int8
	for argumentIndex, value := range values {
		if argumentIndex >= len(result) {
			break
		}
		for characterIndex, character := range []byte(value) {
			if characterIndex >= len(result[argumentIndex])-1 {
				break
			}
			result[argumentIndex][characterIndex] = int8(character)
		}
	}
	return result
}
