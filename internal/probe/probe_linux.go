//go:build linux

package probe

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Vincent-P-essy/kernel-sentinel/internal/model"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

const (
	kernelEventExec     = 1
	kernelEventFileOpen = 2
	kernelEventConnect  = 3
	kernelEventSetUID   = 4
	kernelEventFork     = 5
)

type Live struct {
	objects               bpfObjects
	links                 []link.Link
	reader                *ringbuf.Reader
	host                  string
	wallReference         time.Time
	monoReference         time.Duration
	decodeFailures        atomic.Uint64
	normalizationFailures atomic.Uint64
	readerFailures        atomic.Uint64
	statsReadFailures     atomic.Uint64
}

func NewLive() (*Live, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock limit: %w", err)
	}
	live := &Live{}
	if err := loadBpfObjects(&live.objects, nil); err != nil {
		return nil, fmt.Errorf("load eBPF objects: %w", err)
	}
	return initializeAttachments(live)
}

// initializeAttachments stays separate so every partially-created kernel resource is closed.
func initializeAttachments(live *Live) (*Live, error) {
	attachments := []struct {
		category    string
		name        string
		programName string
	}{
		{category: "syscalls", name: "sys_enter_execve", programName: "exec-enter"},
		{category: "syscalls", name: "sys_exit_execve", programName: "exec-exit"},
		{category: "syscalls", name: "sys_enter_openat", programName: "open-enter"},
		{category: "syscalls", name: "sys_exit_openat", programName: "open-exit"},
		{category: "syscalls", name: "sys_enter_connect", programName: "connect-enter"},
		{category: "syscalls", name: "sys_exit_connect", programName: "connect-exit"},
		{category: "syscalls", name: "sys_enter_setuid", programName: "setuid-enter"},
		{category: "syscalls", name: "sys_exit_setuid", programName: "setuid-exit"},
		{category: "sched", name: "sched_process_fork", programName: "process-fork"},
	}
	programs := []*ebpf.Program{
		live.objects.TraceExecveEnter,
		live.objects.TraceExecveExit,
		live.objects.TraceOpenatEnter,
		live.objects.TraceOpenatExit,
		live.objects.TraceConnectEnter,
		live.objects.TraceConnectExit,
		live.objects.TraceSetuidEnter,
		live.objects.TraceSetuidExit,
		live.objects.TraceSchedProcessFork,
	}
	for index, attachment := range attachments {
		attached, err := link.Tracepoint(attachment.category, attachment.name, programs[index], nil)
		if err != nil {
			live.Close()
			return nil, fmt.Errorf("attach %s (%s): %w", attachment.name, attachment.programName, err)
		}
		live.links = append(live.links, attached)
	}
	reader, err := ringbuf.NewReader(live.objects.Events)
	if err != nil {
		live.Close()
		return nil, fmt.Errorf("open event ring buffer: %w", err)
	}
	live.reader = reader
	live.host, _ = os.Hostname()
	live.wallReference = time.Now()
	var monotonic unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &monotonic); err != nil {
		live.Close()
		return nil, fmt.Errorf("read monotonic clock: %w", err)
	}
	live.monoReference = time.Duration(monotonic.Nano())
	return live, nil
}

func (live *Live) Run(ctx context.Context, output chan<- model.Event) error {
	go func() {
		<-ctx.Done()
		if live.reader != nil {
			_ = live.reader.Close()
		}
	}()
	for {
		record, err := live.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) && ctx.Err() != nil {
				return nil
			}
			live.readerFailures.Add(1)
			return fmt.Errorf("read ring buffer: %w", err)
		}
		var raw bpfEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.NativeEndian, &raw); err != nil {
			live.decodeFailures.Add(1)
			continue
		}
		event, err := live.normalize(raw)
		if err != nil {
			live.normalizationFailures.Add(1)
			continue
		}
		select {
		case <-ctx.Done():
			return nil
		case output <- event:
		}
	}
}

func (live *Live) ProbeStats() model.ProbeStats {
	stats := model.ProbeStats{Available: true}
	possibleCPUs, err := ebpf.PossibleCPU()
	if err != nil || live.objects.ProbeStats == nil {
		live.statsReadFailures.Add(1)
		return live.withUserSpaceStats(stats)
	}
	values := make([]bpfProbeStats, possibleCPUs)
	key := uint32(0)
	if err := live.objects.ProbeStats.Lookup(&key, &values); err != nil {
		live.statsReadFailures.Add(1)
		return live.withUserSpaceStats(stats)
	}
	stats = aggregateBPFProbeStats(values)
	return live.withUserSpaceStats(stats)
}

func aggregateBPFProbeStats(values []bpfProbeStats) model.ProbeStats {
	stats := model.ProbeStats{Available: true}
	for _, value := range values {
		stats.EventsEmitted += value.EventsEmitted
		stats.RingBufferOutputFailures += value.RingbufOutputFailures
		stats.PendingUpdateFailures += value.PendingUpdateFailures
		stats.PendingLookupMisses += value.PendingLookupMisses
		stats.PendingTypeMismatches += value.PendingTypeMismatches
		stats.PendingDeleteFailures += value.PendingDeleteFailures
	}
	return stats
}

func (live *Live) withUserSpaceStats(stats model.ProbeStats) model.ProbeStats {
	stats.DecodeFailures = live.decodeFailures.Load()
	stats.NormalizationFailures = live.normalizationFailures.Load()
	stats.ReaderFailures = live.readerFailures.Load()
	stats.StatsReadFailures = live.statsReadFailures.Load()
	return stats
}

func (live *Live) normalize(raw bpfEvent) (model.Event, error) {
	now := time.Now()
	event := model.Event{
		SchemaVersion: "1.0",
		Timestamp:     live.wallReference.Add(time.Duration(raw.TimestampNs) - live.monoReference),
		ObservedAt:    now,
		Host:          live.host,
		Process: model.Process{
			PID:        raw.Pid,
			TID:        raw.Tid,
			PPID:       raw.Ppid,
			UID:        raw.Uid,
			GID:        raw.Gid,
			Name:       int8String(raw.Comm[:]),
			ParentName: int8String(raw.ParentComm[:]),
		},
		Outcome: model.Outcome{Success: syscallSucceeded(raw), ReturnCode: raw.Retval},
		Raw: map[string]interface{}{
			"cgroup_id":   raw.CgroupId,
			"duration_ns": raw.DurationNs,
		},
	}
	path := int8String(raw.Path[:])
	switch raw.EventType {
	case kernelEventExec:
		event.Kind = model.EventExec
		event.Process.Executable = path
		event.Process.Arguments = execArguments(raw)
		event.Process.CommandLine = strings.Join(event.Process.Arguments, " ")
	case kernelEventFork:
		event.Kind = model.EventFork
	case kernelEventFileOpen:
		event.Kind = model.EventFileOpen
		event.File = &model.File{Path: path, Flags: raw.Flags}
	case kernelEventConnect:
		event.Kind = model.EventConnect
		family := strconv.FormatUint(uint64(raw.Family), 10)
		address := ""
		if raw.Family == unix.AF_INET {
			family = "ipv4"
			encoded := make([]byte, net.IPv4len)
			binary.NativeEndian.PutUint32(encoded, raw.AddressV4)
			address = net.IP(encoded).String()
		} else if raw.Family == unix.AF_INET6 {
			family = "ipv6"
			address = net.IP(raw.AddressV6[:]).String()
		}
		event.Network = &model.Network{Family: family, Address: address, Port: raw.Port, FD: raw.Fd}
	case kernelEventSetUID:
		event.Kind = model.EventSetUID
		event.Privilege = &model.Privilege{TargetUID: raw.Flags}
	default:
		return model.Event{}, fmt.Errorf("unsupported kernel event type %d", raw.EventType)
	}
	event.EnsureDefaults(now)
	return event, nil
}

func syscallSucceeded(raw bpfEvent) bool {
	return raw.Retval >= 0 || (raw.EventType == kernelEventConnect && raw.Retval == -int64(unix.EINPROGRESS))
}

func execArguments(raw bpfEvent) []string {
	count := raw.Argc
	if count > uint32(len(raw.Argv)) {
		count = uint32(len(raw.Argv))
	}
	arguments := make([]string, 0, int(count))
	for index := 0; index < int(count); index++ {
		arguments = append(arguments, int8String(raw.Argv[index][:]))
	}
	return arguments
}

func (live *Live) Close() error {
	var failures []error
	if live.reader != nil {
		failures = append(failures, live.reader.Close())
	}
	for _, attached := range live.links {
		failures = append(failures, attached.Close())
	}
	failures = append(failures, live.objects.Close())
	return errors.Join(failures...)
}

func int8String(value []int8) string {
	bytesValue := make([]byte, 0, len(value))
	for _, character := range value {
		if character == 0 {
			break
		}
		bytesValue = append(bytesValue, byte(character))
	}
	return string(bytesValue)
}
