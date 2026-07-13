//go:build ignore

#include "common.h"

#define AF_INET 2
#define AF_INET6 10
#define TASK_COMM_LEN 16
#define PATH_LEN 256
#define MAX_EXEC_ARGUMENTS 6
#define EXEC_ARGUMENT_LEN 128

enum sentinel_event_type {
	EVENT_EXEC = 1,
	EVENT_FILE_OPEN = 2,
	EVENT_CONNECT = 3,
	EVENT_SETUID = 4,
	EVENT_FORK = 5,
};

struct trace_event_raw_sys_enter {
	u64 pad;
	s64 syscall_nr;
	u64 args[6];
};

struct trace_event_raw_sys_exit {
	u64 pad;
	s64 syscall_nr;
	s64 ret;
};

struct trace_event_raw_sched_process_fork {
	u64 pad;
	char parent_comm[TASK_COMM_LEN];
	s32 parent_pid;
	char child_comm[TASK_COMM_LEN];
	s32 child_pid;
};

struct sockaddr_in_min {
	u16 family;
	u16 port;
	u32 address;
	u8 zero[8];
};

struct sockaddr_in6_min {
	u16 family;
	u16 port;
	u32 flowinfo;
	u8 address[16];
	u32 scope_id;
};

struct event {
	u64 timestamp_ns;
	u64 cgroup_id;
	s64 retval;
	u64 duration_ns;
	u32 pid;
	u32 tid;
	u32 ppid;
	u32 uid;
	u32 gid;
	u32 event_type;
	s32 fd;
	u32 flags;
	u16 family;
	u16 port;
	u32 address_v4;
	u8 address_v6[16];
	u32 argc;
	char comm[TASK_COMM_LEN];
	char parent_comm[TASK_COMM_LEN];
	char path[PATH_LEN];
	char argv[MAX_EXEC_ARGUMENTS][EXEC_ARGUMENT_LEN];
};

struct probe_stats {
	u64 events_emitted;
	u64 ringbuf_output_failures;
	u64 pending_update_failures;
	u64 pending_lookup_misses;
	u64 pending_type_mismatches;
	u64 pending_delete_failures;
};

enum probe_counter {
	COUNTER_EVENTS_EMITTED = 0,
	COUNTER_RINGBUF_OUTPUT_FAILURES = 1,
	COUNTER_PENDING_UPDATE_FAILURES = 2,
	COUNTER_PENDING_LOOKUP_MISSES = 3,
	COUNTER_PENDING_TYPE_MISMATCHES = 4,
	COUNTER_PENDING_DELETE_FAILURES = 5,
};

/* The event is larger than the 512-byte BPF stack, so entry probes build it in per-CPU storage. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct event);
} scratch_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, u32);
	__type(value, struct event);
} pending_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct probe_stats);
} probe_stats SEC(".maps");

static __always_inline void increment_probe_counter(u32 counter) {
	u32 key = 0;
	struct probe_stats *stats = bpf_map_lookup_elem(&probe_stats, &key);

	if (!stats)
		return;
	switch (counter) {
	case COUNTER_EVENTS_EMITTED:
		stats->events_emitted++;
		break;
	case COUNTER_RINGBUF_OUTPUT_FAILURES:
		stats->ringbuf_output_failures++;
		break;
	case COUNTER_PENDING_UPDATE_FAILURES:
		stats->pending_update_failures++;
		break;
	case COUNTER_PENDING_LOOKUP_MISSES:
		stats->pending_lookup_misses++;
		break;
	case COUNTER_PENDING_TYPE_MISMATCHES:
		stats->pending_type_mismatches++;
		break;
	case COUNTER_PENDING_DELETE_FAILURES:
		stats->pending_delete_failures++;
		break;
	}
}

static __always_inline struct event *initialize_event(u32 event_type) {
	u32 scratch_key = 0;
	struct event *event = bpf_map_lookup_elem(&scratch_events, &scratch_key);
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u64 uid_gid = bpf_get_current_uid_gid();

	if (!event)
		return 0;

	event->timestamp_ns = bpf_ktime_get_ns();
	event->cgroup_id = bpf_get_current_cgroup_id();
	event->retval = 0;
	event->duration_ns = 0;
	event->pid = pid_tgid >> 32;
	event->tid = (u32)pid_tgid;
	event->ppid = 0;
	event->uid = (u32)uid_gid;
	event->gid = uid_gid >> 32;
	event->event_type = event_type;
	event->fd = -1;
	event->flags = 0;
	event->family = 0;
	event->port = 0;
	event->address_v4 = 0;
	__builtin_memset(event->address_v6, 0, sizeof(event->address_v6));
	event->argc = 0;
	event->comm[0] = 0;
	event->parent_comm[0] = 0;
	event->path[0] = 0;
#pragma unroll
	for (int index = 0; index < MAX_EXEC_ARGUMENTS; index++)
		event->argv[index][0] = 0;
	bpf_get_current_comm(&event->comm, sizeof(event->comm));
	return event;
}

static __always_inline void capture_exec_arguments(struct event *event, const char *const *argv) {
#pragma unroll
	for (int index = 0; index < MAX_EXEC_ARGUMENTS; index++) {
		const char *argument = 0;

		if (bpf_probe_read_user(&argument, sizeof(argument), &argv[index]) < 0 || !argument)
			break;
		if (bpf_probe_read_user_str(event->argv[index], sizeof(event->argv[index]), argument) <= 0)
			break;
		event->argc++;
	}
}

static __always_inline int remember_event(struct event *event) {
	u32 tid = event->tid;

	if (bpf_map_update_elem(&pending_events, &tid, event, BPF_ANY) < 0)
		increment_probe_counter(COUNTER_PENDING_UPDATE_FAILURES);
	return 0;
}

static __always_inline int submit_event(struct trace_event_raw_sys_exit *ctx, u32 expected_type) {
	u32 tid = (u32)bpf_get_current_pid_tgid();
	struct event *pending = bpf_map_lookup_elem(&pending_events, &tid);
	int output_result;

	if (!pending) {
		increment_probe_counter(COUNTER_PENDING_LOOKUP_MISSES);
		return 0;
	}
	if (pending->event_type != expected_type) {
		increment_probe_counter(COUNTER_PENDING_TYPE_MISMATCHES);
		if (bpf_map_delete_elem(&pending_events, &tid) < 0)
			increment_probe_counter(COUNTER_PENDING_DELETE_FAILURES);
		return 0;
	}

	pending->retval = ctx->ret;
	pending->duration_ns = bpf_ktime_get_ns() - pending->timestamp_ns;
	if (expected_type == EVENT_EXEC && ctx->ret >= 0)
		bpf_get_current_comm(&pending->comm, sizeof(pending->comm));
	output_result = bpf_ringbuf_output(&events, pending, sizeof(*pending), 0);
	if (output_result < 0)
		increment_probe_counter(COUNTER_RINGBUF_OUTPUT_FAILURES);
	else
		increment_probe_counter(COUNTER_EVENTS_EMITTED);
	if (bpf_map_delete_elem(&pending_events, &tid) < 0)
		increment_probe_counter(COUNTER_PENDING_DELETE_FAILURES);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve_enter(struct trace_event_raw_sys_enter *ctx) {
	struct event *event = initialize_event(EVENT_EXEC);

	if (!event)
		return 0;
	bpf_probe_read_user_str(event->path, sizeof(event->path), (const void *)ctx->args[0]);
	capture_exec_arguments(event, (const char *const *)ctx->args[1]);
	return remember_event(event);
}

SEC("tracepoint/syscalls/sys_exit_execve")
int trace_execve_exit(struct trace_event_raw_sys_exit *ctx) {
	return submit_event(ctx, EVENT_EXEC);
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat_enter(struct trace_event_raw_sys_enter *ctx) {
	struct event *event = initialize_event(EVENT_FILE_OPEN);

	if (!event)
		return 0;
	event->fd = (s32)ctx->args[0];
	event->flags = (u32)ctx->args[2];
	bpf_probe_read_user_str(event->path, sizeof(event->path), (const void *)ctx->args[1]);
	return remember_event(event);
}

SEC("tracepoint/syscalls/sys_exit_openat")
int trace_openat_exit(struct trace_event_raw_sys_exit *ctx) {
	return submit_event(ctx, EVENT_FILE_OPEN);
}

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect_enter(struct trace_event_raw_sys_enter *ctx) {
	struct event *event = initialize_event(EVENT_CONNECT);
	u16 family = 0;

	if (!event)
		return 0;
	event->fd = (s32)ctx->args[0];
	bpf_probe_read_user(&family, sizeof(family), (const void *)ctx->args[1]);
	event->family = family;
	if (family == AF_INET) {
		struct sockaddr_in_min address;

		__builtin_memset(&address, 0, sizeof(address));
		bpf_probe_read_user(&address, sizeof(address), (const void *)ctx->args[1]);
		event->port = __builtin_bswap16(address.port);
		event->address_v4 = address.address;
	} else if (family == AF_INET6) {
		struct sockaddr_in6_min address;

		__builtin_memset(&address, 0, sizeof(address));
		bpf_probe_read_user(&address, sizeof(address), (const void *)ctx->args[1]);
		event->port = __builtin_bswap16(address.port);
#pragma unroll
		for (int index = 0; index < 16; index++)
			event->address_v6[index] = address.address[index];
	}
	return remember_event(event);
}

SEC("tracepoint/syscalls/sys_exit_connect")
int trace_connect_exit(struct trace_event_raw_sys_exit *ctx) {
	return submit_event(ctx, EVENT_CONNECT);
}

SEC("tracepoint/syscalls/sys_enter_setuid")
int trace_setuid_enter(struct trace_event_raw_sys_enter *ctx) {
	struct event *event = initialize_event(EVENT_SETUID);

	if (!event)
		return 0;
	event->flags = (u32)ctx->args[0];
	return remember_event(event);
}

SEC("tracepoint/syscalls/sys_exit_setuid")
int trace_setuid_exit(struct trace_event_raw_sys_exit *ctx) {
	return submit_event(ctx, EVENT_SETUID);
}

SEC("tracepoint/sched/sched_process_fork")
int trace_sched_process_fork(struct trace_event_raw_sched_process_fork *ctx) {
	struct event *event = initialize_event(EVENT_FORK);
	int output_result;

	if (!event)
		return 0;
	event->pid = (u32)ctx->child_pid;
	event->tid = (u32)ctx->child_pid;
	event->ppid = (u32)ctx->parent_pid;
#pragma unroll
	for (int index = 0; index < TASK_COMM_LEN; index++) {
		event->comm[index] = ctx->child_comm[index];
		event->parent_comm[index] = ctx->parent_comm[index];
	}
	output_result = bpf_ringbuf_output(&events, event, sizeof(*event), 0);
	if (output_result < 0)
		increment_probe_counter(COUNTER_RINGBUF_OUTPUT_FAILURES);
	else
		increment_probe_counter(COUNTER_EVENTS_EMITTED);
	return 0;
}

char __license[] SEC("license") = "Dual MIT/GPL";
