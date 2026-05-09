// SPDX-License-Identifier: GPL-2.0
// LSIG Runtime Agent — eBPF uprobe program
//
// Attaches uprobes to function entry/exit in user-space processes and emits
// call events to a perf ring buffer consumed by the Go userspace agent.
//
// Compiled with: clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
//   -I/usr/include/bpf -c uprobe.bpf.c -o uprobe.bpf.o

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// ─── Constants ────────────────────────────────────────────────────────────────
#define SYMBOL_LEN     128
#define COMM_LEN       16
#define MAX_STACK_DEPTH 12

// ─── Event structure sent to userspace ───────────────────────────────────────
struct call_event {
    __u64  timestamp_ns;
    __u32  pid;
    __u32  tgid;
    __u64  func_ip;         // instruction pointer of the probed function
    __u64  caller_ip;       // return address (= caller's next instruction)
    __u64  cpu_time_ns;     // CPU time accumulated (filled on uretprobe)
    char   comm[COMM_LEN];  // process name
    __u8   is_return;       // 0 = entry, 1 = return
};

// ─── Maps ─────────────────────────────────────────────────────────────────────

// Perf event array: events streamed to userspace
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} call_events SEC(".maps");

// Per-CPU scratch buffer to avoid stack overflows
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct call_event);
} scratch SEC(".maps");

// Track entry timestamp per (pid, func_ip) for latency measurement
struct entry_key {
    __u32 pid;
    __u64 func_ip;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct entry_key);
    __type(value, __u64);   // ktime_ns at entry
} entry_times SEC(".maps");

// PID filter map: only trace these PIDs (0 = trace all)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u8);
} pid_filter SEC(".maps");

// ─── Helpers ──────────────────────────────────────────────────────────────────

static __always_inline bool should_trace(__u32 pid)
{
    // If pid_filter is empty, trace everything.
    // If it has entries, only trace listed PIDs.
    __u8 *val = bpf_map_lookup_elem(&pid_filter, &pid);
    // An empty map has no entries; map_lookup on an empty map always returns NULL.
    // We can't query map size in BPF, so we use a sentinel key 0 = "filter active".
    __u32 sentinel = 0;
    __u8 *active = bpf_map_lookup_elem(&pid_filter, &sentinel);
    if (!active) {
        return true;   // no filter active
    }
    return val != NULL;
}

// ─── Uprobe: function entry ───────────────────────────────────────────────────

SEC("uprobe")
int uprobe_entry(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid  = (__u32)(pid_tgid >> 32);
    __u32 tgid = (__u32)(pid_tgid & 0xFFFFFFFF);

    if (!should_trace(pid)) {
        return 0;
    }

    __u64 now = bpf_ktime_get_ns();
    __u64 func_ip = PT_REGS_IP(ctx);

    // Record entry time for latency tracking
    struct entry_key ekey = { .pid = pid, .func_ip = func_ip };
    bpf_map_update_elem(&entry_times, &ekey, &now, BPF_ANY);

    // Build event
    __u32 zero = 0;
    struct call_event *ev = bpf_map_lookup_elem(&scratch, &zero);
    if (!ev) {
        return 0;
    }

    __builtin_memset(ev, 0, sizeof(*ev));
    ev->timestamp_ns = now;
    ev->pid          = pid;
    ev->tgid         = tgid;
    ev->func_ip      = func_ip;
    ev->caller_ip    = PT_REGS_SP(ctx);  // return addr lives at top of stack
    ev->is_return    = 0;
    bpf_get_current_comm(ev->comm, sizeof(ev->comm));

    bpf_perf_event_output(ctx, &call_events, BPF_F_CURRENT_CPU,
                          ev, sizeof(*ev));
    return 0;
}

// ─── Uretprobe: function return ───────────────────────────────────────────────

SEC("uretprobe")
int uprobe_return(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid  = (__u32)(pid_tgid >> 32);
    __u32 tgid = (__u32)(pid_tgid & 0xFFFFFFFF);

    if (!should_trace(pid)) {
        return 0;
    }

    __u64 now     = bpf_ktime_get_ns();
    __u64 func_ip = PT_REGS_IP(ctx);

    // Compute CPU time from entry
    struct entry_key ekey = { .pid = pid, .func_ip = func_ip };
    __u64 *entry_ts = bpf_map_lookup_elem(&entry_times, &ekey);
    __u64 cpu_time  = entry_ts ? (now - *entry_ts) : 0;
    if (entry_ts) {
        bpf_map_delete_elem(&entry_times, &ekey);
    }

    __u32 zero = 0;
    struct call_event *ev = bpf_map_lookup_elem(&scratch, &zero);
    if (!ev) {
        return 0;
    }

    __builtin_memset(ev, 0, sizeof(*ev));
    ev->timestamp_ns = now;
    ev->pid          = pid;
    ev->tgid         = tgid;
    ev->func_ip      = func_ip;
    ev->cpu_time_ns  = cpu_time;
    ev->is_return    = 1;
    bpf_get_current_comm(ev->comm, sizeof(ev->comm));

    bpf_perf_event_output(ctx, &call_events, BPF_F_CURRENT_CPU,
                          ev, sizeof(*ev));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
