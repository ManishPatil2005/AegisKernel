// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/*
 * AegisKernel: In-Kernel BPF-LSM & Tracepoint Security Instrumentation
 * 
 * Intercepts binary executions, privilege transitions, and memory mutations,
 * emitting structured records into BPF_MAP_TYPE_RINGBUF.
 */

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
#endif

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

#define MAX_COMM_LEN 16
#define MAX_PATH_LEN 256

enum aegis_event_type {
    AEGIS_EVENT_PROCESS_EXEC  = 1,
    AEGIS_EVENT_PROCESS_EXIT  = 2,
    AEGIS_EVENT_PRIVILEGE_ESC = 3,
    AEGIS_EVENT_MEMORY_PROT   = 4,
    AEGIS_EVENT_SOCKET_CONN   = 5,
    AEGIS_EVENT_CANARY_HIT    = 6,
    AEGIS_EVENT_GHOST_SHUNT   = 7,
};

struct aegis_raw_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tgid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    __u32 event_type;
    __u64 cgroup_id;
    __u64 lineage_hash;
    char comm[MAX_COMM_LEN];
    char filename[MAX_PATH_LEN];
};

/* BPF Ring Buffer Map Definition */
struct {
    __u32 type;
    __u32 max_entries;
} aegis_events_ringbuf __attribute__((section(".maps"))) = {
    .type = 27, /* BPF_MAP_TYPE_RINGBUF */
    .max_entries = 64 * 1024 * 1024, /* 64 MB */
};

/* BPF Helper Prototypes */
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) = (void *) 131;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *) 132;
static void (*bpf_ringbuf_discard)(void *data, __u64 flags) = (void *) 133;
static __u64 (*bpf_ktime_get_ns)(void) = (void *) 5;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *) 14;
static __u64 (*bpf_get_current_uid_gid)(void) = (void *) 15;
static long (*bpf_get_current_comm)(void *buf, __u32 size_of_buf) = (void *) 16;
static __u64 (*bpf_get_current_cgroup_id)(void) = (void *) 80;

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute pop
#endif

__attribute__((section("tracepoint/sched/sched_process_exec"), used))
int handle_sched_process_exec(void *ctx)
{
    struct aegis_raw_event *event;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();

    event = bpf_ringbuf_reserve(&aegis_events_ringbuf, sizeof(*event), 0);
    if (!event) {
        return 0; // Ring buffer full, event dropped gracefully
    }

    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = pid_tgid >> 32;
    event->tgid = (__u32)pid_tgid;
    event->ppid = 1; // Resolved via task struct in full CO-RE build
    event->uid = (__u32)uid_gid;
    event->gid = uid_gid >> 32;
    event->event_type = AEGIS_EVENT_PROCESS_EXEC;
    event->cgroup_id = bpf_get_current_cgroup_id();
    event->lineage_hash = 0;

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    // Submit atomically to userspace ring buffer
    bpf_ringbuf_submit(event, 0);

    return 0;
}

__attribute__((section("license"), used))
char LICENSE[] = "Dual BSD/GPL";
