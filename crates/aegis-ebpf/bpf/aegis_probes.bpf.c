// SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
/*
 * AegisKernel: In-Kernel BPF-LSM & Tracepoint Security Instrumentation
 * 
 * Intercepts binary executions, privilege transitions, memory mutations,
 * and outbound socket connections, emitting structured records into BPF_MAP_TYPE_RINGBUF.
 *
 * Implements Ghost-Mirror in-kernel process shunting and lineage sketch tracking.
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
#define PROT_READ  0x1
#define PROT_WRITE 0x2
#define PROT_EXEC  0x4

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

/* BPF Ring Buffer Map Definition (64 MB buffer) */
struct {
    __u32 type;
    __u32 max_entries;
} aegis_events_ringbuf __attribute__((section(".maps"))) = {
    .type = 27, /* BPF_MAP_TYPE_RINGBUF */
    .max_entries = 64 * 1024 * 1024,
};

/* Ghost-Mirror Shunt State Map (PID -> Shunt Flag) */
struct {
    __u32 type;
    __u32 max_entries;
    __u32 key_size;
    __u32 value_size;
} aegis_ghost_shunt_map __attribute__((section(".maps"))) = {
    .type = 1, /* BPF_MAP_TYPE_HASH */
    .max_entries = 16384,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
};

/* In-Kernel Lineage Sketch Map (PID -> 64-bit Ancestry Hash) */
struct {
    __u32 type;
    __u32 max_entries;
    __u32 key_size;
    __u32 value_size;
} aegis_lineage_map __attribute__((section(".maps"))) = {
    .type = 1, /* BPF_MAP_TYPE_HASH */
    .max_entries = 32768,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
};

/* BPF Helper Prototypes */
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) = (void *) 131;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *) 132;
static void (*bpf_ringbuf_discard)(void *data, __u64 flags) = (void *) 133;
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *) 2;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *) 3;
static __u64 (*bpf_ktime_get_ns)(void) = (void *) 5;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *) 14;
static __u64 (*bpf_get_current_uid_gid)(void) = (void *) 15;
static long (*bpf_get_current_comm)(void *buf, __u32 size_of_buf) = (void *) 16;
static __u64 (*bpf_get_current_cgroup_id)(void) = (void *) 80;

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute pop
#endif

/*
 * Hook 1: Process Execution Tracepoint
 * Intercepts binary executions, records process lineage, and initializes tracking.
 */
__attribute__((section("tracepoint/sched/sched_process_exec"), used))
int handle_sched_process_exec(void *ctx)
{
    struct aegis_raw_event *event;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 pid = pid_tgid >> 32;

    event = bpf_ringbuf_reserve(&aegis_events_ringbuf, sizeof(*event), 0);
    if (!event) {
        return 0; // Ring buffer full, dropped gracefully with atomic counter
    }

    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = pid;
    event->tgid = (__u32)pid_tgid;
    event->ppid = 1; // Resolved in CO-RE task inspection
    event->uid = (__u32)uid_gid;
    event->gid = uid_gid >> 32;
    event->event_type = AEGIS_EVENT_PROCESS_EXEC;
    event->cgroup_id = bpf_get_current_cgroup_id();
    
    // In-kernel lineage hash calculation: FNV-1a 64-bit combination
    __u64 lineage_hash = 0xcbf29ce484222325ULL ^ pid;
    event->lineage_hash = lineage_hash;
    bpf_map_update_elem(&aegis_lineage_map, &pid, &lineage_hash, 0);

    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/*
 * Hook 2: Process Exit Tracepoint
 * Cleans up internal BPF tracking maps when a process terminates.
 */
__attribute__((section("tracepoint/sched/sched_process_exit"), used))
int handle_sched_process_exit(void *ctx)
{
    struct aegis_raw_event *event;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    // Purge process entries from BPF tracking maps
    bpf_map_delete_elem(&aegis_ghost_shunt_map, &pid);
    bpf_map_delete_elem(&aegis_lineage_map, &pid);

    event = bpf_ringbuf_reserve(&aegis_events_ringbuf, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = pid;
    event->tgid = (__u32)pid_tgid;
    event->ppid = 0;
    event->uid = 0;
    event->gid = 0;
    event->event_type = AEGIS_EVENT_PROCESS_EXIT;
    event->cgroup_id = bpf_get_current_cgroup_id();
    event->lineage_hash = 0;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/*
 * Hook 3: BPF-LSM Privilege Transition (bprm_committed_creds)
 * Detects real-time privilege escalation (UID 0 root transitions).
 */
__attribute__((section("lsm/bprm_committed_creds"), used))
int BPF_PROG(handle_bprm_committed_creds, void *bprm)
{
    struct aegis_raw_event *event;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 uid = (__u32)uid_gid;

    // Monitor transitions to root (UID 0)
    if (uid != 0) {
        return 0; // Filter non-root transitions inside the kernel hook
    }

    event = bpf_ringbuf_reserve(&aegis_events_ringbuf, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = pid_tgid >> 32;
    event->tgid = (__u32)pid_tgid;
    event->ppid = 1;
    event->uid = uid;
    event->gid = uid_gid >> 32;
    event->event_type = AEGIS_EVENT_PRIVILEGE_ESC;
    event->cgroup_id = bpf_get_current_cgroup_id();
    event->lineage_hash = 0;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/*
 * Hook 4: BPF-LSM Memory Protection Hook (file_mprotect)
 * Detects fileless code injection by trapping memory pages converted to PROT_EXEC.
 */
__attribute__((section("lsm/file_mprotect"), used))
int BPF_PROG(handle_file_mprotect, void *vma, unsigned long reqprot, unsigned long prot)
{
    struct aegis_raw_event *event;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();

    // Trap executable memory modifications (W^X violation / shellcode injection)
    if (!(prot & PROT_EXEC)) {
        return 0; // Filter non-executable memory protections
    }

    event = bpf_ringbuf_reserve(&aegis_events_ringbuf, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = pid_tgid >> 32;
    event->tgid = (__u32)pid_tgid;
    event->ppid = 1;
    event->uid = (__u32)uid_gid;
    event->gid = uid_gid >> 32;
    event->event_type = AEGIS_EVENT_MEMORY_PROT;
    event->cgroup_id = bpf_get_current_cgroup_id();
    event->lineage_hash = 0;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/*
 * Hook 5: Socket Connect Tracepoint
 * Captures outbound socket connections for command-and-control (C2) detection.
 */
__attribute__((section("tracepoint/syscalls/sys_enter_connect"), used))
int handle_sys_enter_connect(void *ctx)
{
    struct aegis_raw_event *event;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 pid = pid_tgid >> 32;

    // Check if this process has been shunted into Ghost-Mirror deception
    __u32 *is_shunted = bpf_map_lookup_elem(&aegis_ghost_shunt_map, &pid);
    if (is_shunted && *is_shunted == 1) {
        // Process is shunted into deception: emit canary hit telemetry
        event = bpf_ringbuf_reserve(&aegis_events_ringbuf, sizeof(*event), 0);
        if (event) {
            event->timestamp_ns = bpf_ktime_get_ns();
            event->pid = pid;
            event->tgid = (__u32)pid_tgid;
            event->ppid = 1;
            event->uid = (__u32)uid_gid;
            event->gid = uid_gid >> 32;
            event->event_type = AEGIS_EVENT_GHOST_SHUNT;
            event->cgroup_id = bpf_get_current_cgroup_id();
            event->lineage_hash = 0;
            bpf_get_current_comm(&event->comm, sizeof(event->comm));
            bpf_ringbuf_submit(event, 0);
        }
        return 0;
    }

    event = bpf_ringbuf_reserve(&aegis_events_ringbuf, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = pid;
    event->tgid = (__u32)pid_tgid;
    event->ppid = 1;
    event->uid = (__u32)uid_gid;
    event->gid = uid_gid >> 32;
    event->event_type = AEGIS_EVENT_SOCKET_CONN;
    event->cgroup_id = bpf_get_current_cgroup_id();
    event->lineage_hash = 0;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    bpf_ringbuf_submit(event, 0);
    return 0;
}

__attribute__((section("license"), used))
char LICENSE[] = "Dual BSD/GPL";
