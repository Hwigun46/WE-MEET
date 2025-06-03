#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "common.h"

char LICENSE[] SEC("license") = "GPL";

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} shell_cmd_event_map SEC(".maps");

SEC("uretprobe/bash:readline")
static int handle_shell_cmd(struct pt_regs *ctx)
{
    struct shell_cmd_event_t *evt;
    evt = bpf_ringbuf_reserve(&shell_cmd_event_map, sizeof(*evt), 0);

    if (!evt)
        return 0;

    // event type
    evt->base.event_type = EVENT_SHELL_CMD;

    // pid
    u64 pid_tgid = bpf_get_current_pid_tgid();
    evt->base.pid = pid_tgid >> 32;

    // ppid
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent;

    bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent);
    bpf_probe_read_kernel(&evt->base.ppid, sizeof(evt->base.ppid), &parent->tgid);

    // uid
    u64 uid_gid = bpf_get_current_uid_gid();
    evt->base.uid = uid_gid >> 32;

    // comm
    bpf_get_current_comm(&evt->base.comm, sizeof(evt->base.comm));

    // filename

    // timestamp
    evt->base.timestamp_ns = bpf_ktime_get_ns();

    // readline
    const char *line_ptr = (const char *)PT_REGS_RC(ctx);
    bpf_probe_read_user_str(&evt->command, sizeof(evt->command), line_ptr);

    bpf_ringbuf_submit(evt, 0);
    return 0;
}