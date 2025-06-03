#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "common.h"

#ifndef __user
#define __user
#endif

#define ARG_MAX 5
#define ARG_LEN 24

// 라이센스 설정
char LICENSE[] SEC("license") = "GPL";

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} shell_cmd_event_map SEC(".maps");

SEC("kprobe/sys_execve")
static int handle_shell_cmd(struct pt_regs *ctx)
{

    struct shell_cmd_event_t *evt;
    evt = bpf_ringbuf_reserve(&shell_cmd_event_map, sizeof(*evt), 0);
    if (!evt)
        return 0;

    evt->base.event_type = EVENT_SHELL_CMD;

    u64 pid_tgid = bpf_get_current_pid_tgid();

    evt->base.pid = pid_tgid >> 32;

    u64 uid_gid = bpf_get_current_uid_gid();

    evt->base.uid = uid_gid >> 32;

    bpf_get_current_comm(&evt->base.comm, sizeof(evt->base.comm));

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent;

    bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent);
    bpf_probe_read_kernel(&evt->base.ppid, sizeof(evt->base.ppid), &parent->tgid);

    evt->base.timestamp_ns = bpf_ktime_get_ns();

    const char __user *const __user *argv = (const char __user *const __user *)PT_REGS_PARM2(ctx);

    bool has_command = false;

    #pragma unroll
    for (int i = 0; i < ARG_MAX; i++)
    {
        const char *arg;
        bpf_probe_read_user(&arg, sizeof(arg), &argv[i]);
        if (!arg)
            break;

        int start = i * ARG_LEN;
        if (start >= sizeof(evt->command))
            break;

        int len = bpf_probe_read_user_str(&evt->command[start], ARG_LEN, arg);
        bpf_printk("arg[%d] len=%d", i, len);
        if (len > 1)
        {
            has_command = true;
        }
    }

    if (has_command)
    {
        bpf_ringbuf_submit(evt, 0);
    }
    else
    {
        bpf_ringbuf_discard(evt, 0);
    }

    return 0;
}