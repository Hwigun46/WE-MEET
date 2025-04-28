#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

// 라이센스 설정
char LICENSE[] SEC("license") = "GPL";

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_file_open(struct trace_event_raw_sys_enter *ctx)
{

    struct file_open_event_t evt = {};

    // event type
    evt.base.event_type = EVENT_FILE_OPEN;

    // pid & tid
    u64 pid_tgid = bpf_get_current_pid_tgid();

    evt.base.pid = pid_tgid >> 32;
    evt.base.tid = pid_tgid & 0xFFFFFFFF;

    // uid & gid
    u64 uid_gid = bpf_get_current_uid_gid();

    evt.base.uid = uid_gid >> 32;
    evt.base.gid = uid_gid & 0xFFFFFFFF;

    // ppid
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent;

    bpf_core_read(&parent, sizeof(parent), &task->real_parent);
    bpf_core_read(&evt.base.ppid, sizeof(evt.base.ppid), &parent->tgid);

    // comm
    bpf_get_current_comm(&evt.base.comm, sizeof(evt.base.comm));

    // p_comm
    bpf_core_read_str(&evt.base.parent_comm, sizeof(evt.base.parent_comm), parent->comm);

    // timestamp
    evt.base.timestamp_ns = bpf_ktime_get_ns();

    // filename
    const char *filename_ptr = (const char *)ctx->args[1];
    bpf_core_read_str(evt.filename, sizeof(evt.filename), filename_ptr);

    //flags
    evt.flags = (int)ctx->args[2];

    // mode
    evt.mode = (int)ctx->args[3];

    // event map에 보내기
    bpf_perf_event_output(ctx, &event_output_map, BPF_F_CURRENT_CPU, &evt, sizeof(evt));

    return 0;
}
