#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

// 라이센스 설정
char LICENSE[] SEC("license") = "GPL";

// map 정의
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} file_open_event_map SEC(".maps");

// 파일 열기(생성) Tracepoint
SEC("tracepoint/syscalls/sys_enter_openat")
static int handle_file_open(struct trace_event_raw_sys_enter *ctx)
{

    struct file_open_event_t *evt;
    evt = bpf_ringbuf_reserve(&file_open_event_map, sizeof(*evt), 0);
    if (!evt)
        return 0;

    // event type
    evt->base.event_type = EVENT_FILE_OPEN;

    // pid
    u64 pid_tgid = bpf_get_current_pid_tgid();
    evt->base.pid = pid_tgid >> 32;

    // ppid
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent;

    bpf_core_read(&parent, sizeof(parent), &task->real_parent);
    bpf_core_read(&evt->base.ppid, sizeof(evt->base.ppid), &parent->tgid);

    // uid
    u64 uid_gid = bpf_get_current_uid_gid();
    evt->base.uid = uid_gid >> 32;

    // comm
    bpf_get_current_comm(&evt->base.comm, sizeof(evt->base.comm));

    // timestamp
    evt->base.timestamp_ns = bpf_ktime_get_ns();


    // filename
    const char *filename = (const char *)ctx->args[1];
    int len = bpf_probe_read_user_str(&evt->filename, sizeof(evt->filename), filename);

    if (len <= 1)
    { // 빈 문자열 또는 읽기 실패 시
        bpf_ringbuf_discard(evt, 0);
        return 0;
    }

    evt->flags = (int)ctx->args[2];
    evt->mode = (int)ctx->args[3];

    bpf_ringbuf_submit(evt, 0);

    return 0;
}
