#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "common.h"

// 라이센스 설정
char LICENSE[] SEC("license") = "GPL";

// map 구조체 설정
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} process_create_event_map SEC(".maps");

// 프로세스 생성 Tracepoint
SEC("tracepoint/syscalls/sys_enter_execve")
static int handle_process_create(struct trace_event_raw_sys_enter *ctx)
{

    // common 헤더 파일에 생성해 둔 이벤트 구조체
    struct process_create_event_t *evt;
    evt = bpf_ringbuf_reserve(&process_create_event_map, sizeof(*evt), 0);
    if (!evt)
        return 0;

    // event type
    evt->base.event_type = EVENT_PROCESS_CREATE;

    // pid & tid
    u64 pid_tgid = bpf_get_current_pid_tgid();

    evt->base.pid = pid_tgid >> 32;
    evt->base.tid = pid_tgid & 0xFFFFFFFF;

    // ppid
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent;

    // 현재 task_struct 구조체로 부모를 찾음
    // 이후 task_struct.tgid는 그 스레드가 속하는 프로세스의 그룹 id => 실제 프로세스id
    // 따라서 tgid를 가져와야함
    bpf_core_read(&parent, sizeof(parent), &task->real_parent);
    bpf_core_read(&evt->base.ppid, sizeof(evt->base.ppid), &parent->tgid);

    // uid & gid
    u64 uid_gid = bpf_get_current_uid_gid();

    evt->base.uid = uid_gid >> 32;
    evt->base.gid = uid_gid & 0xFFFFFFFF;

    // comm
    bpf_get_current_comm(&evt->base.comm, sizeof(evt->base.comm));

    // timestamp
    // evt->base.timestamp_ns = bpf_ktime_get_ns();

    // start_time_ns
    bpf_probe_read_kernel(&evt->start_time_ns, sizeof(evt->start_time_ns), &task->start_time);

    // event map에 보내기
    bpf_ringbuf_submit(evt, 0);
    return 0;
}
