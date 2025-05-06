#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

// 라이센스 설정
char LICENSE[] SEC("license") = "GPL";

// 프로세스 생성 Tracepoint
SEC("tracepoint/syscalls/sys_enter_execve")
int handle_process_create(struct trace_event_raw_sys_enter *ctx)
{

    struct process_create_event_t evt = {};

    // event type
    evt.base.event_type = EVENT_PROCESS_CREATE;

    // pid & tid
    u64 pid_tgid = bpf_get_current_pid_tgid();

    evt.base.pid = pid_tgid >> 32;
    evt.base.tid = pid_tgid & 0xFFFFFFFF;

    // ppid
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent;

    bpf_core_read(&parent, sizeof(parent), &task->real_parent);
    bpf_core_read(&evt.base.ppid, sizeof(evt.base.ppid), &parent->tgid);

    // uid & gid
    u64 uid_gid = bpf_get_current_uid_gid();

    evt.base.uid = uid_gid >> 32;
    evt.base.gid = uid_gid & 0xFFFFFFFF;

    // comm
    bpf_get_current_comm(&evt.base.comm, sizeof(evt.base.comm));

    // parent comm
    bpf_core_read_str(&evt.base.parent_comm, sizeof(evt.base.parent_comm), parent->comm);

    // timestamp
    evt.base.timestamp_ns = bpf_ktime_get_ns();

    // start_time_ns
    bpf_probe_read_kernel(&evt.start_time_ns,sizeof(evt.start_time_ns), &task->start_time);

    // event map에 보내기
    bpf_perf_event_output(ctx, &event_output_map, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return 0;
}

// 프로세스 종료 Tracepoint
// 프로세스 종료는 내부 커널 함수로 처리된다 syscall이 아닌 -> 동적 Tracepoint를 사용
SEC("kprobe/do_exit")
// 동적 Tracepoint의 경우에는 ctx 타입이 당시 register의 주소 정보로 받는다
int handle_process_exit(struct pt_regs *ctx)
{

    struct process_terminate_event_t evt = {};

    // event type
    evt.base.event_type = EVENT_PROCESS_TERMINATE;

    // pid & tid
    u64 pid_tgid = bpf_get_current_pid_tgid();

    evt.base.pid = pid_tgid >> 32;
    evt.base.tid = pid_tgid & 0xFFFFFFFF;

    // ppid
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent;

    bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent);
    bpf_probe_read_kernel(&evt.base.ppid, sizeof(evt.base.ppid), &parent->tgid);

    // uid & gid
    u64 uid_gid = bpf_get_current_uid_gid();

    evt.base.uid = uid_gid >> 32;
    evt.base.gid = uid_gid & 0xFFFFFFFF;

    // comm
    bpf_get_current_comm(&evt.base.comm, sizeof(evt.base.comm));

    // parent comm
    bpf_core_read_str(&evt.base.parent_comm, sizeof(evt.base.parent_comm), parent->comm);

    // timestamp
    evt.base.timestamp_ns = bpf_ktime_get_ns();

    // exit_code
    evt.exit_code = PT_REGS_PARM1(ctx);

    // duration
    u64 start_ns = 0;
    bpf_probe_read_kernel(&start_ns, sizeof(start_ns), &task->start_time);

    evt.duration_ns = evt.base.timestamp_ns - start_ns;

    // event map에 보내기
    bpf_perf_event_output(ctx, &event_output_map, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return 0;
}