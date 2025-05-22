#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "common.h"

// 라이센스 설정
char LICENSE[] SEC("license") = "GPL";

// sock_info를 저장할 map
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, struct sock_info_t);
    __uint(max_entries, 1024);
} sock_info_map SEC(".maps");

// map 정의
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} tcp_connect_event_map SEC(".maps");

// 요청이 들어왔을 때 당시 해당 pt_regs에서 소켓 정보 가져와서 map 저장해두기
SEC("kprobe/tcp_connect")
static int handle_tcp_connect_kprobe(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);

    if (!sk)
        return 0;

    u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct sock_info_t info = {};

    // 더블언더바(__)는 내부 전용 혹은 특별한 용도라는 의미 / 내부에서만 사용하고 외부에서 직접 쓰면 X
    bpf_core_read(&info.saddr, sizeof(info.saddr), &sk->__sk_common.skc_rcv_saddr);
    bpf_core_read(&info.daddr, sizeof(info.daddr), &sk->__sk_common.skc_daddr);
    bpf_core_read(&info.sport, sizeof(info.sport), &sk->__sk_common.skc_num);
    bpf_core_read(&info.dport, sizeof(info.dport), &sk->__sk_common.skc_dport);

    bpf_map_update_elem(&sock_info_map, &pid, &info, BPF_ANY);

    return 0;
}

// map에 저장해둔 소켓 정보 + 연결 결과값 합치기
// 동적 trcepoint kretporbe로 걸어두기
SEC("kretprobe/tcp_connect")
static int handle_tcp_connect_kretprobe(struct pt_regs *ctx)
{
    // tcp 연결 성공 여부
    int ret = (int)PT_REGS_RC(ctx);

    // 연결 실패시 로그 X
    if (ret != 0)
        return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    struct sock_info_t *info = bpf_map_lookup_elem(&sock_info_map, &pid);

    if (!info)
        return 0;

    struct tcp_connect_event_t *evt;
    evt = bpf_ringbuf_reserve(&tcp_connect_event_map, sizeof(*evt), 0);
    if (!evt)
        return 0;

    evt->base.event_type = EVENT_TCP_CONNECT;

    evt->base.pid = pid;
    evt->base.tid = pid_tgid & 0xFFFFFFFF;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent;

    bpf_core_read(&parent, sizeof(parent), &task->real_parent);
    bpf_core_read(&evt->base.ppid, sizeof(evt->base.ppid), &parent->tgid);

    u64 uid_gid = bpf_get_current_uid_gid();
    evt->base.uid = uid_gid >> 32;
    evt->base.gid = uid_gid & 0xFFFFFFFF;

    bpf_get_current_comm(&evt->base.comm, sizeof(evt->base.comm));

    evt->base.timestamp_ns = bpf_ktime_get_ns();

    evt->saddr = info->saddr;
    evt->daddr = info->daddr;
    evt->sport = info->sport;
    evt->dport = bpf_ntohs(info->dport);
    evt->protocol = IPPROTO_TCP;

    bpf_ringbuf_submit(evt, 0);

    bpf_map_delete_elem(&sock_info_map, &pid);

    return 0;
}