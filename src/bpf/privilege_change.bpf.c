#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

// 라이센스 설정
char LICENSE[] SEC("license") = "GPL";

// 기존 uid_gid_info를 저장할 map
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, struct euid_info_t);
    __uint(max_entries, 1024);
} euid_info_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} privilege_change_event_map SEC(".maps");

// kprobe (setreuid 전에 attach 해서 process uid,euid check)
SEC("kprobe/sys_setreuid")
static int handle_privilege_change_kprobe(struct pt_regs *ctx)
{

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    u32 euid;
    struct cred *cred_ptr;

    bpf_core_read(&cred_ptr, sizeof(cred_ptr), &task->cred);
    bpf_core_read(&euid, sizeof(euid), &cred_ptr->euid);

    u32 pid = bpf_get_current_pid_tgid() >> 32;

    u32 uid = bpf_get_current_uid_gid() >> 32;

    struct euid_info_t info = {};

    info.pid = pid;
    info.old_uid = uid;
    info.old_euid = euid;

    bpf_map_update_elem(&euid_info_map, &pid, &info, BPF_ANY);

    return 0;
}

// kretprobe (setreuid return에 attach 해서 변화된 euid check)
SEC("kretprobe/sys_setreuid")
static int handle_privilege_change_kretprobe(struct pt_regs *ctx)
{
    struct privilege_change_event_t *evt;
    evt = bpf_ringbuf_reserve(&privilege_change_event_map, sizeof(*evt), 0);
    if (!evt)
        return 0;

    evt->base.event_type = EVENT_PRIVILEGE_CHANGE;

    u64 pid_tid = bpf_get_current_pid_tgid();

    u32 pid = pid_tid >> 32;

    u32 tid = pid_tid & 0xFFFFFFFF;

    u64 uid_gid = bpf_get_current_uid_gid();

    u32 uid = uid_gid >> 32;

    u32 gid = uid_gid & 0xFFFFFFFF;

    // 아까 저장해둔 old_uid, old_euid map에서 꺼내오기
    struct euid_info_t *info = bpf_map_lookup_elem(&euid_info_map, &pid);

    if (!info)
    {
        bpf_ringbuf_discard(evt, 0);
        return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent;

    bpf_core_read(&parent, sizeof(parent), &task->real_parent);
    bpf_core_read(&evt->base.ppid, sizeof(evt->base.ppid), &parent->tgid);

    bpf_get_current_comm(&evt->base.comm, sizeof(evt->base.comm));

    evt->base.timestamp_ns = bpf_ktime_get_ns();

    evt->base.pid = pid;

    evt->base.uid = uid;

    evt->old_uid = info->old_uid;
    evt->old_euid = info->old_euid;

    struct cred *cred_ptr;

    bpf_core_read(&cred_ptr, sizeof(cred_ptr), &task->cred);
    bpf_core_read(&evt->new_euid, sizeof(evt->new_euid), &cred_ptr->euid);

    bpf_ringbuf_submit(evt, 0);

    bpf_map_delete_elem(&euid_info_map, &pid);

    return 0;
}