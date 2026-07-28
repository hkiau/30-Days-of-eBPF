#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";
#define EPERM 1

SEC("lsm/bprm_check_security")
int BPF_PROG(guard_suid_exec, struct linux_binprm *bprm, int ret)
{
    if (ret != 0)                       
        return ret;

    __u32 caller_uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    if (caller_uid == 0)               
        return 0;

    __u32 new_euid = BPF_CORE_READ(bprm, cred, euid.val);
    if (new_euid == 0) {               
        bpf_printk("blocked suid-root exec by uid %u", caller_uid);
        return -EPERM;
    }
    return 0;
}

SEC("lsm/task_fix_setuid")
int BPF_PROG(guard_setuid, struct cred *new, const struct cred *old,
             int flags, int ret)
{
    if (ret != 0)
        return ret;

    __u32 old_euid = BPF_CORE_READ(old, euid.val);
    __u32 new_euid = BPF_CORE_READ(new, euid.val);

    if (old_euid != 0 && new_euid == 0) {
        bpf_printk("blocked setuid escalation %u -> %u", old_euid, new_euid);
        return -EPERM;
    }
    return 0;
}