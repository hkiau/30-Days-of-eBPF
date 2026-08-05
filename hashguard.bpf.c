#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define EPERM     1
#define HASH_LEN  32

#define ENFORCE   0

#define N_BLOCKED 2
static const __u8 blocklist[N_BLOCKED][HASH_LEN] = {
    { 0xaa,0xbb,0xcc,0xdd,0x00,0x11,0x22,0x33,
      0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,
      0xcc,0xdd,0xee,0xff,0x00,0x11,0x22,0x33,
      0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb },

      { 0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
      0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,
      0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
      0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00 },
};

static __always_inline int hash_eq(const __u8 *a, const __u8 *b)
{
    #pragma unroll
    for (int i = 0; i < HASH_LEN; i++)
        if (a[i] != b[i])
            return 0;
    return 1;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(check_hash, struct linux_binprm *bprm, int ret)
{
    if (ret != 0)
        return ret;

    __u8 hash[HASH_LEN] = {};
    struct file *f = BPF_CORE_READ(bprm, file);

    long r = bpf_ima_file_hash(f, hash, sizeof(hash));
    if (r < 0)
        return 0;          

    #pragma unroll
    for (int i = 0; i < N_BLOCKED; i++) {
        if (hash_eq(hash, blocklist[i])) {
            __u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
            bpf_printk("hashguard: MATCH blocklist[%d] uid=%u", i, uid);
#if ENFORCE
            return -EPERM; 
#else
            return 0;
#endif
        }
    }
    return 0;
}