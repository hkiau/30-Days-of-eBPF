#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

SEC("tp/syscalls/sys_enter_write")
int hello(struct trace_event_raw_sys_enter *ctx)
{
    int fd = (int)ctx->args[0];
    const char *ubuf = (const char *)ctx->args[1];
    __u64 count = (__u64)ctx->args[2];

    char buf[64] = {};
    bpf_probe_read_user_str(buf, sizeof(buf), ubuf);
    bpf_printk("fd=%d count=%llu data=%s", fd, count, buf);
    return 0;
}