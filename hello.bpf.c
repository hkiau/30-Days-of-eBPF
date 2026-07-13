#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

SEC("tp/syscalls/sys_enter_write")
int hello(void *ctx)
{
    bpf_printk("Hello, eBPF World! Someone called write()\n");
    return 0;
}