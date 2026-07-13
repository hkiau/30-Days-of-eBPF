#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>

int main(void)
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link;

    obj = bpf_object__open_file("hello.bpf.o", NULL);
    if (!obj) {
        fprintf(stderr, "ERROR: opening BPF object file failed\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "ERROR: loading BPF object into kernel failed\n");
        return 1;
    }

    prog = bpf_object__find_program_by_name(obj, "hello");
    link = bpf_program__attach(prog);
    if (!link) {
        fprintf(stderr, "ERROR: attaching BPF program failed\n");
        return 1;
    }

    printf("BPF program attached successfully!\n");
    printf("Run this in another terminal to see the output:\n");
    printf("  sudo cat /sys/kernel/debug/tracing/trace_pipe\n\n");
    printf("Press Ctrl+C to stop.\n");

    while (1)
        sleep(1);

    bpf_link__destroy(link);
    bpf_object__close(obj);
    return 0;
}