#include <bpf/libbpf.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include "guard.skel.h"

static volatile int stop;
static void on_sig(int s) { stop = 1; }

int main(void)
{
    struct guard_bpf *skel = guard_bpf__open_and_load();
    if (!skel) { fprintf(stderr, "open/load failed\n"); return 1; }

    if (guard_bpf__attach(skel)) {
        fprintf(stderr, "attach failed\n");
        guard_bpf__destroy(skel);
        return 1;
    }

    printf("LSM privilege-escalation guard active. Ctrl-C to detach.\n");
    signal(SIGINT, on_sig); signal(SIGTERM, on_sig);
    while (!stop) sleep(1);

    guard_bpf__destroy(skel);
    return 0;
}