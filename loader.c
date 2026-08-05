#include <bpf/libbpf.h>
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include "hashguard.skel.h"

static volatile sig_atomic_t stop;
static void on_sig(int s) { (void)s; stop = 1; }

static int libbpf_print(enum libbpf_print_level lvl, const char *fmt, va_list ap)
{
    (void)lvl;
    return vfprintf(stderr, fmt, ap);
}

int main(void)
{
    libbpf_set_print(libbpf_print);

    struct hashguard_bpf *skel = hashguard_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "ERROR: open/load failed. "
                        "Kernel too old for bpf_ima_file_hash (need 5.18+)?\n");
        return 1;
    }

    if (hashguard_bpf__attach(skel)) {
        fprintf(stderr, "ERROR: attach failed. "
                        "Is 'bpf' listed in /sys/kernel/security/lsm ?\n");
        hashguard_bpf__destroy(skel);
        return 1;
    }

    printf("hashguard active. Watching exec()s. Ctrl-C to detach.\n");
    printf("Logs:  sudo cat /sys/kernel/debug/tracing/trace_pipe\n");

    signal(SIGINT,  on_sig);
    signal(SIGTERM, on_sig);
    while (!stop)
        sleep(1);

    hashguard_bpf__destroy(skel);
    printf("\ndetached.\n");
    return 0;
}