#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "hello.skel.h"
#include "hello.h"

static volatile sig_atomic_t stop;
static FILE *out;
static int   first = 1;  

static void sig_handler(int sig)
{
	stop = 1;
}


static void json_escape(FILE *f, const char *s)
{
	for (; *s; s++) {
		unsigned char c = (unsigned char)*s;
		switch (c) {
		case '"':  fputs("\\\"", f); break;
		case '\\': fputs("\\\\", f); break;
		case '\n': fputs("\\n", f);  break;
		case '\r': fputs("\\r", f);  break;
		case '\t': fputs("\\t", f);  break;
		default:
			if (c < 0x20)
				fprintf(f, "\\u%04x", c);
			else
				fputc(c, f);
		}
	}
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;

	if (!first)
		fputs(",\n", out);
	first = 0;

	fprintf(out, "  {\"pid\": %d, \"comm\": \"", e->pid);
	json_escape(out, e->comm);
	fprintf(out, "\", \"fd\": %d, \"count\": %llu, \"data\": \"",
		e->fd, e->count);
	json_escape(out, e->data);
	fputs("\"}", out);

	fflush(out);  
	return 0;
}

int main(int argc, char **argv)
{
	const char *path = (argc > 1) ? argv[1] : "events.json";
	struct ring_buffer *rb = NULL;
	struct hello_bpf   *skel;
	int err;

	signal(SIGINT,  sig_handler);
	signal(SIGTERM, sig_handler);

	out = fopen(path, "w");
	if (!out) {
		perror("fopen");
		return 1;
	}
	fputs("[\n", out);

	skel = hello_bpf__open();
	if (!skel) {
		fprintf(stderr, "failed to open BPF skeleton\n");
		goto cleanup;
	}

	skel->rodata->my_pid = getpid();

	err = hello_bpf__load(skel);
	if (err) {
		fprintf(stderr, "failed to load BPF skeleton: %d\n", err);
		goto cleanup;
	}

	err = hello_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "failed to attach BPF skeleton: %d\n", err);
		goto cleanup;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb),
			      handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "failed to create ring buffer\n");
		goto cleanup;
	}

	printf("Writing events to %s ... press Ctrl-C to stop.\n", path);

	while (!stop) {
		err = ring_buffer__poll(rb, 100);
		if (err == -EINTR)
			break;
		if (err < 0) {
			fprintf(stderr, "ring buffer poll error: %d\n", err);
			break;
		}
	}

cleanup:
	fputs("\n]\n", out);
	fclose(out);
	ring_buffer__free(rb);
	hello_bpf__destroy(skel);
	return 0;
}