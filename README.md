# Day 1 - Hello eBPF

This is the first example in the 30 Days of eBPF series. It introduces the basic flow of writing an eBPF program, loading it into the kernel, and attaching it to a tracepoint.

## What this example does

The program in [hello.bpf.c](hello.bpf.c) attaches to the tracepoint `tp/syscalls/sys_enter_write` and prints a message whenever the `write()` system call is entered.

The userspace loader in [hello.c](hello.c) opens the compiled BPF object, loads it into the kernel, attaches it, and keeps the process running so the trace output can be observed.

## Prerequisites

Make sure the following tools and packages are installed:

- `clang`
- `gcc`
- `pkg-config`
- `libbpf` development headers and libraries

On Ubuntu or Debian-based systems, you can install the common dependencies with:

```bash
sudo apt update
sudo apt install -y clang gcc pkg-config libbpf-dev linux-headers-$(uname -r)
```

## Build the example

From the repository root, run:

```bash
make
```

This will produce the compiled BPF object `hello.bpf.o` and the userspace loader `hello`.

## Run the example

Start the loader as root:

```bash
sudo ./hello
```

You should see output similar to:

```text
BPF program attached successfully!
Run this in another terminal to see the output:
  sudo cat /sys/kernel/debug/tracing/trace_pipe

Press Ctrl+C to stop.
```

In another terminal, watch the trace pipe:

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

Now run a command that uses `write()`, such as:

```bash
echo "hello" > /dev/null
```

You should see a message from your eBPF program in the trace output.

## Project files

- [hello.bpf.c](hello.bpf.c): the eBPF program itself
- [hello.c](hello.c): the userspace loader that attaches the program
- [Makefile](Makefile): builds the BPF object and loader

## Next steps

Once this example works, you can start exploring:

- how tracepoints are used in eBPF
- how BPF programs are attached to different hooks
- how to inspect kernel-side logs and tracing output
