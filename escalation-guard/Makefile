ARCH := $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/')

all: loader

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

guard.bpf.o: guard.bpf.c vmlinux.h
	clang -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -c guard.bpf.c -o $@

guard.skel.h: guard.bpf.o
	bpftool gen skeleton guard.bpf.o > guard.skel.h

loader: loader.c guard.skel.h
	$(CC) -g -O2 loader.c -lbpf -lelf -lz -o loader

clean:
	rm -f loader *.o *.skel.h vmlinux.h