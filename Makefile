# Toolchain: clang, bpftool, libbpf-dev, libelf-dev, zlib1g-dev
ARCH    := $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/;s/arm.*/arm/')
CLANG   ?= clang
BPFTOOL ?= bpftool

all: loader

# Generated from the RUNNING kernel's BTF. Requires CONFIG_DEBUG_INFO_BTF=y.
vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

hashguard.bpf.o: hashguard.bpf.c vmlinux.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		-c hashguard.bpf.c -o $@

hashguard.skel.h: hashguard.bpf.o
	$(BPFTOOL) gen skeleton hashguard.bpf.o > hashguard.skel.h

loader: loader.c hashguard.skel.h
	$(CC) -g -O2 loader.c -lbpf -lelf -lz -o loader

run: loader
	sudo ./loader

clean:
	rm -f loader *.o *.skel.h vmlinux.h

.PHONY: all run clean