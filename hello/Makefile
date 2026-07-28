CLANG   ?= clang
BPFTOOL ?= bpftool
ARCH    := $(shell uname -m | sed 's/x86_64/x86/; s/aarch64/arm64/; s/arm.*/arm/')

CFLAGS  := -g -O2 -Wall
LDLIBS  := -lbpf -lelf -lz   

APP := hello

.PHONY: all clean

all: $(APP)

$(APP).bpf.o: $(APP).bpf.c hello.h vmlinux.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		-I. -c $(APP).bpf.c -o $@

$(APP).skel.h: $(APP).bpf.o
	$(BPFTOOL) gen skeleton $< > $@

$(APP): $(APP).c $(APP).skel.h hello.h
	$(CC) $(CFLAGS) -I. $(APP).c -o $@ $(LDLIBS)

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

clean:
	rm -f $(APP) $(APP).bpf.o $(APP).skel.h