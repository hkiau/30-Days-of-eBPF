CLANG ?= clang
CC ?= gcc
LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf)
LIBBPF_LIBS := $(shell pkg-config --libs libbpf)

all: hello.bpf.o hello

hello.bpf.o: hello.bpf.c
	$(CLANG) -O2 -g -target bpf -c hello.bpf.c -o hello.bpf.o

hello: hello.c
	$(CC) -g -O2 $(LIBBPF_CFLAGS) -o hello hello.c $(LIBBPF_LIBS)

clean:
	rm -f hello.bpf.o hello

.PHONY: all clean