# AegisKernel eBPF Probe Makefile
# Compiles C BPF source into BPF ELF bytecode using Clang/LLVM

CLANG ?= clang
LLVM_STRIP ?= llvm-strip
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_CFLAGS := -target bpf \
              -D__TARGET_ARCH_$(ARCH) \
              -O2 -g -Wall \
              -I/usr/include/$(shell uname -m)-linux-gnu \
              -I.

BPF_SRC := bpf/aegis_probes.bpf.c
BPF_OBJ := bpf/aegis_probes.bpf.o

.PHONY: all clean

all: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@

clean:
	rm -f $(BPF_OBJ)
