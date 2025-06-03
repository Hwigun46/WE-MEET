BPF_CLANG=clang
BPF_LLVM_STRIP=llvm-strip
BPF_CFLAGS=-O2 -g -target bpf -D__TARGET_ARCH_arm64 \
  -Wall -Werror \
  -I./ \
  -I$(KERNEL_HEADERS) \
  -I$(PWD)

SRC_DIR = ./bpf
BUILD_DIR = ./build

BPF_PROGS = \
  process_create \
  process_terminate \
  file_open \
  tcp_connect \
  shell \
  
  
  

.PHONY: all clean

all: $(BPF_PROGS)

$(BPF_PROGS):
	$(BPF_CLANG) $(BPF_CFLAGS) -c $(SRC_DIR)/$@.bpf.c -o $(BUILD_DIR)/$@.bpf.o

clean:
	rm -f $(BUILD_DIR)/*.bpf.o