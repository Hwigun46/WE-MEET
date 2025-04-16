CLANG_FLAGS = -O2 -g -Wall -target bpf
BPFTOOL_OBJ = prog.o
LOADER = ebpf-loader

all: $(BPFTOOL_OBJ) $(LOADER)

prog.o: main.bpf.c
	clang $(CLANG_FLAGS) -c main.bpf.c -o prog.o

$(LOADER): loader.c
	gcc -o $(LOADER) loader.c -lelf -lz -lbpf

clean:
	rm -f prog.o $(LOADER)