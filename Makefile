build:
	clang -g -O2 -target bpf -I . -c bootstrap.bpf.c -o bootstrap.bpf.o
	bpftool gen skeleton bootstrap.bpf.o > bootstrap.skel.h
	clang -Wall -I . -c bootstrap.c -o bootstrap.o
	clang -Wall bootstrap.o -lbpf -lelf -lz -o bootstrap

btf:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

run:
	./hello

dump:
	llvm-objdump -d hello.bpf.o
