build:
	clang -g -O2 -target bpf -I . -c uprobe.bpf.c -o uprobe.bpf.o
	bpftool gen skeleton uprobe.bpf.o > uprobe.skel.h
	clang -Wall -I . -c uprobe.c -o uprobe.o
	clang -Wall uprobe.o -lbpf -lelf -lz -o sample

btf:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
