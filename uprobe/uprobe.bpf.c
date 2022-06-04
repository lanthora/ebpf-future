#define __x86_64__
#include "uprobe.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// RAX, RBX, RCX, RDI, RSI, R8, R9, R10, R11
// conn buffer.bash buffer.len buffer.cap
SEC("uprobe/crypto/tls.(*Conn).Write")
int crypto_tls_write_enter(struct pt_regs *ctx)
{
	struct crypto_event *e;
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->type = EVENT_WRITE;
	e->size = ctx->cx;
	bpf_probe_read_user(&e->buffer, BUFFER_MAX, (char *)ctx->bx);

	bpf_ringbuf_submit(e, 0);

	return 0;
}

// FIXME: 无法正确获取退出时的参数,获取参数方式可能有问题
SEC("uretprobe/crypto/tls.(*Conn).Read")
int crypto_tls_read_exit(struct pt_regs *ctx)
{
	struct crypto_event *e;
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->type = EVENT_READ;
	e->size = ctx->cx;
	bpf_probe_read_user(&e->buffer, BUFFER_MAX, (char *)ctx->bx);

	bpf_ringbuf_submit(e, 0);
	return 0;
}