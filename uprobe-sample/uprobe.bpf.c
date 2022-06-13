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

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct tls_conn);
	__uint(max_entries, 1);
} array SEC(".maps");

SEC("uprobe/crypto/tls.(*Conn).Write")
int write_enter(struct pt_regs *ctx)
{
	struct event *e;
	struct go_interface i;
	void *ptr;

	__builtin_memset(&i, 0, sizeof(i));

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->type = EVENT_WRITE_ENTER;
	e->size = ctx->cx;
	bpf_probe_read_user(&e->buffer, BUFFER_MAX, (char *)ctx->bx);

	bpf_probe_read_user(&i, sizeof(i), (void *)ctx->ax);
	bpf_probe_read_user(&ptr, sizeof(i), i.ptr);
	bpf_probe_read_user(&e->fd, sizeof(e->fd), ptr + 16);

	bpf_ringbuf_submit(e, 0);

	return 0;
}

SEC("uprobe/crypto/tls.(*Conn).Read")
int read_enter(struct pt_regs *ctx)
{
	u32 id = 0;
	struct tls_conn c;
	struct go_interface i;
	void *ptr;

	__builtin_memset(&c, 0, sizeof(c));
	__builtin_memset(&i, 0, sizeof(i));

	c.buffer = (char *)ctx->bx;

	bpf_probe_read_user(&i, sizeof(i), (void *)ctx->ax);
	bpf_probe_read_user(&ptr, sizeof(i), i.ptr);
	bpf_probe_read_user(&c.fd, sizeof(c.fd), ptr + 16);

	bpf_map_update_elem(&array, &id, &c, BPF_ANY);
	return 0;
}

SEC("uprobe/crypto/tls.(*Conn).Read")
int read_exit(struct pt_regs *ctx)
{
	struct event *e;
	struct tls_conn *c;
	u32 id = 0;

	if (!ctx->ax)
		return 0;

	c = bpf_map_lookup_elem(&array, &id);
	if (!c)
		return 0;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->type = EVENT_READ_EXIT;
	e->size = ctx->ax;
	bpf_probe_read_user(&e->buffer, BUFFER_MAX, c->buffer);
	e->fd = c->fd;

	bpf_ringbuf_submit(e, 0);
	return 0;
}
