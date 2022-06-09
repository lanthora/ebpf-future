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
	__type(value, unsigned long);
	__uint(max_entries, 1);
} array SEC(".maps");

SEC("uprobe/tls_write_enter")
int crypto_tls_write_enter(struct pt_regs *ctx)
{
	struct event *e;
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->type = EVENT_WRITE_ENTER;
	e->size = ctx->cx;
	bpf_probe_read_user(&e->buffer, BUFFER_MAX, (char *)ctx->bx);

	bpf_ringbuf_submit(e, 0);

	return 0;
}

SEC("uprobe/tls_read_enter")
int crypto_tls_read_enter(struct pt_regs *ctx)
{
	u32 id = 0;
	unsigned long rbx;
	rbx = ctx->bx;
	bpf_printk("enter rbx=%p\n", rbx);
	bpf_map_update_elem(&array, &id, &rbx, BPF_ANY);
	return 0;
}

SEC("uprobe/tls_read_exit")
int crypto_tls_read_exit(struct pt_regs *ctx)
{
	struct event *e;
	unsigned long *rbx;
	u32 id = 0;
	rbx = bpf_map_lookup_elem(&array, &id);
	if (!rbx)
		return 0;
	bpf_printk("exit rbx=%p\n", (*rbx));
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->type = EVENT_READ_EXIT;
	e->size = ctx->ax;
	bpf_probe_read_user(&e->buffer, BUFFER_MAX, (char *)(*rbx));

	bpf_ringbuf_submit(e, 0);
	return 0;
}
