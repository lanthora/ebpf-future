#include "uprobe.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// runtime.g goid
#define OFFSET_G_GOID 152
// crypto/tls.Conn conn
#define OFFSET_TLS_CONN_CONN 0
// net.poll.FD Sysfd
#define OFFSET_NET_POLL_FD_SYSFD 16

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct tls_conn_key);
	__type(value, struct tls_conn);
	__uint(max_entries, 128);
} tls_conn_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, u64);
	__type(value, s64);
	__uint(max_entries, MAX_SYSTEM_THREADS);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} goroutines_map SEC(".maps");

s64 get_current_goroutine()
{
	u64 current_thread = bpf_get_current_pid_tgid();
	void *goid_ptr = bpf_map_lookup_elem(&goroutines_map, &current_thread);
	s64 goid;
	bpf_probe_read(&goid, sizeof(goid), goid_ptr);
	return goid;
}

int get_fd_from_tls_conn(void *tls_conn)
{
	struct go_interface i;
	void *ptr;
	int fd;

	__builtin_memset(&i, 0, sizeof(i));

	bpf_probe_read_user(&i, sizeof(i), tls_conn + OFFSET_TLS_CONN_CONN);
	bpf_probe_read_user(&ptr, sizeof(i), i.ptr);
	bpf_probe_read_user(&fd, sizeof(fd), ptr + OFFSET_NET_POLL_FD_SYSFD);

	return fd;
}

SEC("uprobe/crypto/tls.(*Conn).Write")
int write_enter(struct pt_regs *ctx)
{
	struct event *e;
	s64 id = 0;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	id = get_current_goroutine();

	e->type = EVENT_WRITE_ENTER;
	e->size = ctx->cx;
	bpf_probe_read_user(&e->buffer, BUFFER_MAX, (char *)ctx->bx);
	e->fd = get_fd_from_tls_conn((void *)ctx->ax);
	e->goid = id;
	e->tgid = bpf_get_current_pid_tgid() >> 32;

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("uprobe/crypto/tls.(*Conn).Read")
int read_enter(struct pt_regs *ctx)
{
	struct tls_conn c;
	struct tls_conn_key key;

	__builtin_memset(&key, 0, sizeof(key));
	__builtin_memset(&c, 0, sizeof(c));

	c.buffer = (char *)ctx->bx;
	c.fd = get_fd_from_tls_conn((void *)ctx->ax);

	key.tgid = bpf_get_current_pid_tgid() >> 32;
	key.goid = get_current_goroutine();

	bpf_map_update_elem(&tls_conn_map, &key, &c, BPF_ANY);
	return 0;
}

SEC("uprobe/crypto/tls.(*Conn).Read")
int read_exit(struct pt_regs *ctx)
{
	struct event *e;
	struct tls_conn *c;
	struct tls_conn_key key;

	if (!ctx->ax)
		return 0;

	__builtin_memset(&key, 0, sizeof(key));
	key.tgid = bpf_get_current_pid_tgid() >> 32;
	key.goid = get_current_goroutine();

	c = bpf_map_lookup_elem(&tls_conn_map, &key);
	if (!c)
		return 0;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->type = EVENT_READ_EXIT;
	e->size = ctx->ax;
	bpf_probe_read_user(&e->buffer, BUFFER_MAX, c->buffer);
	e->fd = c->fd;
	e->goid = key.goid;
	e->tgid = key.tgid;

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("uprobe/runtime.casgstatus")
int runtime_casgstatus(struct pt_regs *ctx)
{
	s32 newval = (s32)(ctx->cx);
	if (newval != 2)
		return 0;

	void *g_ptr = (void *)(ctx->ax);
	s64 goid = 0;
	bpf_probe_read(&goid, sizeof(goid), g_ptr + OFFSET_G_GOID);
	u64 current_thread = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&goroutines_map, &current_thread, &goid, BPF_ANY);

	return 0;
}
