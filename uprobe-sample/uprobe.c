#include "uprobe.h"
#include "uprobe.skel.h"
#include <argp.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>
#include <time.h>

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static int print_fn(enum libbpf_print_level level, const char *format,
		    va_list args)
{
	return vfprintf(stdout, format, args);
}

static int handle_event(void *ctx, void *data, size_t size)
{
	const struct event *e = data;
	printf("===================================================== size=%d, type=%d\n",
	       e->size, e->type);
	for (int idx = 0; idx < e->size && idx < BUFFER_MAX; ++idx)
		putchar(e->buffer[idx]);

	printf("\n=====================================================\n");
	return 0;
}

int main()
{
	struct ring_buffer *rb = NULL;
	struct uprobe_bpf *skel;
	int error;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	libbpf_set_print(print_fn);

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = uprobe_bpf__open_and_load();
	if (!skel) {
		error = -1;
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		goto cleanup;
	}

	skel->links.crypto_tls_write_enter = bpf_program__attach_uprobe(
		skel->progs.crypto_tls_write_enter, false, -1,
		"/root/uranus/cmd/web/uranus-web", 0x1ffe40);
	if (!skel->links.crypto_tls_write_enter) {
		error = -errno;
		fprintf(stderr, "Failed to attach crypto_tls_write_enter: %d\n",
			error);
		goto cleanup;
	}

	skel->links.crypto_tls_read_enter = bpf_program__attach_uprobe(
		skel->progs.crypto_tls_read_enter, false, -1,
		"/root/uranus/cmd/web/uranus-web", 0x201240);
	if (!skel->links.crypto_tls_read_enter) {
		error = -errno;
		fprintf(stderr, "Failed to attach crypto_tls_read_enter: %d\n",
			error);
		goto cleanup;
	}

	skel->links.crypto_tls_read_exit = bpf_program__attach_uprobe(
		skel->progs.crypto_tls_read_exit, false, -1,
		"/root/uranus/cmd/web/uranus-web", 0x20156c);
	if (!skel->links.crypto_tls_read_exit) {
		error = -errno;
		fprintf(stderr, "Failed to attach crypto_tls_read_exit: %d\n",
			error);
		goto cleanup;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL,
			      NULL);
	if (!rb) {
		error = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	while (!exiting) {
		error = ring_buffer__poll(rb, 100);
		if (error == -EINTR) {
			error = 0;
			break;
		}
		if (error < 0) {
			printf("Error polling perf buffer: %d\n", error);
			break;
		}
	}

cleanup:
	ring_buffer__free(rb);
	uprobe_bpf__destroy(skel);

	return error < 0 ? -error : 0;
}