#include "uprobe.h"
#include "uprobe.skel.h"
#include <argp.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>
#include <time.h>
#include <assert.h>

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
	printf("===================================================== size=%d type=%d fd=%d tgid=%lld goid=%lld\n",
	       e->size, e->type, e->fd, e->tgid, e->goid);
	for (int idx = 0; idx < e->size && idx < BUFFER_MAX; ++idx)
		putchar(e->buffer[idx]);

	printf("\n=====================================================\n");
	return 0;
}

int main(int argc, char *argv[])
{
	struct ring_buffer *rb = NULL;
	struct uprobe_bpf *skel;
	struct bpf_link *link;
	int idx = 4;
	int error;

	assert(argc >= 6);
	const char *binary_path = argv[1];
	const size_t runtime_casgstatus_offset = strtol(argv[2], NULL, 16);
	const size_t write_enter_offset = strtol(argv[3], NULL, 16);
	const size_t read_enter_offset = strtol(argv[4], NULL, 16);

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	libbpf_set_print(print_fn);

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = uprobe_bpf__open_and_load();
	assert(skel);

	link = bpf_program__attach_uprobe(skel->progs.runtime_casgstatus, false,
					  -1, binary_path,
					  runtime_casgstatus_offset);
	assert(link);

	link = bpf_program__attach_uprobe(skel->progs.write_enter, false, -1,
					  binary_path, write_enter_offset);
	assert(link);

	link = bpf_program__attach_uprobe(skel->progs.read_enter, false, -1,
					  binary_path, read_enter_offset);
	assert(link);

	for (idx = 5; idx < argc; ++idx) {
		const size_t read_exit_offset = strtol(argv[idx], NULL, 16);
		link = bpf_program__attach_uprobe(skel->progs.read_exit, false,
						  -1, binary_path,
						  read_exit_offset);
		assert(link);
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL,
			      NULL);
	assert(rb);

	while (!exiting) {
		error = ring_buffer__poll(rb, 100);
		if (error == -EINTR) {
			error = 0;
			break;
		}
		assert(error >= 0);
	}

	ring_buffer__free(rb);
	uprobe_bpf__destroy(skel);

	return error < 0 ? -error : 0;
}