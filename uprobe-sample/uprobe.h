#ifndef UPROBE_H
#define UPROBE_H

#define EVENT_READ_ENTER 1
#define EVENT_READ_EXIT 2
#define EVENT_WRITE_ENTER 3
#define EVENT_WRITE_EXIT 4

#define BUFFER_MAX 0x3FF
#define EVENT_MAX 1024

#define MAX_SYSTEM_THREADS 128

struct event {
	unsigned int type;
	unsigned int size;
	int fd;
	long long int goid;
	long long int tgid;
	char buffer[BUFFER_MAX + 1];
};

struct go_interface {
	long long type;
	void *ptr;
};

struct tls_conn {
	int fd;
	char *buffer;
};

struct tls_conn_key {
	int tgid;
	long long int goid;
};

#endif
