#ifndef UPROBE_H
#define UPROBE_H

#define EVENT_READ_ENTER 1
#define EVENT_READ_EXIT 2
#define EVENT_WRITE_ENTER 3
#define EVENT_WRITE_EXIT 4

#define BUFFER_MAX 0x3FF
#define EVENT_MAX 1024

struct event {
	unsigned int type;
	unsigned int size;
	char buffer[BUFFER_MAX + 1];
};

#endif
