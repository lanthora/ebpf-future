#ifndef UPROBE_H
#define UPROBE_H

#define EVENT_READ 1
#define EVENT_WRITE 2
#define BUFFER_MAX 0x3FF
#define EVENT_MAX 1024

struct crypto_event {
	unsigned int type;
	unsigned int size;
	char buffer[BUFFER_MAX + 1];
};

#endif
