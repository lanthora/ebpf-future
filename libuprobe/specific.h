#ifndef LIB_UPROBE_SPECIFIC_H
#define LIB_UPROBE_SPECIFIC_H

#include <sys/types.h>

/* 函数中 ret 指令的个数 */
#define LIB_UPROBE_RET_MAX 16

typedef enum {
	ERROR_UNSPEC,
	ERROR_INVALID,
	ERROR_ELF_LIB_INIT,
	ERROR_ELF_FILE_OPEN,
	ERROR_ELF_FILE_READ,
	ERROR_ELF_FILE_TYPE,
	ERROR_ELF_GETSHDRSTRNDX,
	ERROR_GELF_GETSHDR,
	ERROR_ELF_NO_TEXT,
	ERROR_ELF_NO_SYM,
	ERROR_DECODE_FAILD,
} LIB_UPROBE_ERROR_TYPE;

struct uprobe_specific {
	/* 带有调试符号的二进制的路径 */
	char *bin;
	/* 需要匹配的符号 */
	char *sym;

	/* 函数入口地址,一般直接进行 uprobe 或者 uretprobe即可 */
	size_t entry;
	size_t size;

	/* Go 需要在 ret 的位置添加 uprobe 模拟 uretprobe */
	size_t rets[LIB_UPROBE_RET_MAX];
};

int uprobe_specific_analyze(struct uprobe_specific *spec);

#endif
