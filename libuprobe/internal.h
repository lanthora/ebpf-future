#ifndef LIB_UPROBE_INTERNAL_H
#define LIB_UPROBE_INTERNAL_H

#include <gelf.h>
#include <libelf.h>

struct uprobe_specific_internal {
	struct uprobe_specific *spec;
	int fd;
	Elf *elf;
	Elf_Scn *section;
	GElf_Sym sym;
	GElf_Shdr shdr;
	Elf_Data *data;
};

#endif
