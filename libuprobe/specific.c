#include "specific.h"
#include "internal.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int analyze_section(struct uprobe_specific_internal *i)
{
	i->section = NULL;
	while ((i->section = elf_nextscn(i->elf, i->section))) {
		if (gelf_getshdr(i->section, &i->shdr) != &i->shdr) {
			return ERROR_GELF_GETSHDR;
		}
		if (i->shdr.sh_type == SHT_SYMTAB)
			return 0;
	}
	return ERROR_ELF_NO_TEXT;
}

static int analyze_sym(struct uprobe_specific_internal *i)
{
	int count, idx;
	char *name;

	i->data = elf_getdata(i->section, NULL);
	count = i->shdr.sh_size / i->shdr.sh_entsize;

	for (idx = 0; idx < count; ++idx) {
		gelf_getsym(i->data, idx, &i->sym);
		name = elf_strptr(i->elf, i->shdr.sh_link, i->sym.st_name);
		if (strcmp(name, i->spec->sym))
			continue;
		return 0;
	}
	return ERROR_ELF_NO_SYM;
}

static int fill_spec(struct uprobe_specific_internal *i)
{
	i->spec->entry = i->sym.st_value;
	i->spec->size = i->sym.st_size;
	i->data = elf_getdata_rawchunk(i->elf, i->spec->entry, i->spec->size,
				       ELF_T_BYTE);
	int retcnt = 0;
	uint8_t *raw = i->data->d_buf;

	return 0;
}

static int analyze_internal(struct uprobe_specific_internal *internal)
{
	int error = 0;
	error = analyze_section(internal);
	if (error)
		goto out;

	error = analyze_sym(internal);
	if (error)
		goto out;

	error = fill_spec(internal);
	if (error)
		goto out;

out:
	return error;
}

int uprobe_specific_analyze(struct uprobe_specific *spec)
{
	int error;
	struct uprobe_specific_internal internal;

	spec->entry = 0;
	memset(spec->rets, 0, sizeof(spec->rets));

	internal.spec = spec;

	if (elf_version(EV_CURRENT) == EV_NONE) {
		error = ERROR_ELF_LIB_INIT;
		goto out;
	}

	if ((internal.fd = open(internal.spec->bin, O_RDONLY, 0)) < 0) {
		error = ERROR_ELF_FILE_OPEN;
		goto out;
	}

	if (!(internal.elf = elf_begin(internal.fd, ELF_C_READ, NULL))) {
		error = ERROR_ELF_FILE_READ;
		goto out_file;
	}

	if (elf_kind(internal.elf) != ELF_K_ELF) {
		error = ERROR_ELF_FILE_TYPE;
		goto out_elf;
	}

	error = analyze_internal(&internal);

out_elf:
	elf_end(internal.elf);
out_file:
	close(internal.fd);
out:
	return error;
}
