#include <libdwarf/libdwarf-0/libdwarf.h>
#include <libdwarf/libdwarf-0/dwarf.h>
#include <fcntl.h>
#include <stddef.h>
#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>

int main(int argc, char *argv[])
{
	Dwarf_Error err = NULL;
	Dwarf_Debug dbg = NULL;
	Dwarf_Die die = NULL;
	Dwarf_Half tag = 0;

	int fd = 0;
	int rc = 0;

	assert(argc >= 2);

	fd = open(argv[1], O_RDONLY, 0);
	assert(fd >= 0);

	rc = dwarf_init_b(fd, DW_GROUPNUMBER_ANY, NULL, NULL, &dbg, &err);
	assert(rc == DW_DLV_OK);

	rc = dwarf_next_cu_header_d(dbg, true, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &err);
	assert(rc == DW_DLV_OK);

	while (rc = dwarf_siblingof_b(dbg, die, true, &die, &err))
	{
		printf("1\n");
		rc = dwarf_tag(die, &tag, &err);
		assert(rc == DW_DLV_OK);
		if (tag != DW_TAG_structure_type)
			continue;

		printf("%d\n", tag);
	}

	rc = dwarf_finish(dbg);
	assert(rc == DW_DLV_OK);

	close(fd);
}