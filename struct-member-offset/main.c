#include <libdwarf/libdwarf-0/libdwarf.h>
#include <libdwarf/libdwarf-0/dwarf.h>
#include <fcntl.h>
#include <stddef.h>
#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <stdbool.h>

struct structure_member_offset {
	char *file;
	char *structure;
	char *member;
	unsigned long long int offset;
};

static int calculate(struct structure_member_offset *instance, Dwarf_Debug dbg,
		     Dwarf_Die die)
{
	Dwarf_Error err = NULL;
	Dwarf_Die child = NULL;
	Dwarf_Half tag = 0;
	Dwarf_Attribute attr = NULL;
	char *name = NULL;

	int rc = 0;

	rc = dwarf_tag(die, &tag, &err);
	assert(rc == DW_DLV_OK);

	if (tag != DW_TAG_structure_type)
		return 0;

	rc = dwarf_die_text(die, DW_AT_name, &name, &err);
	assert(rc != DW_DLV_ERROR);

	if (!name || strcmp(name, instance->structure))
		return 0;

	rc = dwarf_child(die, &child, &err);
	assert(rc != DW_DLV_ERROR);

	while (1) {
		rc = dwarf_die_text(child, DW_AT_name, &name, &err);
		assert(rc != DW_DLV_ERROR);
		if (!strcmp(name, instance->member)) {
			rc = dwarf_attr(child, DW_AT_data_member_location,
					&attr, &err);
			assert(rc != DW_DLV_ERROR);

			rc = dwarf_formudata(attr, &instance->offset, &err);
			assert(rc != DW_DLV_ERROR);
		}

		rc = dwarf_siblingof_b(dbg, child, true, &child, &err);
		assert(rc != DW_DLV_ERROR);

		if (rc == DW_DLV_NO_ENTRY)
			return 0;
	}

	return 0;
}

static int dfs(struct structure_member_offset *instance, Dwarf_Debug dbg,
	       Dwarf_Die die)
{
	Dwarf_Error err = NULL;
	Dwarf_Die child = NULL;
	int rc = 0;

	if (instance->offset != ULLONG_MAX)
		return 0;

	calculate(instance, dbg, die);

	rc = dwarf_child(die, &child, &err);
	assert(rc != DW_DLV_ERROR);
	if (rc == DW_DLV_OK)
		dfs(instance, dbg, child);

	rc = dwarf_siblingof_b(dbg, die, true, &die, &err);
	assert(rc != DW_DLV_ERROR);
	if (rc == DW_DLV_OK)
		dfs(instance, dbg, die);

	return 0;
}

static int
calculate_structure_member_offset(struct structure_member_offset *instance)
{
	Dwarf_Error err = NULL;
	Dwarf_Debug dbg = NULL;
	Dwarf_Die die = NULL;
	int fd = 0;
	int rc = 0;

	fd = open(instance->file, O_RDONLY, 0);
	assert(fd >= 0);

	rc = dwarf_init_b(fd, DW_GROUPNUMBER_ANY, NULL, NULL, &dbg, &err);
	assert(rc == DW_DLV_OK);

	while (1) {
		rc = dwarf_next_cu_header_d(dbg, true, NULL, NULL, NULL, NULL,
					    NULL, NULL, NULL, NULL, NULL, NULL,
					    &err);
		assert(rc != DW_DLV_ERROR);
		if (rc == DW_DLV_NO_ENTRY)
			break;
		rc = dwarf_siblingof_b(dbg, 0, true, &die, &err);
		assert(rc != DW_DLV_ERROR);

		dfs(instance, dbg, die);
	}

	rc = dwarf_finish(dbg);
	assert(rc == DW_DLV_OK);

	close(fd);
}

int main(int argc, char *argv[])
{
	int rc = 0;

	assert(argc >= 4);

	struct structure_member_offset instance = {
		.file = argv[1],
		.structure = argv[2],
		.member = argv[3],
		.offset = ULLONG_MAX,
	};

	rc = calculate_structure_member_offset(&instance);
	assert(rc == 0);
	assert(instance.offset != ULLONG_MAX);

	printf("file: %s\n", instance.file);
	printf("structure: %s\n", instance.structure);
	printf("member: %s\n", instance.member);
	printf("offset: %d\n", instance.offset);

	return 0;
}