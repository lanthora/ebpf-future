#include "specific.h"
#include "string.h"
#include <argp.h>
#include <assert.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
	int error = 0;
	struct uprobe_specific spec;

	if (argc < 3)
		return ERROR_INVALID;

	spec.bin = argv[1];
	spec.sym = argv[2];

	error = uprobe_specific_analyze(&spec);
	if (error)
		return error;

	printf("bin: %s\n", spec.bin);
	printf("sym: %s\n", spec.sym);
	printf("entry: %p\n", spec.entry);
	printf("rets: %p", spec.rets[0]);
	for (int idx = 1; idx < LIB_UPROBE_RET_MAX && spec.rets[idx]; ++idx)
		printf(", %p", spec.rets[idx]);
	printf("\n");
	return 0;
}