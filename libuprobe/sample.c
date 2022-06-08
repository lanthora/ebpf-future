#include "specific.h"
#include "string.h"
#include <assert.h>
#include <stdio.h>

int main()
{
	int error = 0;
	struct uprobe_specific spec;
	spec.bin = "/root/uranus/cmd/web/uranus-web";
	spec.sym = "crypto/tls.(*Conn).Read";

	error = uprobe_specific_analyze(&spec);
	if (error) {
		printf("error: %d\n", error);
		return error;
	}

	printf("bin:\n\t%s\n", spec.bin);
	printf("sym:\n\t%s\n", spec.sym);
	printf("entry:\n\t%p\n", spec.entry);
	printf("rets:\n", spec.rets[0]);
	for (int idx = 0; idx < LIB_UPROBE_RET_MAX && spec.rets[idx]; ++idx)
		printf("\t%p\n", spec.rets[idx]);
	return 0;
}