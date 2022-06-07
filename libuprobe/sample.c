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

	assert(!uprobe_specific_analyze(&spec));
	printf("bin: %s\n", spec.bin);
	printf("sym: %s\n", spec.sym);
	printf("size: %p\n", spec.size);
	printf("entry: %p\n", spec.entry);
	return 0;
}