#include <stdio.h>
#include <string.h>

__attribute__((constructor)) void init() {
	FILE *f = fopen("/poc", "wb");
	char msg[] = "pocpoc";
	fprintf(f, "%s", msg);
	fclose(f);
}

