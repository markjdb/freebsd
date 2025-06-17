/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025 Mark Johnston <markj@FreeBSD.org>
 */

#include <sys/types.h>
#include <sys/mman.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
main(int argc, char **argv)
{
	int vec[2048];

	for (int i = 1; i < 2048; i++) {
		uint32_t *addr;
		size_t size;
		int error;

		size = 4096 * i;
		addr = mmap(NULL, size, PROT_READ | PROT_WRITE,
		    MAP_ANON | MAP_PRIVATE, -1, 0);
		if (addr == MAP_FAILED)
			err(1, "mmap(%zu)", size);

		memset(vec, 0, sizeof(vec));
		for (int j = 0; j < i; j++) {
			addr[j * 4096 / sizeof(int)] = i - j;
			vec[j] = i - j - 1;
		}

		error = mswizzle(addr, size, vec);
		if (error != 0)
			err(1, "mswizzle(%zu)", size);

		for (int j = 0; j < i; j++) {
			if (addr[j * 4096 / sizeof(int)] != j + 1)
				errx(1, "mswizzle(%zu) failed: "
				    "addr[%d] = %d, expected %d",
				    size, j, addr[j * 4096 / sizeof(int)], j + 1);
		}

		if (munmap(addr, size) == -1)
			err(1, "munmap(%zu)", size);
		printf("swizzled %d pages\n", i);
	}
}
