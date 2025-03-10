#include <err.h>
#include <stdio.h>

int
main(int argc, char **argv)
{
	int error;

	error = rename(argv[1], argv[2]);
	if (error != 0)
		err(1, "rename");
	return (0);
}
