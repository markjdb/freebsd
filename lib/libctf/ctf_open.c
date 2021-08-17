#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include "_libctf.h"

Ctf *
ctf_open(const char *path, int *errp)
{
	int fd;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		if (errp != NULL)
			*errp = CTF_E_IO;
		return (NULL);
	}

	return (ctf_fdopen(fd, errp));
}

/* Ctf *ctf_elfopen(int fd) */

Ctf *
ctf_fdopen(int fd, int *errp)
{
	struct ctf_header hdr;
	Ctf *ctf;
	ssize_t n;

	if ((n = read(fd, &hdr, sizeof(hdr))) != sizeof(hdr)) {
		LIBCTF_SET_ERROR(errp, n < 0 ? CTF_E_IO : CTF_E_ARGUMENT); 
		return (NULL);
	}

	if (hdr.cth_magic != CTF_MAGIC) {
		LIBCTF_SET_ERROR(errp, CTF_E_ARGUMENT);
		return (NULL);
	}
	if (hdr.cth_version != CTF_VERSION) {
		LIBCTF_SET_ERROR(errp, CTF_E_VERSION);
		return (NULL);
	}
	if ((hdr.cth_flags & ~CTF_F_COMPRESS) != 0) {
		LIBCTF_SET_ERROR(errp, CTF_E_ARGUMENT);
		return (NULL);
	}

	ctf = calloc(1, sizeof(*ctf));
	if (ctf == NULL) {
		LIBCTF_SET_ERROR(errp, CTF_E_RESOURCE);
		return (NULL);
	}

	return (ctf);
}
