#include "_libctf.h"

static const char *_libctf_errors[] = {
	[CTF_E_ARGUMENT] =	"Invalid argument",
	[CTF_E_IO] =		"I/O error",
	[CTF_E_RESOURCE] =	"Resource exhaustion",
	[CTF_E_VERSION] =	"Unsupported CTF version",
};

const char *
ctf_errmsg(int error)
{

	return (_libctf_errors[error]);
}
