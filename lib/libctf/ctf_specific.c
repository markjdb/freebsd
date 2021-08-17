#include "_libctf.h"

void *
ctf_getspecific(Ctf *ctf)
{

	return (ctf->ctf_specific);
}

void
ctf_setspecific(Ctf *ctf, void *value)
{

	ctf->ctf_specific = value;
}
