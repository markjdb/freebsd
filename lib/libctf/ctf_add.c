#include "_libctf.h"

#if 0
ctf_id_t
libctf_add_type(Ctf *ctf, const char *name, ctf_id_t ref __unused)
{
	struct ctf_imtype *imt;
	ctf_id_t nextid;

	imt = malloc(sizeof(*imt));
	if (imt == NULL) {
		ctf->ctf_error = CTF_E_RESOURCE;
		return (-1);
	}

	imt->t_name = strdup(name);
	if (imt->t_name == NULL) {
		free(imt);
		ctf->ctf_error = CTF_E_RESOURCE;
		return (-1);
	}

	nextid = ++ctf->ctf_nextid;
	if (nextid >= 32768) {
		free(imt->t_name);
		free(imt);
		ctf->ctf_error = CTF_E_FULL;
		return (-1);
	}
	imt->t_id = nextid;

	LIST_INSERT_HEAD(&ctf->ctf_tlist, imt, t_next);

	return (imt->t_id);
}

ctf_id_t
ctf_add_array(Ctf *ctf, unsigned int flags, ctf_id_t contents, ctf_id_t index,
    uint32_t nelems)
{
	ctf_id_t id;

	id = libctf_add_type(ctf, NULL, 
}

ctf_id_t
ctf_add_const(Ctf *ctf, unsigned int flags, ctf_id_t id)
{
}

ctf_id_t
ctf_add_enum(Ctf *ctf, unsigned int flags, const char *name)
{
}

int
ctf_add_enumerator(Ctf *ctf, ctf_id_t id, const char *name, int value)
{
}

ctf_id_t
ctf_add_float(Ctf *ctf, unsigned int flags, const char *name,
    unsigned int encoding)
{
}

ctf_id_t
ctf_add_function(Ctf *ctf, unsigned int flags /*, XXX */)
{
}

ctf_id_t
ctf_add_integer(Ctf *ctf, unsigned int flags, unsigned int encoding)
{
}

int
ctf_add_member(Ctf *ctf, ctf_id_t id, const char *name, ctf_id_t type)
{
}

ctf_id_t
ctf_add_pointer(Ctf *ctf, unsigned int flags, ctf_id_t ref)
{
}

ctf_id_t
ctf_add_restrict(Ctf *ctf, unsigned int flags, ctf_id_t ref)
{
}

ctf_id_t
ctf_add_typedef(Ctf *ctf, unsigned int flags, const char *name, ctf_id_t ref)
{
}

ctf_id_t
ctf_add_volatile(Ctf *ctf, unsigned int flags, ctf_id_t ref)
{
}
#endif
