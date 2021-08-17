#include "_libctf.h"

#include <stdio.h>

Ctf *
libctf_create(size_t strtabsz, int *errp)
{
	Ctf *ctf;

	ctf = calloc(1, sizeof(*ctf));
	if (ctf == NULL) {
		if (errp != NULL)
			*errp = CTF_E_RESOURCE;
		return (NULL);
	}

	STAILQ_INIT(&ctf->ctf_dtypes);

	ctf->ctf_strtab = elftc_string_table_create(strtabsz);
	if (ctf->ctf_strtab == NULL) {
		if (errp != NULL)
			*errp = CTF_E_RESOURCE;
		free(ctf);
		return (NULL);
	}

	return (ctf);
}

int
ctf_update(Ctf *ctf)
{
	struct ctf_array arrayval;
	struct ctf_enum enumval;
	struct ctf_header hdr;
	struct ctf_imtype *imt;
	struct ctf_imtelem *elem;
	struct ctf_lmember lmember;
	struct ctf_member member;
	struct ctf_stype st;
	struct ctf_type t;
	const char *strtab;
	char *buf, *obuf;
	size_t bufsz, strtabsz;
	int count, i;
	uint16_t param;

	strtab = elftc_string_table_image(ctf->ctf_strtab, &strtabsz);

	bufsz = sizeof(hdr) + ctf->ctf_dtype_bsz + strtabsz;
	buf = obuf = malloc(bufsz);
	if (buf == NULL) {
		ctf->ctf_error = errno;
		return (-1);
	}

	memset(&hdr, 0, sizeof(hdr));
	hdr.cth_magic = CTF_MAGIC;
	hdr.cth_version = CTF_VERSION;
	hdr.cth_flags = 0;
	hdr.cth_parlabel = 0;
	hdr.cth_parname = 0;
	hdr.cth_lbloff = 0;
	hdr.cth_objtoff = 0;
	hdr.cth_funcoff = 0;
	hdr.cth_typeoff = 0;
	hdr.cth_stroff = 0;
	hdr.cth_strlen = strtabsz;
	memcpy(buf, &hdr, sizeof(hdr));

	buf += sizeof(hdr);

	STAILQ_FOREACH(imt, &ctf->ctf_dtypes, t_next) {
		switch (imt->t_kind) {
		case CTF_K_ENUM:
			count = imt->t_enum.vals.el_count;
			if (count > CTF_MAX_VLEN)
				/* XXX */
				count = CTF_MAX_VLEN;
			memset(&st, 0, sizeof(st));
			st.cts_name = (uint32_t)imt->t_name;
			st.cts_info = (imt->t_kind << 11) |
			    (count & CTF_MAX_VLEN);
			st.cts_size = sizeof(uint32_t);
			memcpy(buf, &st, sizeof(st));
			buf += sizeof(st);
			for (i = 0; i < count; i++) {
				elem = &imt->t_enum.vals.el_list[i];
				memset(&enumval, 0, sizeof(enumval));
				enumval.cte_name = elem->e_name;
				enumval.cte_value = elem->e_val;
				memcpy(buf, &enumval, sizeof(enumval));
				buf += sizeof(enumval);
			}
			break;
		case CTF_K_FLOAT:
		case CTF_K_INTEGER:
			memset(&st, 0, sizeof(st));
			st.cts_name = (uint32_t)imt->t_name;
			st.cts_info = (imt->t_kind << 11) |
			    (sizeof(uint32_t) & CTF_MAX_VLEN);
			st.cts_size = CTF_INT_BITS(imt->t_num.enc) / NBBY;
			memcpy(buf, &st, sizeof(st));
			buf += sizeof(st);
			memcpy(buf, &imt->t_num.enc, sizeof(uint32_t));
			buf += sizeof(uint32_t);
			break;
		case CTF_K_ARRAY:
			memset(&st, 0, sizeof(st));
			st.cts_name = imt->t_name;
			st.cts_info = (imt->t_kind << 11) |
			    (sizeof(arrayval) & CTF_MAX_VLEN);
			st.cts_size = 0;
			memcpy(buf, &st, sizeof(st));
			buf += sizeof(st);
			memset(&arrayval, 0, sizeof(arrayval));
			arrayval.cta_contents = imt->t_ref.id;
			arrayval.cta_index = 0; /* XXX */
			arrayval.cta_nelems = imt->t_ref.count;
			memcpy(buf, &arrayval, sizeof(arrayval));
			buf += sizeof(arrayval);
			break;
		case CTF_K_STRUCT:
		case CTF_K_UNION:
			count = imt->t_sou.members.el_count;
			if (count > CTF_MAX_VLEN)
				/* XXX */
				count = CTF_MAX_VLEN;
			if (imt->t_sou.bsz > CTF_MAX_SIZE) {
				memset(&t, 0, sizeof(t));
				t.ctt_name = imt->t_name;
				t.ctt_info = (imt->t_kind << 11) |
				    (count & CTF_MAX_VLEN);
				t.ctt_size = CTF_LSIZE_SENT;
				t.ctt_lsizehi = imt->t_sou.bsz >> 32;
				t.ctt_lsizelo = imt->t_sou.bsz & 0xffffffffu;
				memcpy(buf, &t, sizeof(t));
				buf += sizeof(t);
			} else {
				memset(&st, 0, sizeof(st));
				st.cts_name = imt->t_name;
				st.cts_info = (imt->t_kind << 11) |
				    (count & CTF_MAX_VLEN);
				st.cts_size = imt->t_sou.bsz;
				memcpy(buf, &st, sizeof(st));
				buf += sizeof(st);
			}
			if (imt->t_sou.bsz > CTF_LSTRUCT_THRESH) {
				for (i = 0; i < count; i++) {
					elem = &imt->t_sou.members.el_list[i];
					memset(&lmember, 0, sizeof(lmember));
					lmember.ctlm_name = elem->e_name;
					lmember.ctlm_type = elem->e_type;
					lmember.ctlm_offsethi =
					    elem->e_off >> 32;
					lmember.ctlm_offsetlo =
					    elem->e_off & 0xffffffffu;
					memcpy(buf, &lmember, sizeof(lmember));
					buf += sizeof(lmember);
				}
			} else {
				for (i = 0; i < count; i++) {
					elem = &imt->t_sou.members.el_list[i];
					memset(&member, 0, sizeof(member));
					member.ctm_name = elem->e_name;
					member.ctm_type = elem->e_type;
					member.ctm_offset = elem->e_off;
					memcpy(buf, &member, sizeof(member));
					buf += sizeof(member);
				}
			}
			break;
		case CTF_K_FUNCTION:
			count = imt->t_func.params.el_count;
			if (imt->t_func.variadic)
				count++;
			if (count > CTF_MAX_VLEN)
				/* XXX */
				count = CTF_MAX_VLEN;
			memset(&st, 0, sizeof(st));
			st.cts_name = 0;
			st.cts_info = (imt->t_kind << 11) |
			    (count & CTF_MAX_VLEN);
			st.cts_type = imt->t_func.params.el_list[0].e_type;
			memcpy(buf, &st, sizeof(st));
			buf += sizeof(st);
			for (i = 0; i < count; i++) {
				elem = &imt->t_func.params.el_list[i];
				memset(&param, 0, sizeof(param));
				if (imt->t_func.variadic && i == count - 1)
					param = 0;
				else
					param = elem->e_type;
				memcpy(buf, &param, sizeof(param));
				buf += sizeof(param);
			}
			if (count % 2 != 0) {
				memset(&param, 0, sizeof(param));
				memcpy(buf, &param, sizeof(param));
				buf += sizeof(param);
			}
			break;
		case CTF_K_CONST:
		case CTF_K_POINTER:
		case CTF_K_RESTRICT:
		case CTF_K_TYPEDEF:
		case CTF_K_VOLATILE:
			memset(&st, 0, sizeof(st));
			st.cts_name = imt->t_name;
			st.cts_info = (imt->t_kind << 11);
			st.cts_type = imt->t_ref.id;
			memcpy(buf, &st, sizeof(st));
			buf += sizeof(st);
			break;
		default:
			errx(1, "ctf_update: unimplemented kind %d",
			    imt->t_kind);
		}
	}

	memcpy(buf, strtab, strtabsz);
	ctf->ctf_buf = obuf;
	hdr.cth_stroff = buf - obuf - sizeof(hdr);
	memcpy(obuf, &hdr, sizeof(hdr));
	ctf->ctf_bufsz = buf - obuf + strtabsz;

	return (0);
}

int
ctf_write(Ctf *ctf, int fd)
{
	char *buf;
	size_t resid;
	ssize_t n;

	buf = ctf->ctf_buf;
	resid = ctf->ctf_bufsz;

	while (resid > 0 && (n = write(fd, buf, resid)) >= 0) {
		buf += n;
		resid -= n;
	}
	if (n < 0) {
		ctf->ctf_error = errno;
		return (-1);
	}
	return (0);
}
