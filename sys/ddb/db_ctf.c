/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2022  <bnovkov@freebsd.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/ctype.h>
#include <sys/linker.h>
#include <sys/malloc.h>
#include <sys/mutex.h>

#include <contrib/zlib/zlib.h>

#include <ddb/ddb.h>
#include <ddb/db_ctf.h>

struct db_ctf {
	linker_ctf_t lc;
	char *modname;
	LIST_ENTRY(db_ctf) link;
};

static LIST_HEAD(, db_ctf) ctf_table = SLIST_HEAD_INITIALIZER(ctf_table);
static struct mtx db_ctf_mtx;
MTX_SYSINIT(db_ctf, &db_ctf_mtx, "ddb module CTF data registry", MTX_DEF);

static MALLOC_DEFINE(M_DBCTF, "ddb ctf", "ddb module ctf data");

/* Used to register kernel CTF data before SUB_KLD. */
static struct db_ctf kctf;

static struct db_ctf *
db_ctf_lookup(const char *modname)
{
	struct db_ctf *dcp;

	LIST_FOREACH (dcp, &ctf_table, link) {
		if (dcp->modname != NULL && strcmp(modname, dcp->modname) == 0)
			break;
	}

	return (dcp);
}

int
db_ctf_register(linker_file_t mod)
{
	struct db_ctf *dcp;
	char *modname = mod->filename;

	mtx_lock(&db_ctf_mtx);
	if (db_ctf_lookup(modname) != NULL) {
		mtx_unlock(&db_ctf_mtx);
		printf("%s: ddb CTF data for module %s already loaded!\n",
		    __func__, modname);

		return (EINVAL);
	}
	mtx_unlock(&db_ctf_mtx);

	dcp = malloc(sizeof(struct db_ctf), M_DBCTF, M_WAITOK);
	if (linker_ctf_get(mod, &dcp->lc) != 0) {
		free(dcp, M_DBCTF);
		return (EINVAL);
	}
	dcp->modname = strdup(modname, M_DBCTF);

	mtx_lock(&db_ctf_mtx);
	LIST_INSERT_HEAD(&ctf_table, dcp, link);
	mtx_unlock(&db_ctf_mtx);

	return (0);
}

int
db_ctf_unregister(linker_file_t mod)
{
	struct db_ctf *dcp;
	char *modname = mod->filename;

	mtx_lock(&db_ctf_mtx);
	dcp = db_ctf_lookup(modname);
	if (dcp == NULL) {
		mtx_unlock(&db_ctf_mtx);
		printf("%s: ddb CTF data for module %s already loaded!\n",
		    __func__, modname);

		return (EINVAL);
	}
	mtx_unlock(&db_ctf_mtx);

	mtx_lock(&db_ctf_mtx);
	LIST_REMOVE(dcp, link);
	mtx_unlock(&db_ctf_mtx);

	free(dcp->modname, M_TEMP);
	free(dcp, M_DBCTF);

	return (0);
}

static const ctf_header_t *
db_ctf_fetch_cth(linker_ctf_t *lc)
{
	return (const ctf_header_t *)lc->ctftab;
}

static uint32_t
sym_to_objtoff(linker_ctf_t *lc, const Elf_Sym *sym, const Elf_Sym *symtab,
    const Elf_Sym *symtab_end)
{
	const ctf_header_t *hp = db_ctf_fetch_cth(lc);
	uint32_t objtoff = hp->cth_objtoff;
	const size_t idwidth = 4;

	/* Ignore non-object symbols */
	if (ELF_ST_TYPE(sym->st_info) != STT_OBJECT) {
		return DB_CTF_OBJTOFF_INVALID;
	}

	/* Sanity check */
	if (!(sym >= symtab && sym <= symtab_end)) {
		return DB_CTF_OBJTOFF_INVALID;
	}

	for (const Elf_Sym *symp = symtab; symp < symtab_end; symp++) {
		/* Make sure we do not go beyond the objtoff section */
		if (objtoff >= hp->cth_funcoff) {
			objtoff = DB_CTF_OBJTOFF_INVALID;
			break;
		}

		if (symp->st_name == 0 || symp->st_shndx == SHN_UNDEF) {
			continue;
		}

		if ((symp->st_shndx == SHN_ABS && symp->st_value == 0)) {
			continue;
		}

		/* Skip non-object symbols */
		if (ELF_ST_TYPE(symp->st_info) != STT_OBJECT) {
			continue;
		}

		if (symp == sym) {
			break;
		}

		objtoff += idwidth;
	}

	return objtoff;
}

struct ctf_type_v3 *
db_ctf_typeid_to_type(db_ctf_sym_data_t sd, uint32_t typeid)
{
	const ctf_header_t *hp = db_ctf_fetch_cth(sd->lc);
	const uint8_t *ctfstart = (const uint8_t *)hp + sizeof(ctf_header_t);

	uint32_t typeoff = hp->cth_typeoff;
	uint32_t stroff = hp->cth_stroff;
	/* CTF typeids start at 0x1 */
	size_t cur_typeid = 1;

	/* Find corresponding type */
	while (typeoff < stroff) {
		u_int vlen, kind, size;
		size_t skiplen, type_struct_size;
		struct ctf_type_v3 *t =
		    (struct ctf_type_v3 *)(__DECONST(uint8_t *, ctfstart) +
			typeoff);

		vlen = CTF_V3_INFO_VLEN(t->ctt_info);
		kind = CTF_V3_INFO_KIND(t->ctt_info);
		size = ((t->ctt_size == CTF_V3_LSIZE_SENT) ? CTF_TYPE_LSIZE(t) :
							     t->ctt_size);
		type_struct_size = ((t->ctt_size == CTF_V3_LSIZE_SENT) ?
			sizeof(struct ctf_type_v3) :
			sizeof(struct ctf_stype_v3));

		switch (kind) {
		case CTF_K_INTEGER:
		case CTF_K_FLOAT:
			skiplen = sizeof(uint32_t);
			break;
		case CTF_K_ARRAY:
			skiplen = sizeof(struct ctf_array_v3);
			break;
		case CTF_K_UNION:
		case CTF_K_STRUCT:
			skiplen = vlen *
			    ((size < CTF_V3_LSTRUCT_THRESH) ?
				    sizeof(struct ctf_member_v3) :
				    sizeof(struct ctf_lmember_v3));
			break;
		case CTF_K_ENUM:
			skiplen = vlen * sizeof(struct ctf_enum);
			break;
		case CTF_K_FUNCTION:
			skiplen = vlen * sizeof(uint32_t);
			break;
		case CTF_K_UNKNOWN:
		case CTF_K_FORWARD:
		case CTF_K_POINTER:
		case CTF_K_TYPEDEF:
		case CTF_K_VOLATILE:
		case CTF_K_CONST:
		case CTF_K_RESTRICT:
			skiplen = 0;
			break;
		default:
			db_printf("Error: invalid CTF type kind encountered\n");
			return (NULL);
		}

		/* We found the type struct */
		if (cur_typeid == typeid) {
			break;
		}

		cur_typeid++;
		typeoff += type_struct_size + skiplen;
	}

	if (typeoff < stroff) {
		return (struct ctf_type_v3 *)(__DECONST(uint8_t *, ctfstart) +
		    typeoff);
	} else { /* A type struct was not found */
		return (NULL);
	}
}

const char *
db_ctf_stroff_to_str(db_ctf_sym_data_t sd, uint32_t off)
{
	const ctf_header_t *hp = db_ctf_fetch_cth(sd->lc);
	uint32_t stroff = hp->cth_stroff + off;

	if (stroff >= (hp->cth_stroff + hp->cth_strlen)) {
		return "invalid";
	}

	const char *ret = ((const char *)hp + sizeof(ctf_header_t)) + stroff;
	if (*ret == '\0') {
		return NULL;
	}

	return ret;
}

struct ctf_type_v3 *
db_ctf_sym_to_type(db_ctf_sym_data_t sd)
{
	uint32_t objtoff, typeid;
	const Elf_Sym *symtab, *symtab_end;

	if (sd->sym == NULL) {
		return (NULL);
	}

	symtab = sd->lc->symtab;
	symtab_end = symtab + sd->lc->nsym;

	objtoff = sym_to_objtoff(sd->lc, sd->sym, symtab, symtab_end);
	/* Sanity check - should not happen */
	if (objtoff == DB_CTF_OBJTOFF_INVALID) {
		db_printf("Could not find CTF object offset.");
		return (NULL);
	}

	typeid = *(
	    const uint32_t *)(sd->lc->ctftab + sizeof(ctf_header_t) + objtoff);

	return db_ctf_typeid_to_type(sd, typeid);
}

int
db_ctf_find_symbol(db_expr_t addr, db_ctf_sym_data_t sd)
{
	db_expr_t off;
	struct db_ctf *dcp;

	sd->sym = __DECONST(Elf_Sym *,
	    db_search_symbol(addr, DB_STGY_ANY, &off));
	if (sd->sym == NULL) {
		return (ENOENT);
	}

	dcp = db_ctf_lookup(linker_kernel_file->filename);
	if (dcp == NULL) {
		return (ENOENT);
	}

	sd->lc = &dcp->lc;

	return (0);
}

void
db_ctf_init_kctf(vm_offset_t ksymtab, vm_offset_t kstrtab,
    vm_offset_t ksymtab_size)
{
	const ctf_header_t *hp;
	uint8_t *ctf_start;
	size_t size;
	void *mod;

	mod = preload_search_by_type("ddb_kctf");
	if (mod == NULL) {
		return;
	}

	ctf_start = preload_fetch_addr(mod);
	size = preload_fetch_size(mod);
	bzero(&kctf.lc, sizeof(kctf.lc));
	hp = (const ctf_header_t *)ctf_start;

	/* Sanity check. */
	if (hp->cth_magic != CTF_MAGIC) {
		printf("%s: bad kernel CTF magic value\n", __func__);
		return;
	}

	if (hp->cth_version != CTF_VERSION_3) {
		printf("%s: CTF V2 data encountered\n", __func__);
		return;
	}

	/* We only deal with uncompressed data */
	if (hp->cth_flags & CTF_F_COMPRESS) {
		printf("%s: kernel CTF data is compressed\n", __func__);
		return;
	}

	kctf.lc.ctftab = ctf_start;
	kctf.lc.ctfcnt = size;
	kctf.lc.symtab = (const Elf_Sym *)ksymtab;
	kctf.lc.nsym = ksymtab_size / sizeof(Elf_Sym);
	kctf.lc.strtab = (const char *)kstrtab;
	kctf.modname = "kernel";

	LIST_INSERT_HEAD(&ctf_table, &kctf, link);
}

linker_ctf_t *
db_ctf_fetch_kctf(void)
{
	return (kctf.modname != NULL ? &kctf.lc : NULL);
}
