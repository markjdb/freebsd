/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2019-2020 Mark Johnston <markj@FreeBSD.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the distribution.
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
__FBSDID("$FreeBSD$");

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <atf-c.h>
#include <dwarf.h>
#include <gelf.h>
#include <libctf.h>
#include <libdwarf.h>
#include <libelf.h>
#include <libelftc.h>

struct strtab {
	char *tab;
	size_t asz;	/* Allocated size. */
	size_t sz;	/* Bytes used. */
};

struct inputf {
	Dwarf_P_Debug	dbg;
	Elf		*elf;
	Elf_Scn		*symtabscn;
	struct strtab	strtab;
	int		fd;
};

#define	LIBDWARF_REQUIRE(cond)	ATF_REQUIRE_MSG(cond, "%s", dwarf_errmsg(derr))
#define	LIBELF_REQUIRE(cond)	ATF_REQUIRE_MSG(cond, "%s", elf_errmsg(-1))

static void
strtab_init(struct strtab *strtab)
{
	char *tab;

	tab = malloc(1024);
	ATF_REQUIRE(tab != NULL);
	tab[0] = '\0';

	strtab->tab = tab;
	strtab->asz = 1024;
	strtab->sz = 1; /* nul entry */
}

static size_t
strtab_insert(struct strtab *strtab, const char *str)
{
	char *ntab;
	size_t sz;

	sz = strlen(str) + 1;
	while (sz + strtab->sz > strtab->asz) {
		strtab->asz *= 2;
		ntab = realloc(strtab->tab, strtab->asz);
		ATF_REQUIRE(ntab != NULL);
		strtab->tab = ntab;
	}
	(void)strlcpy(strtab->tab + strtab->sz, str, strtab->asz);
	strtab->sz += sz;
	return (strtab->sz - sz);
}

static char *
strtab_image(struct strtab *strtab, size_t *szp)
{
	*szp = strtab->sz;
	return (strtab->tab);
}

static void
strtab_destroy(struct strtab *strtab)
{
	free(strtab->tab);
}

static int
dwarf_producer_cb(char *name, int size, Dwarf_Unsigned type,
    Dwarf_Unsigned flags, Dwarf_Unsigned link, Dwarf_Unsigned info,
    Dwarf_Unsigned *index, void *arg, int *error __unused)
{
	Elf_Scn *scn;
	GElf_Shdr shdr;
	struct inputf *fp;

	fp = arg;

	scn = elf_newscn(fp->elf);
	LIBELF_REQUIRE(scn != NULL);
	LIBELF_REQUIRE(gelf_getshdr(scn, &shdr) != NULL);
	shdr.sh_name = strtab_insert(&fp->strtab, name);
	LIBELF_REQUIRE(shdr.sh_name != 0);
	shdr.sh_size = size;
	shdr.sh_type = type;
	shdr.sh_flags = flags;
	shdr.sh_link = link;
	shdr.sh_info = info;
	LIBELF_REQUIRE(gelf_update_shdr(scn, &shdr) != 0);

	*index = elf_ndxscn(fp->symtabscn);
	return ((int)elf_ndxscn(scn));
}

static void
input_file_init(struct inputf *fp)
{
	Dwarf_Error derr;
	Dwarf_P_Debug dbg;
	Elf *elf;
	Elf64_Ehdr *ehdr;
	Elf_Scn *symtabscn;
	GElf_Shdr shdr;
	char filename[16];
	int error, fd;

	(void)snprintf(filename, sizeof(filename), "input.XXXXXX");
	fd = mkstemp(filename);
	ATF_REQUIRE_MSG(fd != -1, "mkstemp: %s", strerror(errno)); 
	ATF_REQUIRE_MSG(unlink(filename) == 0, "unlink: %s", strerror(errno));

	strtab_init(&fp->strtab);

	LIBELF_REQUIRE(elf_version(EV_CURRENT) != EV_NONE);

	elf = elf_begin(fd, ELF_C_WRITE, NULL);
	LIBELF_REQUIRE(elf != NULL);
	ehdr = elf64_newehdr(elf);
	LIBELF_REQUIRE(ehdr != NULL);
	ehdr->e_ident[EI_DATA] = ELFDATA2LSB;
	ehdr->e_type = ET_REL;

	symtabscn = elf_newscn(elf);
	LIBELF_REQUIRE(symtabscn != NULL);
	LIBELF_REQUIRE(gelf_getshdr(symtabscn, &shdr) != NULL);
	shdr.sh_name = strtab_insert(&fp->strtab, ".symtab");
	ATF_REQUIRE(shdr.sh_name != 0);
	shdr.sh_type = SHT_SYMTAB;
	shdr.sh_flags = 0;
	shdr.sh_addralign = 8;
	shdr.sh_entsize = sizeof(Elf64_Sym);
	LIBELF_REQUIRE(gelf_update_shdr(symtabscn, &shdr) != 0);

	error = dwarf_producer_init(DW_DLC_WRITE | DW_DLC_SIZE_64,
	    dwarf_producer_cb, NULL, NULL, fp, NULL, NULL, NULL, &dbg, &derr);
	LIBDWARF_REQUIRE(error == DW_DLV_OK);

	fp->dbg = dbg;
	fp->elf = elf;
	fp->fd = fd;
	fp->symtabscn = symtabscn;
}

static int
input_file_finalize(struct inputf *fp)
{
	Dwarf_Error derr;
	Dwarf_P_Debug dbg;
	Dwarf_Ptr bytes;
	Dwarf_Signed count, i, ndx;
	Dwarf_Unsigned len;
	Elf *elf;
	Elf_Data *data, *strtabdata;
	Elf_Scn *scn, *shstrtabscn;
	GElf_Shdr shdr;
	size_t shstrtaboff;

	dbg = fp->dbg;
	elf = fp->elf;

	count = dwarf_transform_to_disk_form(dbg, &derr);
	LIBDWARF_REQUIRE(count != DW_DLV_NOCOUNT);

	/*
	 * The DWARF sections are finalized, so now we can add the section name
	 * string table.
	 */
	shstrtaboff = strtab_insert(&fp->strtab, ".shstrtab");
	shstrtabscn = elf_newscn(elf);
	LIBELF_REQUIRE(shstrtabscn != NULL);
	strtabdata = elf_newdata(shstrtabscn);
	LIBELF_REQUIRE(strtabdata != NULL);
	strtabdata->d_buf = strtab_image(&fp->strtab, &strtabdata->d_size);
	LIBELF_REQUIRE(gelf_getshdr(shstrtabscn, &shdr) != NULL);
	shdr.sh_name = shstrtaboff;
	shdr.sh_type = SHT_STRTAB;
	shdr.sh_flags = SHF_ALLOC | SHF_STRINGS;
	shdr.sh_entsize = 0;
	LIBELF_REQUIRE(gelf_update_shdr(shstrtabscn, &shdr) != 0);
	LIBELF_REQUIRE(elf_setshstrndx(elf, elf_ndxscn(shstrtabscn)) != 0);

	for (i = 0; i < count; i++) {
		bytes = dwarf_get_section_bytes(dbg, i, &ndx, &len, &derr);
		LIBDWARF_REQUIRE(bytes != NULL);
		scn = elf_getscn(elf, ndx);
		LIBELF_REQUIRE(scn != NULL);
		data = elf_newdata(scn);
		LIBELF_REQUIRE(data != NULL);
		data->d_buf = bytes;
		data->d_size = len;

		LIBELF_REQUIRE(gelf_getshdr(scn, &shdr) != NULL);
		shdr.sh_size = len;
		LIBELF_REQUIRE(gelf_update_shdr(scn, &shdr) != 0);
	}

	LIBELF_REQUIRE(elf_update(elf, ELF_C_WRITE) != -1);
	(void)elf_end(elf);
	(void)dwarf_producer_finish(dbg, &derr);
	strtab_destroy(&fp->strtab);

	(void)lseek(fp->fd, SEEK_SET, 0);
	return (fp->fd);
}

static void
add_die(struct inputf *fp, Dwarf_P_Die die)
{
	Dwarf_Error derr;

	LIBDWARF_REQUIRE(dwarf_add_die_to_debug(fp->dbg, die, &derr) !=
	    (Dwarf_Unsigned)DW_DLV_NOCOUNT);
}

static Dwarf_P_Die
new_die(struct inputf *fp, Dwarf_Tag tag)
{
	Dwarf_Error derr;
	Dwarf_P_Die die;

	die = dwarf_new_die(fp->dbg, tag, NULL, NULL, NULL, NULL, &derr);
	LIBDWARF_REQUIRE(die != DW_DLV_BADADDR);
	return (die);
}

static Dwarf_P_Die __unused
new_child_die(struct inputf *fp, Dwarf_Tag tag, Dwarf_P_Die parent)
{
	Dwarf_Error derr;
	Dwarf_P_Die die;

	die = dwarf_new_die(fp->dbg, tag, parent, NULL, NULL, NULL, &derr);
	LIBDWARF_REQUIRE(die != DW_DLV_BADADDR);
	return (die);
}

ATF_TC(empty_cu);
ATF_TC_HEAD(empty_cu, tc)
{
	atf_tc_set_md_var(tc, "descr", "Make sure we handle an empty CU DIE");
}
ATF_TC_BODY(empty_cu, tc)
{
	Ctf *ctf;
	Dwarf_P_Die cu;
	struct inputf f;
	int fd;

	input_file_init(&f);
	cu = new_die(&f, DW_TAG_compile_unit);
	add_die(&f, cu);
	fd = input_file_finalize(&f);

	ctf = ctf_convert_dwarf(fd, NULL);
	ATF_REQUIRE(ctf != NULL);
	/* XXXMJ assert no types are present */
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, empty_cu);

	return (atf_no_error());
}
