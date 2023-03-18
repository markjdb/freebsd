/*
 * CDDL HEADER START
 *
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 *
 * CDDL HEADER END
 */

/*
 * Copyright (c) 2012, 2016 by Delphix. All rights reserved.
 */

/*
 * Syntactic sugar features are implemented by transforming the D parse tree
 * such that it only uses the subset of D that is supported by the rest of the
 * compiler / the kernel.  A clause containing these language features is
 * referred to as a "super-clause", and its transformation typically entails
 * creating several "sub-clauses" to implement it. For diagnosability, the
 * sub-clauses will be printed if the "-xtree=8" flag is specified.
 *
 * Currently, the only syntactic sugar feature is "if/else" statements.  Each
 * basic block (e.g. the body of the "if" and "else" statements, and the
 * statements before and after) is turned into its own sub-clause, with a
 * predicate that causes it to be executed only if the code flows to this point.
 * Nested if/else statements are supported.
 *
 * This infrastructure is designed to accommodate other syntactic sugar features
 * in the future.
 */

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/sysmacros.h>
#include <sys/param.h>
#include <sys/queue.h>

#include <assert.h>
#include <ctype.h>
#include <dwarf.h>
#include <err.h>
#include <fcntl.h>
#include <gelf.h>
#include <libdwarf.h>
#include <libelf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <dt_module.h>
#include <dt_program.h>
#include <dt_provider.h>
#include <dt_printf.h>
#include <dt_pid.h>
#include <dt_grammar.h>
#include <dt_ident.h>
#include <dt_string.h>
#include <dt_impl.h>

#include <dis_tables.h>

/* kinst-related */
struct elf_info {
	Elf			*elf;
	struct section	{
		Elf_Scn		*scn;
		GElf_Shdr	sh;
		const char	*name;
	}			*sl;
	size_t			shnum;
	int			fd;
};

struct entry {
	struct off {
		const char	*func;
		uint64_t	val;
		int		valid;
	}			*off;
	int			noff;
	TAILQ_ENTRY(entry)	next;
};

typedef struct dt_sugar_parse {
	dtrace_hdl_t *dtsp_dtp;		/* dtrace handle */
	dt_node_t *dtsp_pdescs;		/* probe descriptions */
	int dtsp_num_conditions;	/* number of condition variables */
	int dtsp_num_ifs;		/* number of "if" statements */
	dt_node_t *dtsp_clause_list;	/* list of clauses */
	struct elf_info	dtsp_elf_kern;	/* ELF info of the kernel executable */
	struct elf_info dtsp_elf_dbg;	/* ELF info of the kernel debug file */
	dtrace_probedesc_t *dtsp_desc;	/* kinst pdesc to duplicate contents */
	Dwarf_Off dtsp_dieoff;		/* DIE offset of kinst inline definition */
	int dtsp_inline;		/* kinst probe function is inline */
	int dtsp_entry;			/* kinst probe is entry */
	int dtsp_return;		/* kinst probe is return */
	TAILQ_HEAD(, entry) dtsp_head;	/* kinst inline copy entry TAILQ */
} dt_sugar_parse_t;

enum {
	F_SUBPROGRAM,
	F_INLINE_COPY,
};

static void dt_sugar_visit_stmts(dt_sugar_parse_t *, dt_node_t *, int);

/*
 * Return a node for "self->%error".
 *
 * Note that the "%" is part of the variable name, and is included so that
 * this variable name can not collide with any user-specified variable.
 *
 * This error variable is used to keep track of if there has been an error
 * in any of the sub-clauses, and is used to prevent execution of subsequent
 * sub-clauses following an error.
 */
static dt_node_t *
dt_sugar_new_error_var(void)
{
	return (dt_node_op2(DT_TOK_PTR, dt_node_ident(strdup("self")),
	    dt_node_ident(strdup("%error"))));
}

/*
 * Append this clause to the clause list.
 */
static void
dt_sugar_append_clause(dt_sugar_parse_t *dp, dt_node_t *clause)
{
	dp->dtsp_clause_list = dt_node_link(dp->dtsp_clause_list, clause);
}

/*
 * Prepend this clause to the clause list.
 */
static void
dt_sugar_prepend_clause(dt_sugar_parse_t *dp, dt_node_t *clause)
{
	dp->dtsp_clause_list = dt_node_link(clause, dp->dtsp_clause_list);
}

/*
 * Return a node for "this->%condition_<condid>", or NULL if condid==0.
 *
 * Note that the "%" is part of the variable name, and is included so that
 * this variable name can not collide with any user-specified variable.
 */
static dt_node_t *
dt_sugar_new_condition_var(int condid)
{
	char *str;

	if (condid == 0)
		return (NULL);
	assert(condid > 0);

	(void) asprintf(&str, "%%condition_%d", ABS(condid));
	return (dt_node_op2(DT_TOK_PTR, dt_node_ident(strdup("this")),
	    dt_node_ident(str)));
}

/*
 * Return new clause to evaluate predicate and set newcond.  condid is
 * the condition that we are already under, or 0 if none.
 * The new clause will be of the form:
 *
 * dp_pdescs
 * /!self->%error/
 * {
 *	this->%condition_<newcond> =
 *	    (this->%condition_<condid> && pred);
 * }
 *
 * Note: if condid==0, we will instead do "... = (1 && pred)", to effectively
 * convert the pred to a boolean.
 *
 * Note: Unless an error has been encountered, we always set the condition
 * variable (either to 0 or 1).  This lets us avoid resetting the condition
 * variables back to 0 when the super-clause completes.
 */
static dt_node_t *
dt_sugar_new_condition_impl(dt_sugar_parse_t *dp,
    dt_node_t *pred, int condid, int newcond)
{
	dt_node_t *value, *body, *newpred;

	/* predicate is !self->%error */
	newpred = dt_node_op1(DT_TOK_LNEG, dt_sugar_new_error_var());

	if (condid == 0) {
		/*
		 * value is (1 && pred)
		 *
		 * Note, D doesn't allow a probe-local "this" variable to
		 * be reused as a different type, even from a different probe.
		 * Therefore, value can't simply be <pred>, because then
		 * its type could be different when we reuse this condid
		 * in a different meta-clause.
		 */
		value = dt_node_op2(DT_TOK_LAND, dt_node_int(1), pred);
	} else {
		/* value is (this->%condition_<condid> && pred) */
		value = dt_node_op2(DT_TOK_LAND,
		    dt_sugar_new_condition_var(condid), pred);
	}

	/* body is "this->%condition_<retval> = <value>;" */
	body = dt_node_statement(dt_node_op2(DT_TOK_ASGN,
	    dt_sugar_new_condition_var(newcond), value));

	return (dt_node_clause(dp->dtsp_pdescs, newpred, body));
}

/*
 * Generate a new clause to evaluate predicate and set a new condition variable,
 * whose ID will be returned.  The new clause will be appended to
 * dp_first_new_clause.
 */
static int
dt_sugar_new_condition(dt_sugar_parse_t *dp, dt_node_t *pred, int condid)
{
	dp->dtsp_num_conditions++;
	dt_sugar_append_clause(dp, dt_sugar_new_condition_impl(dp,
	    pred, condid, dp->dtsp_num_conditions));
	return (dp->dtsp_num_conditions);
}

/*
 * kinst-related
 */
static void
dt_sugar_elf_init(dtrace_hdl_t *dtp, struct elf_info *ei, const char *file)
{
	Elf_Scn *scn;
	GElf_Shdr sh;
	struct section *s;
	const char *name;
	size_t shstrndx, ndx;

	if (elf_version(EV_CURRENT) == EV_NONE)
		errx(1, "dt_sugar: elf_version(): %s", elf_errmsg(-1));
	if ((ei->fd = open(file, O_RDONLY)) < 0)
		err(1, "dt_sugar: open(%s)", file);
	if ((ei->elf = elf_begin(ei->fd, ELF_C_READ, NULL)) == NULL)
		errx(1, "dt_sugar: elf_begin(): %s", elf_errmsg(-1));
	if (elf_kind(ei->elf) == ELF_K_NONE)
		errx(1, "dt_sugar: not an ELF file: %s", file);

	/* Load ELF sections */
	if (!elf_getshnum(ei->elf, &ei->shnum))
		errx(1, "dt_sugar: elf_getshnum(): %s", elf_errmsg(-1));
	ei->sl = dt_alloc(dtp, ei->shnum * sizeof(struct section));
	if (ei->sl == NULL)
		err(1, "dt_sugar: dt_alloc()");
	if (!elf_getshstrndx(ei->elf, &shstrndx))
		errx(1, "dt_sugar: elf_getshstrndx(): %s", elf_errmsg(-1));
	if ((scn = elf_getscn(ei->elf, 0)) == NULL)
		errx(1, "dt_sugar: elf_getscn(): %s", elf_errmsg(-1));
	(void) elf_errno();

	do {
		if (gelf_getshdr(scn, &sh) == NULL) {
			warnx("dt_sugar: gelf_getshdr(): %s", elf_errmsg(-1));
			(void) elf_errno();
			continue;
		}
		if ((name = elf_strptr(ei->elf, shstrndx, sh.sh_name)) == NULL)
			(void) elf_errno();
		if ((ndx = elf_ndxscn(scn)) == SHN_UNDEF && elf_errno() != 0) {
			warnx("dt_sugar: elf_ndxscn(): %s", elf_errmsg(-1));
			continue;
		}
		if (ndx >= ei->shnum)
			continue;
		s = &ei->sl[ndx];
		s->scn = scn;
		s->sh = sh;
		s->name = name;
	} while ((scn = elf_nextscn(ei->elf, scn)) != NULL);
	if (elf_errno() != 0)
		warnx("dt_sugar: elf_nextscn(): %s", elf_errmsg(-1));
}

static void
dt_sugar_elf_deinit(dtrace_hdl_t *dtp, struct elf_info *ei)
{
	dt_free(dtp, ei->sl);
	close(ei->fd);
	elf_end(ei->elf);
}

static int
dt_sugar_dis_get_byte(void *p)
{
	int ret;
	uint8_t **instr = p;

	ret = **instr;
	(*instr)++;

	return (ret);
}

/*
 * Find the caller function and offset of an inline copy. Since we know the
 * inline copy's boundaries (`addr_lo` and `addr_hi` arguments), the caller
 * function is going to be the ELF symbol that the inline copy's boundaries are
 * inside of.
 */
static void
dt_sugar_kinst_find_caller_func(dt_sugar_parse_t *dp, struct off *off,
    uint64_t addr_lo, uint64_t addr_hi, int last)
{
	Elf_Data *d;
	GElf_Sym sym;
	struct section *s;
	dis86_t d86;
	uint8_t *buf;
	uint64_t addr, lo, hi;
	uint32_t stab;
	int len, i, j;

	/* Find the caller function's boundaries and name. */
	off->func = NULL;
	for (i = 1; i < dp->dtsp_elf_kern.shnum; i++) {
		s = &dp->dtsp_elf_kern.sl[i];
		if (s->sh.sh_type != SHT_SYMTAB && s->sh.sh_type != SHT_DYNSYM)
			continue;
		if (s->sh.sh_link >= dp->dtsp_elf_kern.shnum)
			continue;
		stab = s->sh.sh_link;
		(void) elf_errno();
		if ((d = elf_getdata(s->scn, NULL)) == NULL) {
			if (elf_errno() != 0)
				warnx("dt_sugar: elf_getdata(): %s",
				    elf_errmsg(-1));
			continue;
		}
		if (d->d_size <= 0)
			continue;
		if (s->sh.sh_entsize == 0)
			continue;
		else if (s->sh.sh_size / s->sh.sh_entsize > INT_MAX)
			continue;
		len = (int)(s->sh.sh_size / s->sh.sh_entsize);
		for (j = 0; j < len; j++) {
			if (gelf_getsym(d, j, &sym) != &sym) {
				warnx("dt_sugar: gelf_getsym(): %s",
				    elf_errmsg(-1));
				continue;
			}
			lo = sym.st_value;
			hi = sym.st_value + sym.st_size;
			if (addr_lo < lo || addr_hi > hi)
				continue;
			if ((off->func = elf_strptr(dp->dtsp_elf_kern.elf, stab,
			    sym.st_name)) != NULL)
				break;
		}
	}

	/* Find inline copy's return offset. */
	for (i = 1; i < dp->dtsp_elf_kern.shnum; i++) {
		s = &dp->dtsp_elf_kern.sl[i];
		if (strcmp(s->name, ".text") != 0 ||
		    s->sh.sh_type != SHT_PROGBITS)
			continue;
		(void) elf_errno();
		if ((d = elf_getdata(s->scn, NULL)) == NULL) {
			if (elf_errno() != 0)
				warnx("dt_sugar: elf_getdata(): %s",
				    elf_errmsg(-1));
			continue;
		}
		if (d->d_size <= 0 || d->d_buf == NULL)
			continue;

		buf = d->d_buf;
		addr = s->sh.sh_addr + d->d_off;

		/*
		 * Compiling without `-mno-omit-leaf-frame-pointer` might
		 * result in, as the name suggests, leaf functions omitting
		 * `push %rbp`. kinst ignores any function that doesn't start
		 * with this instruction, so in order to avoid having dtrace(1)
		 * exit because one of the probes we're creating is a leaf
		 * function with its 'push %rbp' ommitted, we're catching this
		 * error before we get to kinst.
		 */
		while (addr != lo) {
			addr++;
			buf++;
		}
		if (*buf != 0x55) {
			warnx("dt_sugar: ignoring '%s': function does not "
			    "begin with 'push %%rbp'", off->func);
			off->valid = 0;
			return;
		}
		off->valid = 1;

		/*
		 * Get to the inline copy's start manually to avoid potential
		 * dtrace_disx86() failures.
		 */
		while (addr != addr_lo) {
			addr++;
			buf++;
		}

		if (dp->dtsp_entry) {
			off->val = addr - lo;
			break;
		} else if (dp->dtsp_return)
			;	/* nothing */

		d86.d86_data = &buf;
		d86.d86_get_byte = dt_sugar_dis_get_byte;
		d86.d86_check_func = NULL;

		/* Get to the inline copy's end. */
		while (addr != addr_hi) {
			/*
			 * XXX We might have to add #ifdefs when we port kinst
			 * to other architectures.
			 */
			if (dtrace_disx86(&d86, SIZE64) != 0) {
				warnx("dt_sugar: dtrace_disx86() failed");
				return;
			}
			addr += d86.d86_len;
		}
		/*
		 * In this case the offset is one instruction *outside* the
		 * inline or the caller function, so we have to go back one
		 * instruction to stay within bounds.
		 */
		if (addr_hi == hi || last)
			addr -= d86.d86_len;
		off->val = addr - lo;
		break;
	}
}

/*
 * Parse DWARF info recursively and create a TAILQ of entries that correspond
 * to inline copies of the probe function.
 */
static void
dt_sugar_kinst_parse_die(dt_sugar_parse_t *dp, Dwarf_Debug dbg, Dwarf_Die die,
    int level, int flag)
{
	static Dwarf_Die die_root;
	Dwarf_Die die_next;
	Dwarf_Ranges *ranges, *rp;
	Dwarf_Attribute attp;
	Dwarf_Addr base0, lowpc, highpc;
	Dwarf_Off dieoff, cuoff, culen, v_off;
	Dwarf_Unsigned nbytes, v_udata;
	Dwarf_Signed nranges;
	Dwarf_Half attr, tag;
	Dwarf_Bool v_flag;
	Dwarf_Error error;
	struct entry *e;
	struct off *off;
	char *v_str;
	int res, noff, i, found = 0;

	if (level == 0)
		die_root = die;

	if (dwarf_dieoffset(die, &dieoff, &error) != DW_DLV_OK) {
		warnx("dt_sugar: %s", dwarf_errmsg(error));
		goto cont;
	}
	if (dwarf_die_CU_offset_range(die, &cuoff, &culen, &error) != DW_DLV_OK) {
		warnx("dt_sugar: %s", dwarf_errmsg(error));
		cuoff = 0;
	}
	if (dwarf_tag(die, &tag, &error) != DW_DLV_OK) {
		warnx("dt_sugar: %s", dwarf_errmsg(error));
		goto cont;
	}
	if (tag != DW_TAG_subprogram && tag != DW_TAG_inlined_subroutine)
		goto cont;
	if (flag == F_SUBPROGRAM && tag == DW_TAG_subprogram) {
		if (dwarf_hasattr(die, DW_AT_inline, &v_flag, &error) !=
		    DW_DLV_OK) {
			warnx("dt_sugar: %s", dwarf_errmsg(error));
			goto cont;
		}
		if (!v_flag)
			goto cont;
		res = dwarf_diename(die, &v_str, &error);
		if (res != DW_DLV_OK) {
			warnx("dt_sugar: %s", dwarf_errmsg(error));
			goto cont;
		}
		if (strcmp(v_str, dp->dtsp_desc->dtpd_func) != 0)
			goto cont;
		/*
		 * The function name we're searching for has an inline
		 * definition.
		 */
		found = 1;
		goto cont;
	} else if (flag == F_INLINE_COPY && tag == DW_TAG_inlined_subroutine) {
		res = dwarf_attr(die, DW_AT_abstract_origin, &attp, &error);
		if (res != DW_DLV_OK) {
			if (res == DW_DLV_ERROR)
				warnx("dt_sugar: %s", dwarf_errmsg(error));
			goto cont;
		}
		if (dwarf_formref(attp, &v_off, &error) != DW_DLV_OK) {
			warnx("dt_sugar: %s", dwarf_errmsg(error));
			goto cont;
		}
		v_off += cuoff;
		/* Doesn't point to the definition's DIE offset. */
		if (v_off != dp->dtsp_dieoff)
			goto cont;

		if (dwarf_hasattr(die, DW_AT_ranges, &v_flag, &error) !=
		    DW_DLV_OK) {
			warnx("dt_sugar: %s", dwarf_errmsg(error));
			goto cont;
		}
		if (v_flag) {
			/* DIE has ranges */
			res = dwarf_attr(die, DW_AT_ranges, &attp, &error);
			if (res != DW_DLV_OK) {
				if (res == DW_DLV_ERROR)
					warnx("dt_sugar: %s",
					    dwarf_errmsg(error));
				goto cont;
			}
			if (dwarf_global_formref(attp, &v_off, &error) !=
			    DW_DLV_OK) {
				warnx("dt_sugar: %s", dwarf_errmsg(error));
				goto cont;
			}
			if (dwarf_get_ranges(dbg, v_off, &ranges, &nranges,
			    &nbytes, &error) != DW_DLV_OK) {
				warnx("dt_sugar: %s", dwarf_errmsg(error));
				goto cont;
			}

			res = dwarf_lowpc(die_root, &lowpc, &error);
			if (res != DW_DLV_OK) {
				warnx("dt_sugar: %s", dwarf_errmsg(error));
				goto cont;
			}
			base0 = lowpc;

			if (dp->dtsp_entry) {
				/*
				 * Trace the first instruction of the first
				 * range since this is the beginning of the
				 * inline copy.
				 */
				noff = 1;
			} else if (dp->dtsp_return) {
				/*
				 * Trace the last instruction of every range in
				 * case the inline copy is split into multiple
				 * ranges (e.g if it has early `return`s).
				 */
				noff = nranges - 1;
			}
			off = dt_alloc(dp->dtsp_dtp, noff * sizeof(struct off));
			if (off == NULL)
				err(1, "dt_sugar: dt_alloc()");
			for (i = 0; i < noff; i++) {
				rp = &ranges[i];
				if (rp->dwr_type == DW_RANGES_ADDRESS_SELECTION)
					base0 = rp->dwr_addr2;
				dt_sugar_kinst_find_caller_func(dp, &off[i],
				    rp->dwr_addr1 + base0,
				    rp->dwr_addr2 + base0,
				    dp->dtsp_return && i == noff - 1);
			}
			dwarf_ranges_dealloc(dbg, ranges, nranges);
		} else {
			/* DIE has high/low PC boundaries */
			res = dwarf_lowpc(die, &lowpc, &error);
			if (res != DW_DLV_OK) {
				warnx("dt_sugar: %s", dwarf_errmsg(error));
				goto cont;
			}
			res = dwarf_highpc(die, &highpc, &error);
			if (res != DW_DLV_OK) {
				warnx("dt_sugar: %s", dwarf_errmsg(error));
				goto cont;
			}
			noff = 1;
			off = dt_alloc(dp->dtsp_dtp, noff * sizeof(struct off));
			if (off == NULL)
				err(1, "dt_sugar: dt_alloc()");
			dt_sugar_kinst_find_caller_func(dp, off, lowpc,
			    lowpc + highpc, dp->dtsp_return);
		}
	} else
		goto cont;

	e = dt_alloc(dp->dtsp_dtp, sizeof(struct entry));
	if (e == NULL)
		err(1, "dt_sugar: dt_alloc()");
	e->noff = noff;
	e->off = off;
	TAILQ_INSERT_TAIL(&dp->dtsp_head, e, next);
cont:
	/*
	 * Inline copies might appear before the declaration, so we need to
	 * re-parse the CU.
	 *
	 * The rationale for choosing to re-parse the CU instead of using a
	 * hash table of DIEs is that, because we re-parse only when an inline
	 * definition of the function we want is found, statistically, we won't
	 * have to re-parse many times at all considering that only a handful
	 * of CUs will define the same function, whereas if we have used a hash
	 * table, we would first need to parse the whole CU at once and store
	 * all DW_TAG_inlined_subroutine DIEs (so that we can match them
	 * afterwards). In this case, we always have to "parse" twice -- first
	 * the CU, then the DIE table -- and also, the program would use much
	 * more memory since we would have allocated DIEs, which most of them
	 * would never be used.
	 */
	if (found) {
		die = die_root;
		level = 0;
		/*
		 * We'll be checking against the DIE offset of the definition
		 * to determine if the inline copy's DW_AT_abstract_origin
		 * points to it.
		 */
		dp->dtsp_dieoff = dieoff;
		dp->dtsp_inline = 1;
		flag = F_INLINE_COPY;
	}

	res = dwarf_child(die, &die_next, &error);
	if (res == DW_DLV_ERROR)
		warnx("dt_sugar: %s", dwarf_errmsg(error));
	else if (res == DW_DLV_OK)
		dt_sugar_kinst_parse_die(dp, dbg, die_next, level + 1, flag);

	res = dwarf_siblingof(dbg, die, &die_next, &error);
	if (res == DW_DLV_ERROR)
		warnx("dt_sugar: %s", dwarf_errmsg(error));
	else if (res == DW_DLV_OK)
		dt_sugar_kinst_parse_die(dp, dbg, die_next, level, flag);

	/*
	 * Deallocating on level 0 will attempt to double-free, since die_root
	 * points to the first DIE. We'll deallocate the root DIE in main().
	 */
	if (level > 0)
		dwarf_dealloc(dbg, die, DW_DLA_DIE);
}

/*
 * Append new clauses for each inline copy to the parse tree.
 *
 * If foo() is an inline function, and is called from functions bar() and baz()
 * at offsets 10 and 20 respectively, we'll transform the parse tree from:
 *
 *	kinst::foo:<entry/return>
 *	/<pred>/
 *	{
 *		<acts>
 *	}
 *
 * To:
 *
 *	kinst::bar:10,
 *	kinst::baz:20
 *	/<pred>/
 *	{
 *		<acts>
 *	}
 */
static void
dt_sugar_kinst_create_probes(dt_sugar_parse_t *dp)
{
	dt_node_t *pdesc, *dnp;
	struct entry *e;
	char buf[DTRACE_FULLNAMELEN];
	int i, j = 0;

	dnp = dp->dtsp_clause_list->dn_pdescs;

	/* Clean up as well */
	while (!TAILQ_EMPTY(&dp->dtsp_head)) {
		e = TAILQ_FIRST(&dp->dtsp_head);
		TAILQ_REMOVE(&dp->dtsp_head, e, next);
		for (i = 0; i < e->noff; i++) {
			if (!e->off[i].valid)
				continue;
			if (j++ == 0) {
				/*
				 * Since we're trying to trace inline copies of
				 * a given function by requesting a probe of
				 * the form
				 * `kinst::<inline_func_name>:<entry/return>`,
				 * the requested probe, by definition cannot be
				 * traced, and as a result DTrace will exit
				 * with an error because it cannot create a
				 * probe for this function. In order to get
				 * around this, we're overriding the requested
				 * probe's <function> and <offset> fields with
				 * the very first inline copy's information.
				 */
				snprintf(buf, sizeof(buf), "%lu", e->off[i].val);
				strlcpy(dp->dtsp_desc->dtpd_func, e->off[i].func,
				    sizeof(dp->dtsp_desc->dtpd_func));
				strlcpy(dp->dtsp_desc->dtpd_name, buf,
				    sizeof(dp->dtsp_desc->dtpd_name));
			} else {
				/*
				 * Append the probe description of each inline
				 * copy to main clause.
				 */
				snprintf(buf, sizeof(buf), "%s:%s:%s:%lu",
				    dp->dtsp_desc->dtpd_provider,
				    dp->dtsp_desc->dtpd_mod,
				    e->off[i].func, e->off[i].val);
				pdesc = dt_node_pdesc_by_name(strdup(buf));
				dnp = dt_node_link(dnp, pdesc);
			}
		}
		dt_free(dp->dtsp_dtp, e->off);
		dt_free(dp->dtsp_dtp, e);
	}
}

/*
 * Initialize libelf and libdwarf and parse kernel.debug's DWARF info.
 */
static void
dt_sugar_do_kinst_inline(dt_sugar_parse_t *dp)
{
	Dwarf_Debug dbg;
	Dwarf_Die die;
	Dwarf_Error error;
	char dbgfile[MAXPATHLEN];
	int res = DW_DLV_OK;

	dp->dtsp_entry = 0;
	dp->dtsp_return = 0;
	dp->dtsp_inline = 0;
	/* We only make entry and return probes for inline functions. */
	if (strcmp(dp->dtsp_desc->dtpd_name, "entry") == 0)
		dp->dtsp_entry = 1;
	else if (strcmp(dp->dtsp_desc->dtpd_name, "return") == 0)
		dp->dtsp_return = 1;
	else
		return;

	(void) snprintf(dbgfile, sizeof(dbgfile), "/usr/lib/debug/%s.debug",
	    dp->dtsp_dtp->bootfile);
	dt_sugar_elf_init(dp->dtsp_dtp, &dp->dtsp_elf_kern,
	    dp->dtsp_dtp->bootfile);
	dt_sugar_elf_init(dp->dtsp_dtp, &dp->dtsp_elf_dbg, dbgfile);

	if (dwarf_elf_init(dp->dtsp_elf_dbg.elf, DW_DLC_READ, NULL, NULL, &dbg,
	    &error) != DW_DLV_OK)
		errx(1, "dt_sugar: dwarf_elf_init(): %s", dwarf_errmsg(error));

	TAILQ_INIT(&dp->dtsp_head);
	/*
	 * Parse DWARF info for kernel.debug and create entries for the inline
	 * copies we'll create probes for.
	 */
	while ((res = dwarf_next_cu_header(dbg, NULL, NULL, NULL, NULL, NULL,
	    &error)) == DW_DLV_OK) {
		die = NULL;
		while (dwarf_siblingof(dbg, die, &die, &error) == DW_DLV_OK)
			dt_sugar_kinst_parse_die(dp, dbg, die, 0, F_SUBPROGRAM);
		dwarf_dealloc(dbg, die, DW_DLA_DIE);
	}
	if (res == DW_DLV_ERROR)
		warnx("dt_sugar: %s", dwarf_errmsg(error));

	dt_sugar_elf_deinit(dp->dtsp_dtp, &dp->dtsp_elf_kern);
	dt_sugar_elf_deinit(dp->dtsp_dtp, &dp->dtsp_elf_dbg);
	dwarf_finish(dbg, &error);
}

/*
 * Visit the specified node and all of its descendants.
 */
static void
dt_sugar_visit_all(dt_sugar_parse_t *dp, dt_node_t *dnp)
{
	dt_node_t *arg;

	switch (dnp->dn_kind) {
	case DT_NODE_FREE:
	case DT_NODE_INT:
	case DT_NODE_STRING:
	case DT_NODE_SYM:
	case DT_NODE_TYPE:
	case DT_NODE_PROBE:
	case DT_NODE_PDESC:
	case DT_NODE_IDENT:
		break;

	case DT_NODE_FUNC:
		for (arg = dnp->dn_args; arg != NULL; arg = arg->dn_list)
			dt_sugar_visit_all(dp, arg);
		break;

	case DT_NODE_OP1:
		dt_sugar_visit_all(dp, dnp->dn_child);
		break;

	case DT_NODE_OP2:
		dt_sugar_visit_all(dp, dnp->dn_left);
		dt_sugar_visit_all(dp, dnp->dn_right);
		if (dnp->dn_op == DT_TOK_LBRAC) {
			dt_node_t *ln = dnp->dn_right;
			while (ln->dn_list != NULL) {
				dt_sugar_visit_all(dp, ln->dn_list);
				ln = ln->dn_list;
			}
		}
		break;

	case DT_NODE_OP3:
		dt_sugar_visit_all(dp, dnp->dn_expr);
		dt_sugar_visit_all(dp, dnp->dn_left);
		dt_sugar_visit_all(dp, dnp->dn_right);
		break;

	case DT_NODE_DEXPR:
	case DT_NODE_DFUNC:
		dt_sugar_visit_all(dp, dnp->dn_expr);
		break;

	case DT_NODE_AGG:
		for (arg = dnp->dn_aggtup; arg != NULL; arg = arg->dn_list)
			dt_sugar_visit_all(dp, arg);

		if (dnp->dn_aggfun)
			dt_sugar_visit_all(dp, dnp->dn_aggfun);
		break;

	case DT_NODE_CLAUSE:
		for (arg = dnp->dn_pdescs; arg != NULL; arg = arg->dn_list)
			dt_sugar_visit_all(dp, arg);

		if (dnp->dn_pred != NULL)
			dt_sugar_visit_all(dp, dnp->dn_pred);

		for (arg = dnp->dn_acts; arg != NULL; arg = arg->dn_list)
			dt_sugar_visit_all(dp, arg);
		break;

	case DT_NODE_INLINE: {
		const dt_idnode_t *inp = dnp->dn_ident->di_iarg;

		dt_sugar_visit_all(dp, inp->din_root);
		break;
	}
	case DT_NODE_MEMBER:
		if (dnp->dn_membexpr)
			dt_sugar_visit_all(dp, dnp->dn_membexpr);
		break;

	case DT_NODE_XLATOR:
		for (arg = dnp->dn_members; arg != NULL; arg = arg->dn_list)
			dt_sugar_visit_all(dp, arg);
		break;

	case DT_NODE_PROVIDER:
		for (arg = dnp->dn_probes; arg != NULL; arg = arg->dn_list)
			dt_sugar_visit_all(dp, arg);
		break;

	case DT_NODE_PROG:
		for (arg = dnp->dn_list; arg != NULL; arg = arg->dn_list)
			dt_sugar_visit_all(dp, arg);
		break;

	case DT_NODE_IF:
		dp->dtsp_num_ifs++;
		dt_sugar_visit_all(dp, dnp->dn_conditional);

		for (arg = dnp->dn_body; arg != NULL; arg = arg->dn_list)
			dt_sugar_visit_all(dp, arg);
		for (arg = dnp->dn_alternate_body; arg != NULL;
		    arg = arg->dn_list)
			dt_sugar_visit_all(dp, arg);

		break;

	default:
		(void) dnerror(dnp, D_UNKNOWN, "bad node %p, kind %d\n",
		    (void *)dnp, dnp->dn_kind);
	}
}

/*
 * Return a new clause which resets the error variable to zero:
 *
 *   dp_pdescs{ self->%error = 0; }
 *
 * This clause will be executed at the beginning of each meta-clause, to
 * ensure the error variable is unset (in case the previous meta-clause
 * failed).
 */
static dt_node_t *
dt_sugar_new_clearerror_clause(dt_sugar_parse_t *dp)
{
	dt_node_t *stmt = dt_node_statement(dt_node_op2(DT_TOK_ASGN,
	    dt_sugar_new_error_var(), dt_node_int(0)));
	return (dt_node_clause(dp->dtsp_pdescs, NULL, stmt));
}

/*
 * Evaluate the conditional, and recursively visit the body of the "if"
 * statement (and the "else", if present).
 */
static void
dt_sugar_do_if(dt_sugar_parse_t *dp, dt_node_t *if_stmt, int precondition)
{
	int newid;

	assert(if_stmt->dn_kind == DT_NODE_IF);

	/* condition */
	newid = dt_sugar_new_condition(dp,
	    if_stmt->dn_conditional, precondition);

	/* body of if */
	dt_sugar_visit_stmts(dp, if_stmt->dn_body, newid);

	/*
	 * Visit the body of the "else" statement, if present.  Note that we
	 * generate a new condition which is the inverse of the previous
	 * condition.
	 */
	if (if_stmt->dn_alternate_body != NULL) {
		dt_node_t *pred =
		    dt_node_op1(DT_TOK_LNEG, dt_sugar_new_condition_var(newid));
		dt_sugar_visit_stmts(dp, if_stmt->dn_alternate_body,
		    dt_sugar_new_condition(dp, pred, precondition));
	}
}

/*
 * Generate a new clause to evaluate the statements based on the condition.
 * The new clause will be appended to dp_first_new_clause.
 *
 * dp_pdescs
 * /!self->%error && this->%condition_<condid>/
 * {
 *	stmts
 * }
 */
static void
dt_sugar_new_basic_block(dt_sugar_parse_t *dp, int condid, dt_node_t *stmts)
{
	dt_node_t *pred = NULL;

	if (condid == 0) {
		/*
		 * Don't bother with !error on the first clause, because if
		 * there is only one clause, we don't add the prelude to
		 * zero out %error.
		 */
		if (dp->dtsp_num_conditions != 0) {
			pred = dt_node_op1(DT_TOK_LNEG,
			    dt_sugar_new_error_var());
		}
	} else {
		pred = dt_node_op2(DT_TOK_LAND,
		    dt_node_op1(DT_TOK_LNEG, dt_sugar_new_error_var()),
		    dt_sugar_new_condition_var(condid));
	}
	dt_sugar_append_clause(dp,
	    dt_node_clause(dp->dtsp_pdescs, pred, stmts));
}

/*
 * Visit all the statements in this list, and break them into basic blocks,
 * generating new clauses for "if" and "else" statements.
 */
static void
dt_sugar_visit_stmts(dt_sugar_parse_t *dp, dt_node_t *stmts, int precondition)
{
	dt_node_t *stmt;
	dt_node_t *prev_stmt = NULL;
	dt_node_t *next_stmt;
	dt_node_t *first_stmt_in_basic_block = NULL;

	for (stmt = stmts; stmt != NULL; stmt = next_stmt) {
		next_stmt = stmt->dn_list;

		if (stmt->dn_kind != DT_NODE_IF) {
			if (first_stmt_in_basic_block == NULL)
				first_stmt_in_basic_block = stmt;
			prev_stmt = stmt;
			continue;
		}

		/*
		 * Remove this and following statements from the previous
		 * clause.
		 */
		if (prev_stmt != NULL)
			prev_stmt->dn_list = NULL;

		/*
		 * Generate clause for statements preceding the "if"
		 */
		if (first_stmt_in_basic_block != NULL) {
			dt_sugar_new_basic_block(dp, precondition,
			    first_stmt_in_basic_block);
		}

		dt_sugar_do_if(dp, stmt, precondition);

		first_stmt_in_basic_block = NULL;

		prev_stmt = stmt;
	}

	/* generate clause for statements after last "if". */
	if (first_stmt_in_basic_block != NULL) {
		dt_sugar_new_basic_block(dp, precondition,
		    first_stmt_in_basic_block);
	}
}

/*
 * Generate a new clause which will set the error variable when an error occurs.
 * Only one of these clauses is created per program (e.g. script file).
 * The clause is:
 *
 * dtrace:::ERROR{ self->%error = 1; }
 */
static dt_node_t *
dt_sugar_makeerrorclause(void)
{
	dt_node_t *acts, *pdesc;

	pdesc = dt_node_pdesc_by_name(strdup("dtrace:::ERROR"));

	acts = dt_node_statement(dt_node_op2(DT_TOK_ASGN,
	    dt_sugar_new_error_var(), dt_node_int(1)));

	return (dt_node_clause(pdesc, NULL, acts));
}

/*
 * Transform the super-clause into straight-D, returning the new list of
 * sub-clauses.
 */
dt_node_t *
dt_compile_sugar(dtrace_hdl_t *dtp, dt_node_t *clause)
{
	dt_sugar_parse_t dp = { 0 };
	dt_node_t *dnp;
	int condid = 0;

	dp.dtsp_dtp = dtp;
	dp.dtsp_pdescs = clause->dn_pdescs;

	/* make dt_node_int() generate an "int"-typed integer */
	yyintdecimal = B_TRUE;
	yyintsuffix[0] = '\0';
	yyintprefix = 0;

	dt_sugar_visit_all(&dp, clause);

	if (dp.dtsp_num_ifs == 0 && dp.dtsp_num_conditions == 0) {
		/*
		 * There is nothing that modifies the number of clauses.  Use
		 * the existing clause as-is, with its predicate intact.  This
		 * ensures that in the absence of D sugar, the body of the
		 * clause can create a variable that is referenced in the
		 * predicate.
		 */
		dt_sugar_append_clause(&dp, dt_node_clause(clause->dn_pdescs,
		    clause->dn_pred, clause->dn_acts));
	} else {
		if (clause->dn_pred != NULL) {
			condid = dt_sugar_new_condition(&dp,
			    clause->dn_pred, condid);
		}

		if (clause->dn_acts == NULL) {
			/*
			 * dt_sugar_visit_stmts() does not emit a clause with
			 * an empty body (e.g. if there's an empty "if" body),
			 * but we need the empty body here so that we
			 * continue to get the default tracing action.
			 */
			dt_sugar_new_basic_block(&dp, condid, NULL);
		} else {
			dt_sugar_visit_stmts(&dp, clause->dn_acts, condid);
		}
	}

	if (dp.dtsp_num_conditions != 0) {
		dt_sugar_prepend_clause(&dp,
		    dt_sugar_new_clearerror_clause(&dp));
	}

	/*
	 * This loop is a bit of a hack. What it does is iterate through all
	 * probe descriptions and handle kinst entry/return probes, but you
	 * will notice that in case we handle inline function probes,
	 * dt_sugar_kinst_create_probes() appends new elements to the list
	 * we're looping through, yet it works just fine!
	 *
	 * Consider the following initial `dn_pdescs` list:
	 *
	 * dn_pdescs				= kinst::inlinefunc1:entry
	 * dn_pdescs->dn_list			= kinst::inlinefunc2:return
	 * dn_pdescs->dn_list->dn_list		= kinst::normalfunc1:0
	 * dn_pdescs->dn_list->dn_list->dn_list = kinst::normalfunc2:entry
	 *
	 * The final list will look like this (read the comments in
	 * dt_sugar_kinst_create_probes()):
	 *
	 * dn_pdescs				= kinst::callerfunc1:<x>
	 * dn_pdescs->dn_list			= kinst::callerfunc2:<y>
	 * dn_pdescs->dn_list->dn_list		= kinst::normalfunc1:0
	 * dn_pdescs->dn_list->dn_list->dn_list	= fbt::normalfunc2:entry
	 * ...					= new probes are appended here
	 *
	 * Because it is guaranteed that any new probes appended to the list by
	 * dt_sugar_kinst_create_probes() will be regular kinst probes, the
	 * loop below *does* loop through them as well, but does nothing since
	 * regular kinst probes are skipped.
	 */
	for (dnp = dp.dtsp_clause_list->dn_pdescs; dnp != NULL;
	    dnp = dnp->dn_list) {
		if (strcmp(dnp->dn_desc->dtpd_provider, "kinst") != 0)
			continue;
		dp.dtsp_desc = dnp->dn_desc;
		dt_sugar_do_kinst_inline(&dp);
		if (dp.dtsp_inline)
			dt_sugar_kinst_create_probes(&dp);
		else if (!dp.dtsp_inline && (dp.dtsp_entry || dp.dtsp_return)) {
			/*
			 * Delegate non-inline function probes to FBT so that
			 * we don't duplicate FBT code in kinst.
			 */
			strlcpy(dp.dtsp_desc->dtpd_provider, "fbt",
			    sizeof(dp.dtsp_desc->dtpd_provider));
		}
		/* Regular kinst probes are not affected. */
	}

	if (dp.dtsp_clause_list != NULL &&
	    dp.dtsp_clause_list->dn_list != NULL && !dtp->dt_has_sugar) {
		dtp->dt_has_sugar = B_TRUE;
		dt_sugar_prepend_clause(&dp, dt_sugar_makeerrorclause());
	}

	return (dp.dtsp_clause_list);
}
