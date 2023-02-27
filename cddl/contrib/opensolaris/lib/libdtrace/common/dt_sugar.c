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
#include <strings.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <dt_module.h>
#include <dt_program.h>
#include <dt_provider.h>
#include <dt_printf.h>
#include <dt_pid.h>
#include <dt_grammar.h>
#include <dt_ident.h>
#include <dt_string.h>
#include <dt_impl.h>

/* kinst-related */
#include <dwarf.h>
#include <err.h>
#include <fcntl.h>
#include <gelf.h>
#include <libdwarf.h>
#include <libelf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct dt_sugar_parse {
	dtrace_hdl_t *dtsp_dtp;		/* dtrace handle */
	dt_node_t *dtsp_pdescs;		/* probe descriptions */
	int dtsp_num_conditions;	/* number of condition variables */
	int dtsp_num_ifs;		/* number of "if" statements */
	int dtsp_kinst;			/* specify if the provider is kinst */
	dt_node_t *dtsp_clause_list;	/* list of clauses */
} dt_sugar_parse_t;

/* kinst-related */
struct elf_info {
	Elf			*elf;
	struct section	{
		Elf_Scn		*scn;
		uint64_t	sz;
		uint64_t	entsize;
		uint64_t	type;
		uint32_t	link;
		uint32_t	info;
	}			*sl;
	size_t			shnum;
};

struct entry {
	const char		*callerfunc;
	int			noff;
	struct off {
		const char	*func;
		uint64_t	val;
	}			*off;
	TAILQ_ENTRY(entry)	next;
};

enum {
	F_SUBPROGRAM,
	F_INLINE_COPY,
};

static struct elf_info		ei;
static dtrace_probedesc_t	*desc;
static Dwarf_Off		g_dieoff;
static int			f_inline = 0;
static int			f_entry_or_return = 0;
static TAILQ_HEAD(, entry)	head = TAILQ_HEAD_INITIALIZER(head);

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
static void *
emalloc(size_t nb)
{
	void *p;

	if ((p = malloc(nb)) == NULL)
		err(1, "malloc");

	return (p);
}

/*
 * Find the caller function of an inline copy. Since we know the inline copy's
 * boundaries (`addr_lo` and `addr_hi` arguments), the caller function is going
 * to be the ELF symbol that the inline copy's boundaries are inside of.
 */
static void
dt_sugar_kinst_find_caller_func(struct off *off, uint64_t addr_lo,
    uint64_t addr_hi)
{
	Elf_Data *d;
	GElf_Sym sym;
	struct section *s;
	uint64_t lo, hi;
	uint32_t stab;
	int len, i, j;

	for (i = 0; i < ei.shnum; i++) {
		s = &ei.sl[i];
		if (s->type != SHT_SYMTAB && s->type != SHT_DYNSYM)
			continue;
		if (s->link >= ei.shnum)
			continue;
		stab = s->link;
		(void)elf_errno();
		if ((d = elf_getdata(s->scn, NULL)) == NULL) {
			if (elf_errno() != 0)
				warnx("elf_getdata(): %s", elf_errmsg(-1));
			continue;
		}
		if (d->d_size <= 0)
			continue;
		if (s->entsize == 0)
			continue;
		else if (s->sz / s->entsize > INT_MAX)
			continue;
		len = (int)(s->sz / s->entsize);
		for (j = 0; j < len; j++) {
			if (gelf_getsym(d, j, &sym) != &sym) {
				warnx("gelf_getsym(): %s", elf_errmsg(-1));
				continue;
			}
			lo = sym.st_value;
			hi = sym.st_value + sym.st_size;
			if (addr_lo < lo || addr_hi > hi)
				continue;
			if (strcmp(desc->dtpd_name, "entry") == 0) {
				off->val = addr_lo - lo;
			} else if (strcmp(desc->dtpd_name, "return") == 0) {
				off->val = addr_hi - lo;
				/* FIXME find last instruction's size */
			}
			if ((off->func = elf_strptr(ei.elf, stab, sym.st_name))
			    != NULL)
				return;
		}
	}
	/* NOTREACHED */
	off->func = NULL;
}

/*
 * Parse DWARF info recursively and create a TAILQ of entries that correspond
 * to inline copies of the probe function.
 */
static void
dt_sugar_kinst_parse_die(Dwarf_Debug dbg, Dwarf_Die die, int level, int flag)
{
	static Dwarf_Die die_root;
	Dwarf_Die die_next;
	Dwarf_Ranges *ranges, *rp;
	Dwarf_Attribute attp;
	Dwarf_Addr base0, v_addr;
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
		warnx("%s", dwarf_errmsg(error));
		goto cont;
	}
	if (dwarf_die_CU_offset_range(die, &cuoff, &culen, &error) != DW_DLV_OK) {
		warnx("%s", dwarf_errmsg(error));
		cuoff = 0;
	}
	if (dwarf_tag(die, &tag, &error) != DW_DLV_OK) {
		warnx("%s", dwarf_errmsg(error));
		goto cont;
	}
	if (tag != DW_TAG_subprogram && tag != DW_TAG_inlined_subroutine)
		goto cont;
	if (flag == F_SUBPROGRAM && tag == DW_TAG_subprogram) {
		if (dwarf_hasattr(die, DW_AT_inline, &v_flag, &error) !=
		    DW_DLV_OK) {
			warnx("%s", dwarf_errmsg(error));
			goto cont;
		}
		if (!v_flag)
			goto cont;
		res = dwarf_attr(die, DW_AT_name, &attp, &error);
		if (res != DW_DLV_OK) {
			if (res == DW_DLV_ERROR)
				warnx("%s", dwarf_errmsg(error));
			goto cont;
		}
		if (dwarf_formstring(attp, &v_str, &error) != DW_DLV_OK) {
			warnx("%s", dwarf_errmsg(error));
			goto cont;
		}
		if (strcmp(v_str, desc->dtpd_func) != 0)
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
				warnx("%s", dwarf_errmsg(error));
			goto cont;
		}
		if (dwarf_formref(attp, &v_off, &error) != DW_DLV_OK) {
			warnx("%s", dwarf_errmsg(error));
			goto cont;
		}
		v_off += cuoff;
		/* Doesn't point to the definition's DIE offset. */
		if (v_off != g_dieoff)
			goto cont;

		if (dwarf_hasattr(die, DW_AT_ranges, &v_flag, &error) !=
		    DW_DLV_OK) {
			warnx("%s", dwarf_errmsg(error));
			goto cont;
		}
		if (v_flag) {
			/* DIE has ranges */
			res = dwarf_attr(die, DW_AT_ranges, &attp, &error);
			if (res != DW_DLV_OK) {
				if (res == DW_DLV_ERROR)
					warnx("%s", dwarf_errmsg(error));
				goto cont;
			}
			if (dwarf_global_formref(attp, &v_off, &error) !=
			    DW_DLV_OK) {
				warnx("%s", dwarf_errmsg(error));
				goto cont;
			}
			if (dwarf_get_ranges(dbg, v_off, &ranges, &nranges,
			    &nbytes, &error) != DW_DLV_OK) {
				warnx("%s", dwarf_errmsg(error));
				goto cont;
			}

			res = dwarf_attr(die_root, DW_AT_low_pc, &attp,
			    &error);
			if (res != DW_DLV_OK) {
				if (res == DW_DLV_ERROR)
					warnx("%s", dwarf_errmsg(error));
				goto cont;
			}
			if (dwarf_formaddr(attp, &v_addr, &error) !=
			    DW_DLV_OK) {
				warnx("%s", dwarf_errmsg(error));
				goto cont;
			}
			base0 = v_addr;

			if (strcmp(desc->dtpd_name, "entry") == 0) {
				/*
				 * Trace the first instruction of the first
				 * range since this is the beginning of the
				 * inline copy.
				 */
				noff = 1;
			} else if (strcmp(desc->dtpd_name, "return") == 0) {
				/*
				 * Trace the last instruction of every range in
				 * case the inline copy is split into multiple
				 * ranges (e.g if it has early `return`s).
				 */
				noff = nranges - 1;
			}
			off = emalloc(noff * sizeof(struct off));
			for (i = 0; i < noff; i++) {
				rp = &ranges[i];
				if (rp->dwr_type == DW_RANGES_ADDRESS_SELECTION)
					base0 = rp->dwr_addr2;
				dt_sugar_kinst_find_caller_func(&off[i],
				    rp->dwr_addr1 + base0,
				    rp->dwr_addr2 + base0);
			}
			dwarf_ranges_dealloc(dbg, ranges, nranges);
		} else {
			/* DIE has high/low PC boundaries */
			res = dwarf_attr(die, DW_AT_low_pc, &attp, &error);
			if (res != DW_DLV_OK) {
				if (res == DW_DLV_ERROR)
					warnx("%s", dwarf_errmsg(error));
				goto cont;
			}
			if (dwarf_formaddr(attp, &v_addr, &error) != DW_DLV_OK) {
				warnx("%s", dwarf_errmsg(error));
				goto cont;
			}
			res = dwarf_attr(die, DW_AT_high_pc, &attp, &error);
			if (res != DW_DLV_OK) {
				if (res == DW_DLV_ERROR)
					warnx("%s", dwarf_errmsg(error));
				goto cont;
			}
			if (dwarf_formudata(attp, &v_udata, &error) !=
			    DW_DLV_OK) {
				warnx("%s", dwarf_errmsg(error));
				goto cont;
			}
			noff = 1;
			off = emalloc(noff * sizeof(struct off));
			dt_sugar_kinst_find_caller_func(off, v_addr,
			    v_addr + v_udata);
		}
	} else
		goto cont;

	e = emalloc(sizeof(struct entry));
	e->noff = noff;
	e->off = off;
	TAILQ_INSERT_TAIL(&head, e, next);
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
		g_dieoff = dieoff;
		flag = F_INLINE_COPY;
		f_inline = 1;
	}

	res = dwarf_child(die, &die_next, &error);
	if (res == DW_DLV_ERROR)
		warnx("%s", dwarf_errmsg(error));
	else if (res == DW_DLV_OK)
		dt_sugar_kinst_parse_die(dbg, die_next, level + 1, flag);

	res = dwarf_siblingof(dbg, die, &die_next, &error);
	if (res == DW_DLV_ERROR)
		warnx("%s", dwarf_errmsg(error));
	else if (res == DW_DLV_OK)
		dt_sugar_kinst_parse_die(dbg, die_next, level, flag);

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
 * For example, if foo() is an inline function, and bar() is an inline copy of
 * it called from function baz() at offsets 10 and 20 respectively, we'll
 * transform the parse tree from:
 *
 *	kinst::foo:<entry/return> /pred/{ acts }
 *
 * To:
 *
 *	kinst::baz:10 /pred/{ acts }
 *	kinst::baz:20 /pred/{ acts }
 */
static void
dt_sugar_kinst_create_probes(dt_sugar_parse_t *dp, dt_node_t *dnp)
{
	dt_node_t *pdesc, *dcopy, *dcopyhead, *p, *q;
	struct entry *e;
	char buf[DTRACE_FULLNAMELEN];
	int i, j = 0;

	/*
	 * Perform a deep copy of the predicates and actions so that we can
	 * clone them when we create new clauses for inline copies. If we don't
	 * have a deep copy we'll end up in an infinite loop when we start
	 * appending clauses to the clause list.
	 */
	p = dp->dtsp_clause_list;
	dcopy = NULL;
	if (p != NULL) {
		dcopy = dt_node_xalloc(dp->dtsp_dtp, p->dn_kind);
		dcopyhead = dcopy;
		for (q = p; q != NULL; q = q->dn_list) {
			dcopy->dn_pred = NULL;
			dcopy->dn_acts = NULL;

			if (q->dn_pred != NULL)
				dcopy->dn_pred = q->dn_pred;
			if (q->dn_acts != NULL)
				dcopy->dn_acts = q->dn_acts;
			if (q->dn_list != NULL) {
				/* XXX are we leaking memory? */
				dcopy->dn_list = dt_node_xalloc(dp->dtsp_dtp,
				    q->dn_kind);
				dcopy = dcopy->dn_list;
			}
		}
		dcopy = NULL;
		dcopy = dcopyhead;
	}

	/* Clean up as well */
	while (!TAILQ_EMPTY(&head)) {
		e = TAILQ_FIRST(&head);
		TAILQ_REMOVE(&head, e, next);
		for (i = 0; i < e->noff; i++) {
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
				 * around this, we're replacing the requested
				 * probe's <function> and <offset> fields with
				 * the very first inline copy's information.
				 */
				snprintf(buf, sizeof(buf), "%lu", e->off[i].val);
				strcpy(desc->dtpd_func, e->off[i].func);
				strcpy(desc->dtpd_name, buf);
			} else {
				/*
				 * Create new clauses for each inline copy with
				 * the requested probe's predicates and
				 * actions.
				 */
				snprintf(buf, sizeof(buf), "%s:%s:%s:%lu",
				    desc->dtpd_provider,
				    desc->dtpd_mod,
				    e->off[i].func, e->off[i].val);
				pdesc = dt_node_pdesc_by_name(strdup(buf));

				/* Clone all predicates and actions. */
				for (p = dcopy; p != NULL; p = p->dn_list) {
					dt_sugar_append_clause(dp,
					    dt_node_clause(pdesc,
					    p->dn_pred, p->dn_acts));
				}
			}
		}
		free(e->off);
		free(e);
	}
}

/*
 * Initialize libelf and libdwarf and parse kernel.debug's DWARF info.
 */
static void
dt_sugar_do_kinst_inline(dt_sugar_parse_t *dp, dt_node_t *dnp)
{
	Dwarf_Debug dbg;
	Dwarf_Die die;
	Dwarf_Error error;
	Elf_Scn *scn;
	GElf_Shdr sh;
	struct section *s;
	const char *file = "/usr/lib/debug/boot/kernel/kernel.debug";
	size_t shstrndx, ndx;
	int fd, res = DW_DLV_OK;

	/* We only make entry and return probes for inline functions. */
	if (strcmp(desc->dtpd_name, "entry") != 0 &&
	    strcmp(desc->dtpd_name, "return") != 0)
		return;

	f_entry_or_return = 1;

	if (elf_version(EV_CURRENT) == EV_NONE)
		errx(1, "elf_version(): %s", elf_errmsg(-1));
	if ((fd = open(file, O_RDONLY)) < 0)
		err(1, "open(%s)", file);
	if ((ei.elf = elf_begin(fd, ELF_C_READ, NULL)) == NULL)
		errx(1, "elf_begin(): %s", elf_errmsg(-1));
	if (elf_kind(ei.elf) == ELF_K_NONE)
		errx(1, "not an ELF file: %s", file);
	if (dwarf_elf_init(ei.elf, DW_DLC_READ, NULL, NULL, &dbg, &error) !=
	    DW_DLV_OK)
		errx(1, "dwarf_elf_init(): %s", dwarf_errmsg(error));

	/* Load ELF sections */
	if (!elf_getshnum(ei.elf, &ei.shnum))
		errx(1, "elf_getshnum(): %s", elf_errmsg(-1));
	if ((ei.sl = calloc(ei.shnum, sizeof(struct section))) == NULL)
		err(1, "calloc");
	if (!elf_getshstrndx(ei.elf, &shstrndx))
		errx(1, "elf_getshstrndx(): %s", elf_errmsg(-1));
	if ((scn = elf_getscn(ei.elf, 0)) == NULL)
		err(1, "elf_getscn(): %s", elf_errmsg(-1));
	(void)elf_errno();

	do {
		if (gelf_getshdr(scn, &sh) == NULL) {
			warnx("gelf_getshdr(): %s", elf_errmsg(-1));
			(void)elf_errno();
			continue;
		}
		if ((ndx = elf_ndxscn(scn)) == SHN_UNDEF && elf_errno() != 0) {
			warnx("elf_ndxscn(): %s", elf_errmsg(-1));
			continue;
		}
		if (ndx >= ei.shnum)
			continue;
		s = &ei.sl[ndx];
		s->scn = scn;
		s->sz = sh.sh_size;
		s->entsize = sh.sh_entsize;
		s->type = sh.sh_type;
		s->link = sh.sh_link;
	} while ((scn = elf_nextscn(ei.elf, scn)) != NULL);
	if (elf_errno() != 0)
		warnx("elf_nextscn(): %s", elf_errmsg(-1));

	TAILQ_INIT(&head);
	/*
	 * Parse DWARF info for kernel.debug and create entries for the inline
	 * copies we'll create probes for.
	 */
	do {
		while ((res = dwarf_next_cu_header(dbg, NULL, NULL, NULL, NULL,
		    NULL, &error)) == DW_DLV_OK) {
			die = NULL;
			while (dwarf_siblingof(dbg, die, &die, &error) ==
			    DW_DLV_OK) {
				dt_sugar_kinst_parse_die(dbg, die, 0,
				    F_SUBPROGRAM);
			}
			dwarf_dealloc(dbg, die, DW_DLA_DIE);
		}
		if (res == DW_DLV_ERROR)
			warnx("%s", dwarf_errmsg(error));
	} while (dwarf_next_types_section(dbg, &error) == DW_DLV_OK);

	free(ei.sl);
	elf_end(ei.elf);
	dwarf_finish(dbg, &error);
	close(fd);
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
		break;

	case DT_NODE_PDESC:
		if (strcmp(dnp->dn_desc->dtpd_provider, "kinst") == 0) {
			dp->dtsp_kinst = 1;
			desc = dnp->dn_desc;
			dt_sugar_do_kinst_inline(dp, dnp);
		}
		break;

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

	if (dp.dtsp_kinst) {
		if (f_inline)
			dt_sugar_kinst_create_probes(&dp, clause);
		else if (!f_inline && f_entry_or_return) {
			/*
			 * Delegate non-inline function probes to FBT so that
			 * we don't duplicate FBT code in kinst.
			 */
			strlcpy(desc->dtpd_provider, "fbt",
			    sizeof(desc->dtpd_provider));
		}
	}

	if (dp.dtsp_clause_list != NULL &&
	    dp.dtsp_clause_list->dn_list != NULL && !dtp->dt_has_sugar) {
		dtp->dt_has_sugar = B_TRUE;
		dt_sugar_prepend_clause(&dp, dt_sugar_makeerrorclause());
	}

	return (dp.dtsp_clause_list);
}
