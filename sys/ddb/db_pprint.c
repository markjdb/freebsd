/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2022  <bojan.novkovic@kset.org>
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

#include <ddb/ddb.h>
#include <ddb/db_access.h>
#include <ddb/db_ctf.h>
#include <ddb/db_lex.h>
#include <ddb/db_sym.h>

#define DB_PPRINT_DEFAULT_DEPTH 1

static void db_pprint_type(db_addr_t addr, struct ctf_type_v3 *type,
    u_int depth);

static u_int max_depth = DB_PPRINT_DEFAULT_DEPTH;
static struct db_ctf_sym_data sym_data;

static inline void
db_pprint_int(db_addr_t addr, struct ctf_type_v3 *type)
{
	size_t type_struct_size = ((type->ctt_size == CTF_V3_LSIZE_SENT) ?
		sizeof(struct ctf_type_v3) :
		sizeof(struct ctf_stype_v3));
	uint32_t data = db_get_value((db_expr_t)type + type_struct_size,
	    sizeof(uint32_t), 0);

	u_int bits = CTF_INT_BITS(data);
	boolean_t sign = !!(CTF_INT_ENCODING(data) & CTF_INT_SIGNED);

	if (db_pager_quit) {
		return;
	}

	if (bits > 64) {
		db_printf("Invalid size '%d' found for integer type\n", bits);
		return;
	}

	int nbytes = (bits / 8) ? (bits / 8) : 1;
	db_printf("0x%lx", db_get_value(addr, nbytes, sign));
}

static inline void
db_pprint_struct(db_addr_t addr, struct ctf_type_v3 *type, u_int depth)
{
	const char *mname;

	size_t type_struct_size = ((type->ctt_size == CTF_V3_LSIZE_SENT) ?
		sizeof(struct ctf_type_v3) :
		sizeof(struct ctf_stype_v3));
	size_t struct_size = ((type->ctt_size == CTF_V3_LSIZE_SENT) ?
		CTF_TYPE_LSIZE(type) :
		type->ctt_size);
	u_int vlen = CTF_V3_INFO_VLEN(type->ctt_info);

	if (db_pager_quit) {
		return;
	}

	if (depth > max_depth) {
		db_printf("{ ... }, ");
		return;
	}

	db_printf("{\n");

	if (struct_size < CTF_V3_LSTRUCT_THRESH) {
		struct ctf_member_v3 *mp, *endp;

		mp = (struct ctf_member_v3 *)((db_addr_t)type +
		    type_struct_size);
		endp = mp + vlen;

		for (; mp < endp; mp++) {
			if (db_pager_quit) {
				return;
			}

			struct ctf_type_v3 *mtype =
			    db_ctf_typeid_to_type(&sym_data, mp->ctm_type);
			db_addr_t maddr = addr + mp->ctm_offset;

			mname = db_ctf_stroff_to_str(&sym_data, mp->ctm_name);
			if (mname) {
				db_printf("%s = ", mname);
			}

			db_pprint_type(maddr, mtype, depth + 1);
			db_printf(", ");
		}
	} else {
		struct ctf_lmember_v3 *mp, *endp;
		mp = (struct ctf_lmember_v3 *)((db_addr_t)type +
		    type_struct_size);
		endp = mp + vlen;

		for (; mp < endp; mp++) {
			if (db_pager_quit) {
				return;
			}

			struct ctf_type_v3 *mtype =
			    db_ctf_typeid_to_type(&sym_data, mp->ctlm_type);
			db_addr_t maddr = addr + CTF_LMEM_OFFSET(mp);

			mname = db_ctf_stroff_to_str(&sym_data, mp->ctlm_name);
			if (mname) {
				db_printf("%s = ", mname);
			}

			db_pprint_type(maddr, mtype, depth + 1);
			db_printf(", ");
		}
	}

	db_printf("\n}");
}

static inline void
db_pprint_arr(db_addr_t addr, struct ctf_type_v3 *type, u_int depth)
{
	struct ctf_array_v3 *arr;
	struct ctf_type_v3 *elem_type;
	size_t elem_size;
	size_t type_struct_size = ((type->ctt_size == CTF_V3_LSIZE_SENT) ?
		sizeof(struct ctf_type_v3) :
		sizeof(struct ctf_stype_v3));

	arr = (struct ctf_array_v3 *)((db_addr_t)type + type_struct_size);
	elem_type = db_ctf_typeid_to_type(&sym_data, arr->cta_contents);
	elem_size = ((elem_type->ctt_size == CTF_V3_LSIZE_SENT) ?
		CTF_TYPE_LSIZE(elem_type) :
		elem_type->ctt_size);

	db_addr_t elem_addr = addr;
	db_addr_t end = addr + (arr->cta_nelems * elem_size);

	db_printf("[");
	for (; elem_addr < end; elem_addr += elem_size) {
		if (db_pager_quit) {
			return;
		}

		db_pprint_type(elem_addr, elem_type, depth);

		if ((elem_addr + elem_size) < end) {
			db_printf(", ");
		}
	}
	db_printf("]\n");
}

static inline void
db_pprint_enum(db_addr_t addr, struct ctf_type_v3 *type)
{
	struct ctf_enum *ep, *endp;
	const char *valname;
	u_int vlen = CTF_V3_INFO_VLEN(type->ctt_info);
	db_expr_t val = db_get_value(addr, sizeof(int), 0);
	size_t type_struct_size = ((type->ctt_size == CTF_V3_LSIZE_SENT) ?
		sizeof(struct ctf_type_v3) :
		sizeof(struct ctf_stype_v3));

	if (db_pager_quit) {
		return;
	}

	ep = (struct ctf_enum *)((db_addr_t)type + type_struct_size);
	endp = ep + vlen;

	for (; ep < endp; ep++) {
		if (val == ep->cte_value) {
			valname = db_ctf_stroff_to_str(&sym_data, ep->cte_name);
			if (valname) {
				db_printf("%s ", valname);
			}

			db_printf("(0x%lx)", val);
			break;
		}
	}
}

static inline void
db_pprint_ptr(db_addr_t addr, struct ctf_type_v3 *type, u_int depth)
{
	const char *qual = "";
	const char *name;
	struct ctf_type_v3 *ref_type;
	u_int kind;
	db_addr_t val;

	ref_type = db_ctf_typeid_to_type(&sym_data, type->ctt_type);
	kind = CTF_V3_INFO_KIND(ref_type->ctt_info);

	switch (kind) {
	case CTF_K_STRUCT:
		qual = "struct ";
		break;
	case CTF_K_VOLATILE:
		qual = "volatile ";
		break;
	case CTF_K_CONST:
		qual = "const ";
		break;
	default:
		break;
	}

	val = db_get_value(addr, sizeof(db_addr_t), false);

	if (depth < max_depth) {
		db_pprint_type(addr, ref_type, depth + 1);
	} else {

		name = db_ctf_stroff_to_str(&sym_data, ref_type->ctt_name);
		if (name) {
			db_printf("(%s%s *)", qual, name);
		}

		db_printf("0x%lx", val);
	}
}

static void
db_pprint_type(db_addr_t addr, struct ctf_type_v3 *type, u_int depth)
{

	if (db_pager_quit) {
		return;
	}

	if (type == NULL) {
		db_printf("unknown type");
		return;
	}

	switch (CTF_V3_INFO_KIND(type->ctt_info)) {
	case CTF_K_INTEGER:
		db_pprint_int(addr, type);
		break;
	case CTF_K_UNION:
	case CTF_K_STRUCT:
		db_pprint_struct(addr, type, depth);
		break;
	case CTF_K_FUNCTION:
	case CTF_K_FLOAT:
		db_printf("0x%lx", addr);
		break;
	case CTF_K_POINTER:
		db_pprint_ptr(addr, type, depth);
		break;
	case CTF_K_TYPEDEF:
	case CTF_K_VOLATILE:
	case CTF_K_RESTRICT:
	case CTF_K_CONST: {
		struct ctf_type_v3 *ref_type = db_ctf_typeid_to_type(&sym_data,
		    type->ctt_type);
		db_pprint_type(addr, ref_type, depth);
		break;
	}
	case CTF_K_ENUM:
		db_pprint_enum(addr, type);
		break;
	case CTF_K_ARRAY:
		db_pprint_arr(addr, type, depth);
		break;
	case CTF_K_UNKNOWN:
	case CTF_K_FORWARD:
	default:
		break;
	}
}

static int
db_pprint_symbol(void)
{
	db_addr_t addr = sym_data.sym->st_value;
	struct ctf_type_v3 *type = NULL;
	db_expr_t _val;

	const char *sym_name = NULL;
	const char *type_name = NULL;

	if (db_pager_quit) {
		return -1;
	}

	type = db_ctf_sym_to_type(&sym_data);
	if (!type) {
		db_printf("Cant find CTF type info\n");
		return -1;
	}

	db_symbol_values((c_db_sym_t)sym_data.sym, &sym_name, &_val);
	type_name = db_ctf_stroff_to_str(&sym_data, type->ctt_name);

	if (type_name) {
		db_printf("%s ", type_name);
	}
	if (sym_name) {
		db_printf("%s = ", sym_name);
	}

	db_pprint_type(addr, type, 0);

	return 0;
}

/*
 * Pretty print an address.
 * Syntax: pprint [/d depth] addr
 */
void
db_pprint_cmd(db_expr_t addr, bool have_addr, db_expr_t count, char *modif)
{
	int t = 0;

	/* Set default depth */
	max_depth = DB_PPRINT_DEFAULT_DEPTH;

	/* Parse print modifiers */
	t = db_read_token();
	if (t == tSLASH) {
		t = db_read_token();
		if (t != tIDENT) {
			db_error("Invalid flag passed\n");
		}
		/* Fetch desired depth level */
		if (!strcmp(db_tok_string, "d")) {
			t = db_read_token();
			if (t != tNUMBER) {
				db_error("Invalid depth provided\n");
			}
			max_depth = db_tok_number;
		} else {
			db_error("Invalid flag passed\n");
		}
		/* Fetch next token */
		t = db_read_token();
	}

	if (t != tNUMBER) {
		db_error("No address supplied\n");
	}

	bzero(&sym_data, sizeof(sym_data));
	addr = db_tok_number;
	if (db_ctf_find_symbol(addr, &sym_data)) {
		db_error("Symbol not found\n");
	}

	if (ELF_ST_TYPE(sym_data.sym->st_info) != STT_OBJECT) {
		db_error("Symbol is not a variable\n");
	}

	if (db_pprint_symbol()) {
		db_error("");
	}
}
