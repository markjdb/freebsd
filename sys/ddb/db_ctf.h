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

#ifndef _DDB_DB_CTF_H_
#define _DDB_DB_CTF_H_

#include <sys/types.h>
#include <sys/ctf.h>
#include <sys/linker.h>

#include <ddb/db_sym.h>
#include <ddb/ddb.h>

#define DB_CTF_OBJTOFF_INVALID 0xffffffff

int db_ctf_register(linker_file_t module);
int db_ctf_unregister(linker_file_t module);

struct db_ctf_sym_data {
	linker_ctf_t *lc;
	Elf_Sym *sym;
};

typedef struct db_ctf_sym_data *db_ctf_sym_data_t;

struct ctf_type_v3 *db_ctf_sym_to_type(db_ctf_sym_data_t sd);
struct ctf_type_v3 *db_ctf_typeid_to_type(db_ctf_sym_data_t sd,
    uint32_t typeid);
const char *db_ctf_stroff_to_str(db_ctf_sym_data_t sd, uint32_t off);
int db_ctf_find_symbol(db_expr_t addr, db_ctf_sym_data_t sd);
void db_ctf_init_kctf(vm_offset_t ksymtab, vm_offset_t kstrtab,
    vm_offset_t ksymtab_size);
linker_ctf_t *db_ctf_fetch_kctf(void);

#endif /* !_DDB_DB_CTF_H_ */
