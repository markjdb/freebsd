/*-
 * Copyright (c) 2002-2009 Luigi Rizzo, Universita` di Pisa
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
 *
 * $FreeBSD: projects/ipfw/sys/netpfil/ipfw/ip_fw_private.h 267467 2014-06-14 10:58:39Z melifaro $
 */

#ifndef _IPFW2_TABLE_H
#define _IPFW2_TABLE_H

/*
 * Internal constants and data structures used by ipfw tables
 * not meant to be exported outside the kernel.
 */
#ifdef _KERNEL

struct table_info {
	table_lookup_t	*lookup;	/* Lookup function */
	void		*state;		/* Lookup radix/other structure */
	void		*xstate;	/* eXtended state */
	u_long		data;		/* Hints for given func */
};

/* Internal structures for handling sockopt data */
struct tid_info {
	uint32_t	set;	/* table set */
	uint16_t	uidx;	/* table index */
	uint8_t		type;	/* table type */
	uint8_t		atype;
	void		*tlvs;	/* Pointer to first TLV */
	int		tlen;	/* Total TLV size block */
};

struct tentry_info {
	void		*paddr;
	uint8_t		masklen;	/* mask length			*/
	uint8_t		subtype;
	uint16_t	flags;		/* record flags			*/
	uint32_t	value;		/* value			*/
};
#define	TEI_FLAGS_UPDATE	0x01	/* Add or update rec if exists	*/
#define	TEI_FLAGS_UPDATED	0x02	/* Entry has been updated	*/
#define	TEI_FLAGS_COMPAT	0x04	/* Called from old ABI		*/
#define	TEI_FLAGS_DONTADD	0x08	/* Do not create new rec	*/

typedef int (ta_init)(struct ip_fw_chain *ch, void **ta_state,
    struct table_info *ti, char *data, uint8_t tflags);
typedef void (ta_destroy)(void *ta_state, struct table_info *ti);
typedef int (ta_prepare_add)(struct ip_fw_chain *ch, struct tentry_info *tei,
    void *ta_buf);
typedef int (ta_prepare_del)(struct ip_fw_chain *ch, struct tentry_info *tei,
    void *ta_buf);
typedef int (ta_add)(void *ta_state, struct table_info *ti,
    struct tentry_info *tei, void *ta_buf, uint32_t *pnum);
typedef int (ta_del)(void *ta_state, struct table_info *ti,
    struct tentry_info *tei, void *ta_buf, uint32_t *pnum);
typedef void (ta_flush_entry)(struct ip_fw_chain *ch, struct tentry_info *tei,
    void *ta_buf);

typedef int (ta_has_space)(void *ta_state, struct table_info *ti,
    uint32_t count, uint64_t *pflags);
typedef int (ta_prepare_mod)(void *ta_buf, uint64_t *pflags);
typedef int (ta_fill_mod)(void *ta_state, struct table_info *ti,
    void *ta_buf, uint64_t *pflags);
typedef int (ta_modify)(void *ta_state, struct table_info *ti,
    void *ta_buf, uint64_t pflags);
typedef void (ta_flush_mod)(void *ta_buf);

typedef void (ta_change_ti)(void *ta_state, struct table_info *ti);
typedef void (ta_print_config)(void *ta_state, struct table_info *ti, char *buf,
    size_t bufsize);

typedef int ta_foreach_f(void *node, void *arg);
typedef void ta_foreach(void *ta_state, struct table_info *ti, ta_foreach_f *f,
  void *arg);
typedef int ta_dump_tentry(void *ta_state, struct table_info *ti, void *e,
    ipfw_obj_tentry *tent);
typedef int ta_find_tentry(void *ta_state, struct table_info *ti,
    ipfw_obj_tentry *tent);
typedef void ta_dump_tinfo(void *ta_state, struct table_info *ti, 
    ipfw_ta_tinfo *tinfo);

struct table_algo {
	char		name[16];
	uint32_t	idx;
	uint32_t	type;
	uint32_t	refcnt;
	uint32_t	flags;
	size_t		ta_buf_size;
	ta_init		*init;
	ta_destroy	*destroy;
	ta_prepare_add	*prepare_add;
	ta_prepare_del	*prepare_del;
	ta_add		*add;
	ta_del		*del;
	ta_flush_entry	*flush_entry;
	ta_find_tentry	*find_tentry;
	ta_has_space	*has_space;
	ta_prepare_mod	*prepare_mod;
	ta_fill_mod	*fill_mod;
	ta_modify	*modify;
	ta_flush_mod	*flush_mod;
	ta_change_ti	*change_ti;
	ta_foreach	*foreach;
	ta_dump_tentry	*dump_tentry;
	ta_print_config	*print_config;
	ta_dump_tinfo	*dump_tinfo;
};
#define	TA_FLAG_DEFAULT	0x01	/* Algorithm is default for given type */

int ipfw_add_table_algo(struct ip_fw_chain *ch, struct table_algo *ta,
    size_t size, int *idx);
void ipfw_del_table_algo(struct ip_fw_chain *ch, int idx);

void ipfw_table_algo_init(struct ip_fw_chain *chain);
void ipfw_table_algo_destroy(struct ip_fw_chain *chain);


/* direct ipfw_ctl handlers */
int ipfw_list_tables(struct ip_fw_chain *ch, struct sockopt_data *sd);
int ipfw_dump_table(struct ip_fw_chain *ch, ip_fw3_opheader *op3,
    struct sockopt_data *sd);
int ipfw_describe_table(struct ip_fw_chain *ch, struct sockopt_data *sd);

int ipfw_find_table_entry(struct ip_fw_chain *ch, ip_fw3_opheader *op3,
    struct sockopt_data *sd);
int ipfw_create_table(struct ip_fw_chain *ch, ip_fw3_opheader *op3,
    struct sockopt_data *sd);
int ipfw_modify_table(struct ip_fw_chain *ch, ip_fw3_opheader *op3,
    struct sockopt_data *sd);
int ipfw_manage_table_ent(struct ip_fw_chain *ch, ip_fw3_opheader *op3,
    struct sockopt_data *sd);
int ipfw_flush_table(struct ip_fw_chain *ch, ip_fw3_opheader *op3,
    struct sockopt_data *sd);
int ipfw_list_table_algo(struct ip_fw_chain *ch, struct sockopt_data *sd);
int ipfw_swap_table(struct ip_fw_chain *ch, ip_fw3_opheader *op3,
    struct sockopt_data *sd);
/* Exported to support legacy opcodes */
int add_table_entry(struct ip_fw_chain *ch, struct tid_info *ti,
    struct tentry_info *tei, uint32_t count);
int del_table_entry(struct ip_fw_chain *ch, struct tid_info *ti,
    struct tentry_info *tei, uint32_t count);
int flush_table(struct ip_fw_chain *ch, struct tid_info *ti);

int ipfw_rewrite_table_uidx(struct ip_fw_chain *chain,
    struct rule_check_info *ci);
int ipfw_rewrite_table_kidx(struct ip_fw_chain *chain,
    struct ip_fw_rule0 *rule);
int ipfw_mark_table_kidx(struct ip_fw_chain *chain, struct ip_fw *rule,
    uint32_t *bmask);
int ipfw_export_table_ntlv(struct ip_fw_chain *ch, uint16_t kidx,
    struct sockopt_data *sd);
void ipfw_unbind_table_rule(struct ip_fw_chain *chain, struct ip_fw *rule);

/* utility functions  */
int ipfw_check_table_name(char *name);
int ipfw_move_tables_sets(struct ip_fw_chain *ch, ipfw_range_tlv *rt,
    uint32_t new_set);
void ipfw_swap_tables_sets(struct ip_fw_chain *ch, uint32_t old_set,
    uint32_t new_set, int mv);

/* Legacy interfaces */
int ipfw_count_table(struct ip_fw_chain *ch, struct tid_info *ti,
    uint32_t *cnt);
int ipfw_count_xtable(struct ip_fw_chain *ch, struct tid_info *ti,
    uint32_t *cnt);
int ipfw_dump_table_legacy(struct ip_fw_chain *ch, struct tid_info *ti,
    ipfw_table *tbl);


#endif /* _KERNEL */
#endif /* _IPFW2_TABLE_H */
