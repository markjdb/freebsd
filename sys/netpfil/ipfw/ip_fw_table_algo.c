/*-
 * Copyright (c) 2004 Ruslan Ermilov and Vsevolod Lobko.
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
__FBSDID("$FreeBSD: projects/ipfw/sys/netpfil/ipfw/ip_fw_table.c 267384 2014-06-12 09:59:11Z melifaro $");

/*
 * Lookup table algorithms.
 *
 */

#include "opt_ipfw.h"
#include "opt_inet.h"
#ifndef INET
#error IPFIREWALL requires INET.
#endif /* INET */
#include "opt_inet6.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/rwlock.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <net/if.h>	/* ip_fw.h requires IFNAMSIZ */
#include <net/radix.h>
#include <net/route.h>
#include <net/vnet.h>

#include <netinet/in.h>
#include <netinet/ip_var.h>	/* struct ipfw_rule_ref */
#include <netinet/ip_fw.h>

#include <netpfil/ipfw/ip_fw_private.h>
#include <netpfil/ipfw/ip_fw_table.h>

static MALLOC_DEFINE(M_IPFW_TBL, "ipfw_tbl", "IpFw tables");

static int badd(const void *key, void *item, void *base, size_t nmemb,
    size_t size, int (*compar) (const void *, const void *));
static int bdel(const void *key, void *base, size_t nmemb, size_t size,
    int (*compar) (const void *, const void *));


/*
 * CIDR implementation using radix
 *
 */

/*
 * The radix code expects addr and mask to be array of bytes,
 * with the first byte being the length of the array. rn_inithead
 * is called with the offset in bits of the lookup key within the
 * array. If we use a sockaddr_in as the underlying type,
 * sin_len is conveniently located at offset 0, sin_addr is at
 * offset 4 and normally aligned.
 * But for portability, let's avoid assumption and make the code explicit
 */
#define KEY_LEN(v)	*((uint8_t *)&(v))
/*
 * Do not require radix to compare more than actual IPv4/IPv6 address
 */
#define KEY_LEN_INET	(offsetof(struct sockaddr_in, sin_addr) + sizeof(in_addr_t))
#define KEY_LEN_INET6	(offsetof(struct sa_in6, sin6_addr) + sizeof(struct in6_addr))

#define OFF_LEN_INET	(8 * offsetof(struct sockaddr_in, sin_addr))
#define OFF_LEN_INET6	(8 * offsetof(struct sa_in6, sin6_addr))

struct radix_cidr_entry {
	struct radix_node	rn[2];
	struct sockaddr_in	addr;
	uint32_t		value;
	uint8_t			masklen;
};

struct sa_in6 {
	uint8_t			sin6_len;
	uint8_t			sin6_family;
	uint8_t			pad[2];
	struct in6_addr		sin6_addr;
};

struct radix_cidr_xentry {
	struct radix_node	rn[2];
	struct sa_in6		addr6;
	uint32_t		value;
	uint8_t			masklen;
};

static int
ta_lookup_radix(struct table_info *ti, void *key, uint32_t keylen,
    uint32_t *val)
{
	struct radix_node_head *rnh;

	if (keylen == sizeof(in_addr_t)) {
		struct radix_cidr_entry *ent;
		struct sockaddr_in sa;
		KEY_LEN(sa) = KEY_LEN_INET;
		sa.sin_addr.s_addr = *((in_addr_t *)key);
		rnh = (struct radix_node_head *)ti->state;
		ent = (struct radix_cidr_entry *)(rnh->rnh_matchaddr(&sa, rnh));
		if (ent != NULL) {
			*val = ent->value;
			return (1);
		}
	} else {
		struct radix_cidr_xentry *xent;
		struct sa_in6 sa6;
		KEY_LEN(sa6) = KEY_LEN_INET6;
		memcpy(&sa6.sin6_addr, key, sizeof(struct in6_addr));
		rnh = (struct radix_node_head *)ti->xstate;
		xent = (struct radix_cidr_xentry *)(rnh->rnh_matchaddr(&sa6, rnh));
		if (xent != NULL) {
			*val = xent->value;
			return (1);
		}
	}

	return (0);
}

/*
 * New table
 */
static int
ta_init_radix(struct ip_fw_chain *ch, void **ta_state, struct table_info *ti,
    char *data)
{

	if (!rn_inithead(&ti->state, OFF_LEN_INET))
		return (ENOMEM);
	if (!rn_inithead(&ti->xstate, OFF_LEN_INET6)) {
		rn_detachhead(&ti->state);
		return (ENOMEM);
	}

	*ta_state = NULL;
	ti->lookup = ta_lookup_radix;

	return (0);
}

static int
flush_table_entry(struct radix_node *rn, void *arg)
{
	struct radix_node_head * const rnh = arg;
	struct radix_cidr_entry *ent;

	ent = (struct radix_cidr_entry *)
	    rnh->rnh_deladdr(rn->rn_key, rn->rn_mask, rnh);
	if (ent != NULL)
		free(ent, M_IPFW_TBL);
	return (0);
}

static void
ta_destroy_radix(void *ta_state, struct table_info *ti)
{
	struct radix_node_head *rnh;

	rnh = (struct radix_node_head *)(ti->state);
	rnh->rnh_walktree(rnh, flush_table_entry, rnh);
	rn_detachhead(&ti->state);

	rnh = (struct radix_node_head *)(ti->xstate);
	rnh->rnh_walktree(rnh, flush_table_entry, rnh);
	rn_detachhead(&ti->xstate);
}

static int
ta_dump_radix_tentry(void *ta_state, struct table_info *ti, void *e,
    ipfw_obj_tentry *tent)
{
	struct radix_cidr_entry *n;
	struct radix_cidr_xentry *xn;

	n = (struct radix_cidr_entry *)e;

	/* Guess IPv4/IPv6 radix by sockaddr family */
	if (n->addr.sin_family == AF_INET) {
		tent->k.addr.s_addr = n->addr.sin_addr.s_addr;
		tent->masklen = n->masklen;
		tent->subtype = AF_INET;
		tent->value = n->value;
#ifdef INET6
	} else {
		xn = (struct radix_cidr_xentry *)e;
		memcpy(&tent->k, &xn->addr6.sin6_addr, sizeof(struct in6_addr));
		tent->masklen = xn->masklen;
		tent->subtype = AF_INET6;
		tent->value = xn->value;
#endif
	}

	return (0);
}

static int
ta_find_radix_tentry(void *ta_state, struct table_info *ti, void *key,
    uint32_t keylen, ipfw_obj_tentry *tent)
{
	struct radix_node_head *rnh;
	void *e;

	e = NULL;
	if (keylen == sizeof(in_addr_t)) {
		struct sockaddr_in sa;
		KEY_LEN(sa) = KEY_LEN_INET;
		sa.sin_addr.s_addr = *((in_addr_t *)key);
		rnh = (struct radix_node_head *)ti->state;
		e = rnh->rnh_matchaddr(&sa, rnh);
	} else {
		struct sa_in6 sa6;
		KEY_LEN(sa6) = KEY_LEN_INET6;
		memcpy(&sa6.sin6_addr, key, sizeof(struct in6_addr));
		rnh = (struct radix_node_head *)ti->xstate;
		e = rnh->rnh_matchaddr(&sa6, rnh);
	}

	if (e != NULL) {
		ta_dump_radix_tentry(ta_state, ti, e, tent);
		return (0);
	}

	return (ENOENT);
}

static void
ta_foreach_radix(void *ta_state, struct table_info *ti, ta_foreach_f *f,
    void *arg)
{
	struct radix_node_head *rnh;

	rnh = (struct radix_node_head *)(ti->state);
	rnh->rnh_walktree(rnh, (walktree_f_t *)f, arg);

	rnh = (struct radix_node_head *)(ti->xstate);
	rnh->rnh_walktree(rnh, (walktree_f_t *)f, arg);
}


struct ta_buf_cidr 
{
	struct sockaddr	*addr_ptr;
	struct sockaddr	*mask_ptr;
	void *ent_ptr;
	union {
		struct {
			struct sockaddr_in sa;
			struct sockaddr_in ma;
		} a4;
		struct {
			struct sa_in6 sa;
			struct sa_in6 ma;
		} a6;
	} addr;
};

#ifdef INET6
static inline void
ipv6_writemask(struct in6_addr *addr6, uint8_t mask)
{
	uint32_t *cp;

	for (cp = (uint32_t *)addr6; mask >= 32; mask -= 32)
		*cp++ = 0xFFFFFFFF;
	*cp = htonl(mask ? ~((1 << (32 - mask)) - 1) : 0);
}
#endif


static int
ta_prepare_add_cidr(struct ip_fw_chain *ch, struct tentry_info *tei,
    void *ta_buf)
{
	struct ta_buf_cidr *tb;
	struct radix_cidr_entry *ent;
	struct radix_cidr_xentry *xent;
	in_addr_t addr;
	struct sockaddr_in *mask;
	struct sa_in6 *mask6;
	int mlen;

	tb = (struct ta_buf_cidr *)ta_buf;
	memset(tb, 0, sizeof(struct ta_buf_cidr));

	mlen = tei->masklen;
	
	if (tei->subtype == AF_INET) {
#ifdef INET
		if (mlen > 32)
			return (EINVAL);
		ent = malloc(sizeof(*ent), M_IPFW_TBL, M_WAITOK | M_ZERO);
		ent->value = tei->value;
		mask = &tb->addr.a4.ma;
		/* Set 'total' structure length */
		KEY_LEN(ent->addr) = KEY_LEN_INET;
		KEY_LEN(*mask) = KEY_LEN_INET;
		ent->addr.sin_family = AF_INET;
		mask->sin_addr.s_addr =
		    htonl(mlen ? ~((1 << (32 - mlen)) - 1) : 0);
		addr = *((in_addr_t *)tei->paddr);
		ent->addr.sin_addr.s_addr = addr & mask->sin_addr.s_addr;
		ent->masklen = mlen;
		/* Set pointers */
		tb->ent_ptr = ent;
		tb->addr_ptr = (struct sockaddr *)&ent->addr;
		if (mlen != 32)
			tb->mask_ptr = (struct sockaddr *)mask;
#endif
#ifdef INET6
	} else if (tei->subtype == AF_INET6) {
		/* IPv6 case */
		if (mlen > 128)
			return (EINVAL);
		xent = malloc(sizeof(*xent), M_IPFW_TBL, M_WAITOK | M_ZERO);
		xent->value = tei->value;
		mask6 = &tb->addr.a6.ma;
		/* Set 'total' structure length */
		KEY_LEN(xent->addr6) = KEY_LEN_INET6;
		KEY_LEN(*mask6) = KEY_LEN_INET6;
		xent->addr6.sin6_family = AF_INET6;
		ipv6_writemask(&mask6->sin6_addr, mlen);
		memcpy(&xent->addr6.sin6_addr, tei->paddr,
		    sizeof(struct in6_addr));
		APPLY_MASK(&xent->addr6.sin6_addr, &mask6->sin6_addr);
		xent->masklen = mlen;
		/* Set pointers */
		tb->ent_ptr = xent;
		tb->addr_ptr = (struct sockaddr *)&xent->addr6;
		if (mlen != 128)
			tb->mask_ptr = (struct sockaddr *)mask6;
#endif
	} else {
		/* Unknown CIDR type */
		return (EINVAL);
	}

	return (0);
}

static int
ta_add_cidr(void *ta_state, struct table_info *ti, struct tentry_info *tei,
    void *ta_buf, uint64_t *pflags, uint32_t *pnum)
{
	struct radix_node_head *rnh;
	struct radix_node *rn;
	struct ta_buf_cidr *tb;
	uint32_t value;

	tb = (struct ta_buf_cidr *)ta_buf;

	if (tei->subtype == AF_INET)
		rnh = ti->state;
	else
		rnh = ti->xstate;

	rn = rnh->rnh_addaddr(tb->addr_ptr, tb->mask_ptr, rnh, tb->ent_ptr);
	
	if (rn == NULL) {
		if ((tei->flags & TEI_FLAGS_UPDATE) == 0)
			return (EEXIST);
		/* Record already exists. Update value if we're asked to */
		rn = rnh->rnh_lookup(tb->addr_ptr, tb->mask_ptr, rnh);
		if (rn == NULL) {

			/*
			 * Radix may have failed addition for other reasons
			 * like failure in mask allocation code.
			 */
			return (EINVAL);
		}
		
		if (tei->subtype == AF_INET) {
			/* IPv4. */
			value = ((struct radix_cidr_entry *)tb->ent_ptr)->value;
			((struct radix_cidr_entry *)rn)->value = value;
		} else {
			/* IPv6 */
			value = ((struct radix_cidr_xentry *)tb->ent_ptr)->value;
			((struct radix_cidr_xentry *)rn)->value = value;
		}

		/* Indicate that update has happened instead of addition */
		tei->flags |= TEI_FLAGS_UPDATED;
		*pnum = 0;

		return (0);
	}

	tb->ent_ptr = NULL;
	*pnum = 1;

	return (0);
}

static int
ta_prepare_del_cidr(struct ip_fw_chain *ch, struct tentry_info *tei,
    void *ta_buf)
{
	struct ta_buf_cidr *tb;
	struct sockaddr_in sa, mask;
	struct sa_in6 sa6, mask6;
	in_addr_t addr;
	int mlen;

	tb = (struct ta_buf_cidr *)ta_buf;
	memset(tb, 0, sizeof(struct ta_buf_cidr));

	mlen = tei->masklen;

	if (tei->subtype == AF_INET) {
		if (mlen > 32)
			return (EINVAL);
		memset(&sa, 0, sizeof(struct sockaddr_in));
		memset(&mask, 0, sizeof(struct sockaddr_in));
		/* Set 'total' structure length */
		KEY_LEN(sa) = KEY_LEN_INET;
		KEY_LEN(mask) = KEY_LEN_INET;
		mask.sin_addr.s_addr = htonl(mlen ? ~((1 << (32 - mlen)) - 1) : 0);
		addr = *((in_addr_t *)tei->paddr);
		sa.sin_addr.s_addr = addr & mask.sin_addr.s_addr;
		tb->addr.a4.sa = sa;
		tb->addr.a4.ma = mask;
		tb->addr_ptr = (struct sockaddr *)&tb->addr.a4.sa;
		if (mlen != 32)
			tb->mask_ptr = (struct sockaddr *)&tb->addr.a4.ma;
#ifdef INET6
	} else if (tei->subtype == AF_INET6) {
		if (mlen > 128)
			return (EINVAL);
		memset(&sa6, 0, sizeof(struct sa_in6));
		memset(&mask6, 0, sizeof(struct sa_in6));
		/* Set 'total' structure length */
		KEY_LEN(sa6) = KEY_LEN_INET6;
		KEY_LEN(mask6) = KEY_LEN_INET6;
		ipv6_writemask(&mask6.sin6_addr, mlen);
		memcpy(&sa6.sin6_addr, tei->paddr,
		    sizeof(struct in6_addr));
		APPLY_MASK(&sa6.sin6_addr, &mask6.sin6_addr);
		tb->addr.a6.sa = sa6;
		tb->addr.a6.ma = mask6;
		tb->addr_ptr = (struct sockaddr *)&tb->addr.a6.sa;
		if (mlen != 128)
			tb->mask_ptr = (struct sockaddr *)&tb->addr.a6.ma;
#endif
	} else
		return (EINVAL);

	return (0);
}

static int
ta_del_cidr(void *ta_state, struct table_info *ti, struct tentry_info *tei,
    void *ta_buf, uint64_t *pflags, uint32_t *pnum)
{
	struct radix_node_head *rnh;
	struct radix_node *rn;
	struct ta_buf_cidr *tb;

	tb = (struct ta_buf_cidr *)ta_buf;

	if (tei->subtype == AF_INET)
		rnh = ti->state;
	else
		rnh = ti->xstate;

	rn = rnh->rnh_deladdr(tb->addr_ptr, tb->mask_ptr, rnh);

	tb->ent_ptr = rn;
	
	if (rn == NULL)
		return (ENOENT);

	*pnum = 1;

	return (0);
}

static void
ta_flush_cidr_entry(struct ip_fw_chain *ch, struct tentry_info *tei,
    void *ta_buf)
{
	struct ta_buf_cidr *tb;

	tb = (struct ta_buf_cidr *)ta_buf;

	if (tb->ent_ptr != NULL)
		free(tb->ent_ptr, M_IPFW_TBL);
}

struct table_algo cidr_radix = {
	.name		= "cidr:radix",
	.type		= IPFW_TABLE_CIDR,
	.init		= ta_init_radix,
	.destroy	= ta_destroy_radix,
	.prepare_add	= ta_prepare_add_cidr,
	.prepare_del	= ta_prepare_del_cidr,
	.add		= ta_add_cidr,
	.del		= ta_del_cidr,
	.flush_entry	= ta_flush_cidr_entry,
	.foreach	= ta_foreach_radix,
	.dump_tentry	= ta_dump_radix_tentry,
	.find_tentry	= ta_find_radix_tentry,
};


/*
 * cidr:hash cmds
 *
 *
 * ti->data:
 * [inv.mask4][inv.mask6][log2hsize4][log2hsize6]
 * [        8][        8[          8][         8]
 *
 * inv.mask4: 32 - mask
 * inv.mask6:
 * 1) _slow lookup: mask
 * 2) _aligned: (128 - mask) / 8
 * 3) _64: 8
 */

struct chashentry;

SLIST_HEAD(chashbhead, chashentry);

struct chash_cfg {
	struct chashbhead *head4;
	struct chashbhead *head6;
	size_t	size4;
	size_t	size6;
	size_t	items;
	uint8_t	mask4;
	uint8_t	mask6;
};

struct chashentry {
	SLIST_ENTRY(chashentry)	next;
	uint32_t	value;
	uint32_t	type;
	union {
		uint32_t	a4;	/* Host format */
		struct in6_addr	a6;	/* Network format */
	} a;
};

static __inline uint32_t
hash_ip(uint32_t addr, int hsize)
{

	return (addr % (hsize - 1));
}

static __inline uint32_t
hash_ip6(struct in6_addr *addr6, int hsize)
{
	uint32_t i;

	i = addr6->s6_addr32[0] ^ addr6->s6_addr32[1] ^
	    addr6->s6_addr32[2] ^ addr6->s6_addr32[3];

	return (i % (hsize - 1));
}


static __inline uint16_t
hash_ip64(struct in6_addr *addr6, int hsize)
{
	uint32_t i;

	i = addr6->s6_addr32[0] ^ addr6->s6_addr32[1];

	return (i % (hsize - 1));
}


static __inline uint32_t
hash_ip6_slow(struct in6_addr *addr6, void *key, int mask, int hsize)
{
	struct in6_addr mask6;

	ipv6_writemask(&mask6, mask);
	memcpy(addr6, key, sizeof(struct in6_addr));
	APPLY_MASK(addr6, &mask6);
	return (hash_ip6(addr6, hsize));
}

static __inline uint32_t
hash_ip6_al(struct in6_addr *addr6, void *key, int mask, int hsize)
{
	uint64_t *paddr;

	paddr = (uint64_t *)addr6;
	*paddr = 0;
	*(paddr + 1) = 0;
	memcpy(addr6, key, mask);
	return (hash_ip6(addr6, hsize));
}

static int
ta_lookup_chash_slow(struct table_info *ti, void *key, uint32_t keylen,
    uint32_t *val)
{
	struct chashbhead *head;
	struct chashentry *ent;
	uint16_t hash, hsize;
	uint8_t imask;

	if (keylen == sizeof(in_addr_t)) {
		head = (struct chashbhead *)ti->state;
		imask = ti->data >> 24;
		hsize = 1 << ((ti->data & 0xFFFF) >> 8);
		uint32_t a;
		a = ntohl(*((in_addr_t *)key));
		a = a >> imask;
		hash = hash_ip(a, hsize);
		SLIST_FOREACH(ent, &head[hash], next) {
			if (ent->a.a4 == a) {
				*val = ent->value;
				return (1);
			}
		}
	} else {
		/* IPv6: worst scenario: non-round mask */
		struct in6_addr addr6;
		head = (struct chashbhead *)ti->xstate;
		imask = (ti->data & 0xFF0000) >> 16;
		hsize = 1 << (ti->data & 0xFF);
		hash = hash_ip6_slow(&addr6, key, imask, hsize);
		SLIST_FOREACH(ent, &head[hash], next) {
			if (memcmp(&ent->a.a6, &addr6, 16) == 0) {
				*val = ent->value;
				return (1);
			}
		}
	}

	return (0);
}

static int
ta_lookup_chash_aligned(struct table_info *ti, void *key, uint32_t keylen,
    uint32_t *val)
{
	struct chashbhead *head;
	struct chashentry *ent;
	uint16_t hash, hsize;
	uint8_t imask;

	if (keylen == sizeof(in_addr_t)) {
		head = (struct chashbhead *)ti->state;
		imask = ti->data >> 24;
		hsize = 1 << ((ti->data & 0xFFFF) >> 8);
		uint32_t a;
		a = ntohl(*((in_addr_t *)key));
		a = a >> imask;
		hash = hash_ip(a, hsize);
		SLIST_FOREACH(ent, &head[hash], next) {
			if (ent->a.a4 == a) {
				*val = ent->value;
				return (1);
			}
		}
	} else {
		/* IPv6: aligned to 8bit mask */
		struct in6_addr addr6;
		uint64_t *paddr, *ptmp;
		head = (struct chashbhead *)ti->xstate;
		imask = (ti->data & 0xFF0000) >> 16;
		hsize = 1 << (ti->data & 0xFF);

		hash = hash_ip6_al(&addr6, key, imask, hsize);
		paddr = (uint64_t *)&addr6;
		SLIST_FOREACH(ent, &head[hash], next) {
			ptmp = (uint64_t *)&ent->a.a6;
			if (paddr[0] == ptmp[0] && paddr[1] == ptmp[1]) {
				*val = ent->value;
				return (1);
			}
		}
	}

	return (0);
}

static int
ta_lookup_chash_64(struct table_info *ti, void *key, uint32_t keylen,
    uint32_t *val)
{
	struct chashbhead *head;
	struct chashentry *ent;
	uint16_t hash, hsize;
	uint8_t imask;

	if (keylen == sizeof(in_addr_t)) {
		head = (struct chashbhead *)ti->state;
		imask = ti->data >> 24;
		hsize = 1 << ((ti->data & 0xFFFF) >> 8);
		uint32_t a;
		a = ntohl(*((in_addr_t *)key));
		a = a >> imask;
		hash = hash_ip(a, hsize);
		SLIST_FOREACH(ent, &head[hash], next) {
			if (ent->a.a4 == a) {
				*val = ent->value;
				return (1);
			}
		}
	} else {
		/* IPv6: /64 */
		uint64_t a6, *paddr;
		head = (struct chashbhead *)ti->xstate;
		paddr = (uint64_t *)key;
		hsize = 1 << (ti->data & 0xFF);
		a6 = *paddr;
		hash = hash_ip64((struct in6_addr *)key, hsize);
		SLIST_FOREACH(ent, &head[hash], next) {
			paddr = (uint64_t *)&ent->a.a6;
			if (a6 == *paddr) {
				*val = ent->value;
				return (1);
			}
		}
	}

	return (0);
}

static int
chash_parse_opts(struct chash_cfg *ccfg, char *data)
{
	char *pdel, *pend, *s;
	int mask4, mask6;

	mask4 = ccfg->mask4;
	mask6 = ccfg->mask6;

	if (data == NULL)
		return (0);
	if ((pdel = strchr(data, ' ')) == NULL)
		return (0);
	while (*pdel == ' ')
		pdel++;
	if (strncmp(pdel, "masks=", 6) != 0)
		return (EINVAL);
	if ((s = strchr(pdel, ' ')) != NULL)
		*s++ = '\0';

	pdel += 6;
	/* Need /XX[,/YY] */
	if (*pdel++ != '/')
		return (EINVAL);
	mask4 = strtol(pdel, &pend, 10);
	if (*pend == ',') {
		/* ,/YY */
		pdel = pend + 1;
		if (*pdel++ != '/')
			return (EINVAL);
		mask6 = strtol(pdel, &pend, 10);
		if (*pend != '\0')
			return (EINVAL);
	} else if (*pend != '\0')
		return (EINVAL);

	if (mask4 < 0 || mask4 > 32 || mask6 < 0 || mask6 > 128)
		return (EINVAL);

	ccfg->mask4 = mask4;
	ccfg->mask6 = mask6;

	return (0);
}

static void
ta_print_chash_config(void *ta_state, struct table_info *ti, char *buf,
    size_t bufsize)
{
	struct chash_cfg *ccfg;

	ccfg = (struct chash_cfg *)ta_state;

	if (ccfg->mask4 != 32 || ccfg->mask6 != 128)
		snprintf(buf, bufsize, "%s masks=/%d,/%d", "cidr:hash",
		    ccfg->mask4, ccfg->mask6);
	else
		snprintf(buf, bufsize, "%s", "cidr:hash");
}


/*
 * New table.
 * We assume 'data' to be either NULL or the following format:
 * 'cidr:hash [masks=/32[,/128]]'
 */
static int
ta_init_chash(struct ip_fw_chain *ch, void **ta_state, struct table_info *ti,
    char *data)
{
	int error, i;
	int v4, v6;
	struct chash_cfg *ccfg;

	ccfg = malloc(sizeof(struct chash_cfg), M_IPFW, M_WAITOK | M_ZERO);

	ccfg->mask4 = 32;
	ccfg->mask6 = 128;

	if ((error = chash_parse_opts(ccfg, data)) != 0) {
		free(ccfg, M_IPFW);
		return (error);
	}

	v4 = 7;
	v6 = 7;
	ccfg->size4 = 1 << v4;
	ccfg->size6 = 1 << v6;

	ccfg->head4 = malloc(sizeof(struct chashbhead) * ccfg->size4, M_IPFW,
	    M_WAITOK | M_ZERO);
	ccfg->head6 = malloc(sizeof(struct chashbhead) * ccfg->size6, M_IPFW,
	    M_WAITOK | M_ZERO);
	for (i = 0; i < ccfg->size4; i++)
		SLIST_INIT(&ccfg->head4[i]);
	for (i = 0; i < ccfg->size6; i++)
		SLIST_INIT(&ccfg->head6[i]);


	*ta_state = ccfg;
	ti->state = ccfg->head4;
	ti->xstate = ccfg->head6;

	/* Store data depending on v6 mask length */
	if (ccfg->mask6 == 64) {
		ti->data = (32 - ccfg->mask4) << 24 | (128 - ccfg->mask6) << 16 |
		    v4 << 8 | v6;
		ti->lookup = ta_lookup_chash_64;
	} else if ((ccfg->mask6  % 8) == 0) {
		ti->data = (32 - ccfg->mask4) << 24 |
		    ccfg->mask6 << 13 | v4 << 8 | v6;
		ti->lookup = ta_lookup_chash_aligned;
	} else {
		/* don't do that! */
		ti->data = (32 - ccfg->mask4) << 24 |
		    ccfg->mask6 << 16 | v4 << 8 | v6;
		ti->lookup = ta_lookup_chash_slow;
	}

	return (0);
}

static void
ta_destroy_chash(void *ta_state, struct table_info *ti)
{
	struct chash_cfg *ccfg;
	struct chashentry *ent, *ent_next;
	int i;

	ccfg = (struct chash_cfg *)ta_state;

	for (i = 0; i < ccfg->size4; i++)
		SLIST_FOREACH_SAFE(ent, &ccfg->head4[i], next, ent_next)
			free(ent, M_IPFW_TBL);

	for (i = 0; i < ccfg->size6; i++)
		SLIST_FOREACH_SAFE(ent, &ccfg->head6[i], next, ent_next)
			free(ent, M_IPFW_TBL);

	free(ccfg->head4, M_IPFW);
	free(ccfg->head6, M_IPFW);
}

static int
ta_dump_chash_tentry(void *ta_state, struct table_info *ti, void *e,
    ipfw_obj_tentry *tent)
{
	struct chash_cfg *ccfg;
	struct chashentry *ent;

	ccfg = (struct chash_cfg *)ta_state;
	ent = (struct chashentry *)e;

	if (ent->type == AF_INET) {
		tent->k.addr.s_addr = htonl(ent->a.a4 << (32 - ccfg->mask4));
		tent->masklen = ccfg->mask4;
		tent->subtype = AF_INET;
		tent->value = ent->value;
#ifdef INET6
	} else {
		memcpy(&tent->k, &ent->a.a6, sizeof(struct in6_addr));
		tent->masklen = ccfg->mask6;
		tent->subtype = AF_INET6;
		tent->value = ent->value;
#endif
	}

	return (0);
}

static int
ta_find_chash_tentry(void *ta_state, struct table_info *ti, void *key,
    uint32_t keylen, ipfw_obj_tentry *tent)
{
#if 0
	struct radix_node_head *rnh;
	void *e;

	e = NULL;
	if (keylen == sizeof(in_addr_t)) {
		struct sockaddr_in sa;
		KEY_LEN(sa) = KEY_LEN_INET;
		sa.sin_addr.s_addr = *((in_addr_t *)key);
		rnh = (struct radix_node_head *)ti->state;
		e = rnh->rnh_matchaddr(&sa, rnh);
	} else {
		struct sa_in6 sa6;
		KEY_LEN(sa6) = KEY_LEN_INET6;
		memcpy(&sa6.sin6_addr, key, sizeof(struct in6_addr));
		rnh = (struct radix_node_head *)ti->xstate;
		e = rnh->rnh_matchaddr(&sa6, rnh);
	}

	if (e != NULL) {
		ta_dump_radix_tentry(ta_state, ti, e, tent);
		return (0);
	}
#endif
	return (ENOENT);
}

static void
ta_foreach_chash(void *ta_state, struct table_info *ti, ta_foreach_f *f,
    void *arg)
{
	struct chash_cfg *ccfg;
	struct chashentry *ent, *ent_next;
	int i;

	ccfg = (struct chash_cfg *)ta_state;

	for (i = 0; i < ccfg->size4; i++)
		SLIST_FOREACH_SAFE(ent, &ccfg->head4[i], next, ent_next)
			f(ent, arg);

	for (i = 0; i < ccfg->size6; i++)
		SLIST_FOREACH_SAFE(ent, &ccfg->head6[i], next, ent_next)
			f(ent, arg);
}


struct ta_buf_chash
{
	void *ent_ptr;
	int type;
	union {
		uint32_t	a4;
		struct in6_addr	a6;
	} a;
};

static int
ta_prepare_add_chash(struct ip_fw_chain *ch, struct tentry_info *tei,
    void *ta_buf)
{
	struct ta_buf_chash *tb;
	struct chashentry *ent;
	int mlen;
	struct in6_addr mask6;

	tb = (struct ta_buf_chash *)ta_buf;
	memset(tb, 0, sizeof(struct ta_buf_chash));

	mlen = tei->masklen;
	
	if (tei->subtype == AF_INET) {
#ifdef INET
		if (mlen > 32)
			return (EINVAL);
		ent = malloc(sizeof(*ent), M_IPFW_TBL, M_WAITOK | M_ZERO);
		ent->value = tei->value;
		ent->type = AF_INET;

		/* Calculate mask */
		ent->a.a4 = ntohl(*((in_addr_t *)tei->paddr)) >> (32 - mlen);
		tb->ent_ptr = ent;
#endif
#ifdef INET6
	} else if (tei->subtype == AF_INET6) {
		/* IPv6 case */
		if (mlen > 128)
			return (EINVAL);
		ent = malloc(sizeof(*ent), M_IPFW_TBL, M_WAITOK | M_ZERO);
		ent->value = tei->value;
		ent->type = AF_INET6;

		ipv6_writemask(&mask6, mlen);
		memcpy(&ent->a.a6, tei->paddr, sizeof(struct in6_addr));
		APPLY_MASK(&ent->a.a6, &mask6);
		tb->ent_ptr = ent;
#endif
	} else {
		/* Unknown CIDR type */
		return (EINVAL);
	}

	return (0);
}

static int
ta_add_chash(void *ta_state, struct table_info *ti, struct tentry_info *tei,
    void *ta_buf, uint64_t *pflags, uint32_t *pnum)
{
	struct chash_cfg *ccfg;
	struct chashbhead *head;
	struct chashentry *ent, *tmp;
	struct ta_buf_chash *tb;
	int exists;
	uint32_t hash;

	ccfg = (struct chash_cfg *)ta_state;
	tb = (struct ta_buf_chash *)ta_buf;
	ent = (struct chashentry *)tb->ent_ptr;
	hash = 0;
	exists = 0;

	if (tei->subtype == AF_INET) {
		if (tei->masklen != ccfg->mask4)
			return (EINVAL);
		head = ccfg->head4;
		hash = hash_ip(ent->a.a4, ccfg->size4);
		/* Check for existence */
		SLIST_FOREACH(tmp, &head[hash], next) {
			if (tmp->a.a4 == ent->a.a4) {
				exists = 1;
				break;
			}
		}
	} else {
		if (tei->masklen != ccfg->mask6)
			return (EINVAL);
		head = ccfg->head6;
		if (tei->masklen == 64)
			hash = hash_ip64(&ent->a.a6, ccfg->size6);
		else
			hash = hash_ip6(&ent->a.a6, ccfg->size6);
		/* Check for existence */
		SLIST_FOREACH(tmp, &head[hash], next) {
			if (memcmp(&tmp->a.a6, &ent->a.a6, 16)) {
				exists = 1;
				break;
			}
		}
	}

	if (exists == 1) {
		if ((tei->flags & TEI_FLAGS_UPDATE) == 0)
			return (EEXIST);
		/* Record already exists. Update value if we're asked to */
		tmp->value = tei->value;
		/* Indicate that update has happened instead of addition */
		tei->flags |= TEI_FLAGS_UPDATED;
		*pnum = 0;
	} else {
		SLIST_INSERT_HEAD(&head[hash], ent, next);
		tb->ent_ptr = NULL;
		*pnum = 1;
	}

	return (0);
}

static int
ta_prepare_del_chash(struct ip_fw_chain *ch, struct tentry_info *tei,
    void *ta_buf)
{
	struct ta_buf_chash *tb;
	int mlen;
	struct in6_addr mask6;

	tb = (struct ta_buf_chash *)ta_buf;
	memset(tb, 0, sizeof(struct ta_buf_chash));

	mlen = tei->masklen;
	
	if (tei->subtype == AF_INET) {
#ifdef INET
		if (mlen > 32)
			return (EINVAL);
		tb->type = AF_INET;

		/* Calculate masked address */
		tb->a.a4 = ntohl(*((in_addr_t *)tei->paddr)) >> (32 - mlen);
#endif
#ifdef INET6
	} else if (tei->subtype == AF_INET6) {
		/* IPv6 case */
		if (mlen > 128)
			return (EINVAL);
		tb->type = AF_INET6;

		ipv6_writemask(&mask6, mlen);
		memcpy(&tb->a.a6, tei->paddr, sizeof(struct in6_addr));
		APPLY_MASK(&tb->a.a6, &mask6);
#endif
	} else {
		/* Unknown CIDR type */
		return (EINVAL);
	}

	return (0);
}

static int
ta_del_chash(void *ta_state, struct table_info *ti, struct tentry_info *tei,
    void *ta_buf, uint64_t *pflags, uint32_t *pnum)
{
	struct chash_cfg *ccfg;
	struct chashbhead *head;
	struct chashentry *ent, *tmp_next;
	struct ta_buf_chash *tb;
	uint32_t hash;

	ccfg = (struct chash_cfg *)ta_state;
	tb = (struct ta_buf_chash *)ta_buf;

	if (tei->subtype == AF_INET) {
		if (tei->masklen != ccfg->mask4)
			return (EINVAL);
		head = ccfg->head4;
		hash = hash_ip(tb->a.a4, ccfg->size4);

		SLIST_FOREACH_SAFE(ent, &head[hash], next, tmp_next) {
			if (ent->a.a4 == tb->a.a4) {
				SLIST_REMOVE(&head[hash], ent, chashentry,next);
				*pnum = 1;
				return (0);
			}
		}
	} else {
		if (tei->masklen != ccfg->mask6)
			return (EINVAL);
		head = ccfg->head6;
		if (tei->masklen == 64)
			hash = hash_ip64(&tb->a.a6, ccfg->size6);
		else
			hash = hash_ip6(&tb->a.a6, ccfg->size6);

		SLIST_FOREACH_SAFE(ent, &head[hash], next, tmp_next) {
			if (memcmp(&ent->a.a6, &tb->a.a6, 16)) {
				SLIST_REMOVE(&head[hash], ent, chashentry,next);
				*pnum = 1;
				return (0);
			}
		}
	}

	return (ENOENT);
}

static void
ta_flush_chash_entry(struct ip_fw_chain *ch, struct tentry_info *tei,
    void *ta_buf)
{
	struct ta_buf_chash *tb;

	tb = (struct ta_buf_chash *)ta_buf;

	if (tb->ent_ptr != NULL)
		free(tb->ent_ptr, M_IPFW_TBL);
}

struct table_algo cidr_hash = {
	.name		= "cidr:hash",
	.type		= IPFW_TABLE_CIDR,
	.init		= ta_init_chash,
	.destroy	= ta_destroy_chash,
	.prepare_add	= ta_prepare_add_chash,
	.prepare_del	= ta_prepare_del_chash,
	.add		= ta_add_chash,
	.del		= ta_del_chash,
	.flush_entry	= ta_flush_chash_entry,
	.foreach	= ta_foreach_chash,
	.dump_tentry	= ta_dump_chash_tentry,
	.find_tentry	= ta_find_chash_tentry,
	.print_config	= ta_print_chash_config,
};


/*
 * Iface table cmds.
 *
 * Implementation:
 *
 * Runtime part:
 * - sorted array of "struct ifidx" pointed by ti->state.
 *   Array is allocated with routing up to IFIDX_CHUNK. Only existing
 *   interfaces are stored in array, however its allocated size is
 *   sufficient to hold all table records if needed.
 * - current array size is stored in ti->data
 *
 * Table data:
 * - "struct iftable_cfg" is allocated to store table state (ta_state).
 * - All table records are stored inside namedobj instance.
 *
 */

struct ifidx {
	uint16_t	kidx;
	uint16_t	spare;
	uint32_t	value;
};

struct iftable_cfg;

struct ifentry {
	struct named_object	no;
	struct ipfw_ifc		ic;
	struct iftable_cfg	*icfg;
	uint32_t		value;
	int			linked;
};

struct iftable_cfg {
	struct namedobj_instance	*ii;
	struct ip_fw_chain	*ch;
	struct table_info	*ti;
	void	*main_ptr;
	size_t	size;	/* Number of items allocated in array */
	size_t	count;	/* Number of all items */
	size_t	used;	/* Number of items _active_ now */
};

#define	IFIDX_CHUNK	16

int compare_ifidx(const void *k, const void *v);
static void if_notifier(struct ip_fw_chain *ch, void *cbdata, uint16_t ifindex);

int
compare_ifidx(const void *k, const void *v)
{
	struct ifidx *ifidx;
	uint16_t key;

	key = *((uint16_t *)k);
	ifidx = (struct ifidx *)v;

	if (key < ifidx->kidx)
		return (-1);
	else if (key > ifidx->kidx)
		return (1);
	
	return (0);
}

/*
 * Adds item @item with key @key into ascending-sorted array @base.
 * Assumes @base has enough additional storage.
 *
 * Returns 1 on success, 0 on duplicate key.
 */
static int
badd(const void *key, void *item, void *base, size_t nmemb,
    size_t size, int (*compar) (const void *, const void *))
{
	int min, max, mid, shift, res;
	caddr_t paddr;

	if (nmemb == 0) {
		memcpy(base, item, size);
		return (1);
	}

	/* Binary search */
	min = 0;
	max = nmemb - 1;
	mid = 0;
	while (min <= max) {
		mid = (min + max) / 2;
		res = compar(key, (const void *)((caddr_t)base + mid * size));
		if (res == 0)
			return (0);

		if (res > 0)
			 min = mid + 1;
		else
			 max = mid - 1;
	}

	/* Item not found. */
	res = compar(key, (const void *)((caddr_t)base + mid * size));
	if (res > 0)
		shift = mid + 1;
	else
		shift = mid;

	paddr = (caddr_t)base + shift * size;
	if (nmemb > shift)
		memmove(paddr + size, paddr, (nmemb - shift) * size);

	memcpy(paddr, item, size);

	return (1);
}

/*
 * Deletes item with key @key from ascending-sorted array @base.
 *
 * Returns 1 on success, 0 for non-existent key.
 */
static int
bdel(const void *key, void *base, size_t nmemb, size_t size,
    int (*compar) (const void *, const void *))
{
	caddr_t item;
	size_t sz;

	item = (caddr_t)bsearch(key, base, nmemb, size, compar);

	if (item == NULL)
		return (0);

	sz = (caddr_t)base + nmemb * size - item;

	if (sz > 0)
		memmove(item, item + size, sz);

	return (1);
}

static struct ifidx *
ifidx_find(struct table_info *ti, void *key)
{
	struct ifidx *ifi;

	ifi = bsearch(key, ti->state, ti->data, sizeof(struct ifidx),
	    compare_ifidx);

	return (ifi);
}

static int
ta_lookup_ifidx(struct table_info *ti, void *key, uint32_t keylen,
    uint32_t *val)
{
	struct ifidx *ifi;

	ifi = ifidx_find(ti, key);

	if (ifi != NULL) {
		*val = ifi->value;
		return (1);
	}

	return (0);
}

static int
ta_init_ifidx(struct ip_fw_chain *ch, void **ta_state, struct table_info *ti,
    char *data)
{
	struct iftable_cfg *icfg;

	icfg = malloc(sizeof(struct iftable_cfg), M_IPFW, M_WAITOK | M_ZERO);

	icfg->ii = ipfw_objhash_create(16);
	icfg->main_ptr = malloc(sizeof(struct ifidx) * IFIDX_CHUNK,  M_IPFW,
	    M_WAITOK | M_ZERO);
	icfg->size = IFIDX_CHUNK;
	icfg->ch = ch;

	*ta_state = icfg;
	ti->state = icfg->main_ptr;
	ti->lookup = ta_lookup_ifidx;

	return (0);
}

/*
 * Handle tableinfo @ti pointer change (on table array resize).
 */
static void
ta_change_ti_ifidx(void *ta_state, struct table_info *ti)
{
	struct iftable_cfg *icfg;

	icfg = (struct iftable_cfg *)ta_state;
	icfg->ti = ti;
}

static void
destroy_ifidx_locked(struct namedobj_instance *ii, struct named_object *no,
    void *arg)
{
	struct ifentry *ife;
	struct ip_fw_chain *ch;

	ch = (struct ip_fw_chain *)arg;
	ife = (struct ifentry *)no;

	ipfw_iface_del_notify(ch, &ife->ic);
	free(ife, M_IPFW_TBL);
}


/*
 * Destroys table @ti
 */
static void
ta_destroy_ifidx(void *ta_state, struct table_info *ti)
{
	struct iftable_cfg *icfg;
	struct ip_fw_chain *ch;

	icfg = (struct iftable_cfg *)ta_state;
	ch = icfg->ch;

	if (icfg->main_ptr != NULL)
		free(icfg->main_ptr, M_IPFW);

	ipfw_objhash_foreach(icfg->ii, destroy_ifidx_locked, ch);

	ipfw_objhash_destroy(icfg->ii);

	free(icfg, M_IPFW);
}

struct ta_buf_ifidx
{
	struct ifentry *ife;
	uint32_t value;
};

/*
 * Prepare state to add to the table:
 * allocate ifentry and reference needed interface.
 */
static int
ta_prepare_add_ifidx(struct ip_fw_chain *ch, struct tentry_info *tei,
    void *ta_buf)
{
	struct ta_buf_ifidx *tb;
	char *ifname;
	struct ifentry *ife;

	tb = (struct ta_buf_ifidx *)ta_buf;
	memset(tb, 0, sizeof(struct ta_buf_ifidx));

	/* Check if string is terminated */
	ifname = (char *)tei->paddr;
	if (strnlen(ifname, IF_NAMESIZE) == IF_NAMESIZE)
		return (EINVAL);

	ife = malloc(sizeof(struct ifentry), M_IPFW_TBL, M_WAITOK | M_ZERO);
	ife->value = tei->value;
	ife->ic.cb = if_notifier;
	ife->ic.cbdata = ife;

	if (ipfw_iface_ref(ch, ifname, &ife->ic) != 0)
		return (EINVAL);

	/* Use ipfw_iface 'ifname' field as stable storage */
	ife->no.name = ife->ic.iface->ifname;

	tb->ife = ife;

	return (0);
}

static int
ta_add_ifidx(void *ta_state, struct table_info *ti, struct tentry_info *tei,
    void *ta_buf, uint64_t *pflags, uint32_t *pnum)
{
	struct iftable_cfg *icfg;
	struct ifentry *ife, *tmp;
	struct ta_buf_ifidx *tb;
	struct ipfw_iface *iif;
	struct ifidx *ifi;
	char *ifname;

	tb = (struct ta_buf_ifidx *)ta_buf;
	ifname = (char *)tei->paddr;
	icfg = (struct iftable_cfg *)ta_state;
	ife = tb->ife;

	ife->icfg = icfg;

	tmp = (struct ifentry *)ipfw_objhash_lookup_name(icfg->ii, 0, ifname);

	if (tmp != NULL) {
		if ((tei->flags & TEI_FLAGS_UPDATE) == 0)
			return (EEXIST);

		/* We need to update value */
		iif = tmp->ic.iface;
		tmp->value = ife->value;

		if (iif->resolved != 0) {
			/* We need to update runtime value, too */
			ifi = ifidx_find(ti, &iif->ifindex);
			ifi->value = ife->value;
		}

		/* Indicate that update has happened instead of addition */
		tei->flags |= TEI_FLAGS_UPDATED;
		*pnum = 0;
		return (0);
	}

	/* Link to internal list */
	ipfw_objhash_add(icfg->ii, &ife->no);

	/* Link notifier (possible running its callback) */
	ipfw_iface_add_notify(icfg->ch, &ife->ic);
	icfg->count++;

	if (icfg->count + 1 == icfg->size) {
		/* Notify core we need to grow */
		*pflags = icfg->size + IFIDX_CHUNK;
	}

	tb->ife = NULL;
	*pnum = 1;

	return (0);
}

/*
 * Prepare to delete key from table.
 * Do basic interface name checks.
 */
static int
ta_prepare_del_ifidx(struct ip_fw_chain *ch, struct tentry_info *tei,
    void *ta_buf)
{
	struct ta_buf_ifidx *tb;
	char *ifname;

	tb = (struct ta_buf_ifidx *)ta_buf;
	memset(tb, 0, sizeof(struct ta_buf_ifidx));

	/* Check if string is terminated */
	ifname = (char *)tei->paddr;
	if (strnlen(ifname, IF_NAMESIZE) == IF_NAMESIZE)
		return (EINVAL);

	return (0);
}

/*
 * Remove key from both configuration list and
 * runtime array. Removed interface notification.
 */
static int
ta_del_ifidx(void *ta_state, struct table_info *ti, struct tentry_info *tei,
    void *ta_buf, uint64_t *pflags, uint32_t *pnum)
{
	struct iftable_cfg *icfg;
	struct ifentry *ife;
	struct ta_buf_ifidx *tb;
	char *ifname;
	uint16_t ifindex;
	int res;

	tb = (struct ta_buf_ifidx *)ta_buf;
	ifname = (char *)tei->paddr;
	icfg = (struct iftable_cfg *)ta_state;
	ife = tb->ife;

	ife = (struct ifentry *)ipfw_objhash_lookup_name(icfg->ii, 0, ifname);

	if (ife == NULL)
		return (ENOENT);

	if (ife->linked != 0) {
		/* We have to remove item from runtime */
		ifindex = ife->ic.iface->ifindex;

		res = bdel(&ifindex, icfg->main_ptr, icfg->used,
		    sizeof(struct ifidx), compare_ifidx);

		KASSERT(res == 1, ("index %d does not exist", ifindex));
		icfg->used--;
		ti->data = icfg->used;
		ife->linked = 0;
	}

	/* Unlink from local list */
	ipfw_objhash_del(icfg->ii, &ife->no);
	/* Unlink notifier */
	ipfw_iface_del_notify(icfg->ch, &ife->ic);

	icfg->count--;

	tb->ife = ife;
	*pnum = 1;

	return (0);
}

/*
 * Flush deleted entry.
 * Drops interface reference and frees entry.
 */
static void
ta_flush_ifidx_entry(struct ip_fw_chain *ch, struct tentry_info *tei,
    void *ta_buf)
{
	struct ta_buf_ifidx *tb;

	tb = (struct ta_buf_ifidx *)ta_buf;

	if (tb->ife != NULL) {
		/* Unlink first */
		ipfw_iface_unref(ch, &tb->ife->ic);
		free(tb->ife, M_IPFW_TBL);
	}
}


/*
 * Handle interface announce/withdrawal for particular table.
 * Every real runtime array modification happens here.
 */
static void
if_notifier(struct ip_fw_chain *ch, void *cbdata, uint16_t ifindex)
{
	struct ifentry *ife;
	struct ifidx ifi;
	struct iftable_cfg *icfg;
	struct table_info *ti;
	int res;

	ife = (struct ifentry *)cbdata;
	icfg = ife->icfg;
	ti = icfg->ti;

	KASSERT(ti != NULL, ("ti=NULL, check change_ti handler"));

	if (ife->linked == 0 && ifindex != 0) {
		/* Interface announce */
		ifi.kidx = ifindex;
		ifi.spare = 0;
		ifi.value = ife->value;
		res = badd(&ifindex, &ifi, icfg->main_ptr, icfg->used,
		    sizeof(struct ifidx), compare_ifidx);
		KASSERT(res == 1, ("index %d already exists", ifindex));
		icfg->used++;
		ti->data = icfg->used;
		ife->linked = 1;
	} else if (ife->linked != 0 && ifindex == 0) {
		/* Interface withdrawal */
		ifindex = ife->ic.iface->ifindex;

		res = bdel(&ifindex, icfg->main_ptr, icfg->used,
		    sizeof(struct ifidx), compare_ifidx);

		KASSERT(res == 1, ("index %d does not exist", ifindex));
		icfg->used--;
		ti->data = icfg->used;
		ife->linked = 0;
	}
}


/*
 * Table growing callbacks.
 */

struct mod_ifidx {
	void	*main_ptr;
	size_t	size;
};

/*
 * Allocate ned, larger runtime ifidx array.
 */
static int
ta_prepare_mod_ifidx(void *ta_buf, uint64_t *pflags)
{
	struct mod_ifidx *mi;

	mi = (struct mod_ifidx *)ta_buf;

	memset(mi, 0, sizeof(struct mod_ifidx));
	mi->size = *pflags;
	mi->main_ptr = malloc(sizeof(struct ifidx) * mi->size, M_IPFW,
	    M_WAITOK | M_ZERO);

	return (0);
}

/*
 * Copy data from old runtime array to new one.
 */
static int
ta_fill_mod_ifidx(void *ta_state, struct table_info *ti, void *ta_buf,
    uint64_t *pflags)
{
	struct mod_ifidx *mi;
	struct iftable_cfg *icfg;

	mi = (struct mod_ifidx *)ta_buf;
	icfg = (struct iftable_cfg *)ta_state;

	/* Check if we still need to grow array */
	if (icfg->size >= mi->size) {
		*pflags = 0;
		return (0);
	}

	memcpy(mi->main_ptr, icfg->main_ptr, icfg->used * sizeof(struct ifidx));

	return (0);
}

/*
 * Switch old & new arrays.
 */
static int
ta_modify_ifidx(void *ta_state, struct table_info *ti, void *ta_buf,
    uint64_t pflags)
{
	struct mod_ifidx *mi;
	struct iftable_cfg *icfg;
	void *old_ptr;

	mi = (struct mod_ifidx *)ta_buf;
	icfg = (struct iftable_cfg *)ta_state;

	old_ptr = icfg->main_ptr;
	icfg->main_ptr = mi->main_ptr;
	icfg->size = mi->size;
	ti->state = icfg->main_ptr;

	mi->main_ptr = old_ptr;

	return (0);
}

/*
 * Free unneded array.
 */
static void
ta_flush_mod_ifidx(void *ta_buf)
{
	struct mod_ifidx *mi;

	mi = (struct mod_ifidx *)ta_buf;
	if (mi->main_ptr != NULL)
		free(mi->main_ptr, M_IPFW);
}

static int
ta_dump_ifidx_tentry(void *ta_state, struct table_info *ti, void *e,
    ipfw_obj_tentry *tent)
{
	struct ifentry *ife;

	ife = (struct ifentry *)e;

	tent->masklen = 8 * IF_NAMESIZE;
	memcpy(&tent->k, ife->no.name, IF_NAMESIZE);
	tent->value = ife->value;

	return (0);
}

static int
ta_find_ifidx_tentry(void *ta_state, struct table_info *ti, void *key,
    uint32_t keylen, ipfw_obj_tentry *tent)
{
	struct iftable_cfg *icfg;
	struct ifentry *ife;
	char *ifname;

	icfg = (struct iftable_cfg *)ta_state;
	ifname = (char *)key;

	if (strnlen(ifname, IF_NAMESIZE) == IF_NAMESIZE)
		return (EINVAL);

	ife = (struct ifentry *)ipfw_objhash_lookup_name(icfg->ii, 0, ifname);

	if (ife != NULL) {
		ta_dump_ifidx_tentry(ta_state, ti, ife, tent);
		return (0);
	}

	return (ENOENT);
}

struct wa_ifidx {
	ta_foreach_f	*f;
	void		*arg;
};

static void
foreach_ifidx(struct namedobj_instance *ii, struct named_object *no,
    void *arg)
{
	struct ifentry *ife;
	struct wa_ifidx *wa;

	ife = (struct ifentry *)no;
	wa = (struct wa_ifidx *)arg;

	wa->f(ife, wa->arg);
}

static void
ta_foreach_ifidx(void *ta_state, struct table_info *ti, ta_foreach_f *f,
    void *arg)
{
	struct iftable_cfg *icfg;
	struct wa_ifidx wa;

	icfg = (struct iftable_cfg *)ta_state;

	wa.f = f;
	wa.arg = arg;

	ipfw_objhash_foreach(icfg->ii, foreach_ifidx, &wa);
}

struct table_algo iface_idx = {
	.name		= "iface:array",
	.type		= IPFW_TABLE_INTERFACE,
	.init		= ta_init_ifidx,
	.destroy	= ta_destroy_ifidx,
	.prepare_add	= ta_prepare_add_ifidx,
	.prepare_del	= ta_prepare_del_ifidx,
	.add		= ta_add_ifidx,
	.del		= ta_del_ifidx,
	.flush_entry	= ta_flush_ifidx_entry,
	.foreach	= ta_foreach_ifidx,
	.dump_tentry	= ta_dump_ifidx_tentry,
	.find_tentry	= ta_find_ifidx_tentry,
	.prepare_mod	= ta_prepare_mod_ifidx,
	.fill_mod	= ta_fill_mod_ifidx,
	.modify		= ta_modify_ifidx,
	.flush_mod	= ta_flush_mod_ifidx,
	.change_ti	= ta_change_ti_ifidx,
};

void
ipfw_table_algo_init(struct ip_fw_chain *ch)
{
	size_t sz;

	/*
	 * Register all algorithms presented here.
	 */
	sz = sizeof(struct table_algo);
	ipfw_add_table_algo(ch, &cidr_radix, sz, &cidr_radix.idx);
	ipfw_add_table_algo(ch, &cidr_hash, sz, &cidr_hash.idx);
	ipfw_add_table_algo(ch, &iface_idx, sz, &iface_idx.idx);
}

void
ipfw_table_algo_destroy(struct ip_fw_chain *ch)
{

	ipfw_del_table_algo(ch, cidr_radix.idx);
	ipfw_del_table_algo(ch, cidr_hash.idx);
	ipfw_del_table_algo(ch, iface_idx.idx);
}


