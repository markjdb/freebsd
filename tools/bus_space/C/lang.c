/*-
 * Copyright (c) 2014 Marcel Moolenaar
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/types.h>
#include <errno.h>

#include "bus_space.h"
#include "busdma.h"
#include "libbus_space.h"

int16_t
bus_space_read_1(int rid, long ofs)
{
	uint8_t val;

	return ((!bs_read(rid, ofs, &val, sizeof(val))) ? -1 : (int)val);
}

int32_t
bus_space_read_2(int rid, long ofs)
{
	uint16_t val;

	return ((!bs_read(rid, ofs, &val, sizeof(val))) ? -1 : (int)val);
}

int64_t
bus_space_read_4(int rid, long ofs)
{
	uint32_t val;

	return ((!bs_read(rid, ofs, &val, sizeof(val))) ? -1 : (int64_t)val);
}

int
bus_space_write_1(int rid, long ofs, uint8_t val)
{

	return ((!bs_write(rid, ofs, &val, sizeof(val))) ? errno : 0);
}

int
bus_space_write_2(int rid, long ofs, uint16_t val)
{

	return ((!bs_write(rid, ofs, &val, sizeof(val))) ? errno : 0);
}

int
bus_space_write_4(int rid, long ofs, uint32_t val)
{

	return ((!bs_write(rid, ofs, &val, sizeof(val))) ? errno : 0);
}

int
bus_space_map(const char *dev)
{

	return (bs_map(dev));
}

int
bus_space_unmap(int rid)
{

	return ((!bs_unmap(rid)) ? errno : 0);
}

int
bus_space_subregion(int rid, long ofs, long sz)
{

	return (bs_subregion(rid, ofs, sz));
}

int
busdma_tag_create(const char *dev, bus_addr_t align, bus_addr_t bndry,
    bus_addr_t maxaddr, bus_size_t maxsz, u_int nsegs, bus_size_t maxsegsz,
    u_int datarate, u_int flags, busdma_tag_t *out_p)
{
	int res;

	res = bd_tag_create(dev, align, bndry, maxaddr, maxsz, nsegs, maxsegsz,
	    datarate, flags);
	if (res == -1)
		return (errno);
	*out_p = res;
	return (0);
}

int
busdma_tag_derive(busdma_tag_t tag, bus_addr_t align, bus_addr_t bndry,
    bus_addr_t maxaddr, bus_size_t maxsz, u_int nsegs, bus_size_t maxsegsz, 
    u_int datarate, u_int flags, busdma_tag_t *out_p)
{
	int res;

	res = bd_tag_derive(tag, align, bndry, maxaddr, maxsz, nsegs, maxsegsz,
	    datarate, flags);
	if (res == -1)
		return (errno);
	*out_p = res;
	return (0);
}

int
busdma_tag_destroy(busdma_tag_t tag)
{

	return (bd_tag_destroy(tag));
}

int
busdma_mem_alloc(busdma_tag_t tag, u_int flags, busdma_md_t *out_p)
{
	int res;

	res = bd_mem_alloc(tag, flags);
	if (res == -1)
		return (errno);
	*out_p = res;
	return (0);
}

int
busdma_mem_free(busdma_md_t md)
{

	return (bd_mem_free(md));
}
