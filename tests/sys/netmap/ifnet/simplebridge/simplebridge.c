/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (C) 2011-2014 Luigi Rizzo, Matteo Landi
 *
 * A trimmed-down version of tools/tools/netmap/bridge.c which prints the number
 * of packets sent in each direction before exiting.
 */

#include <sys/ioctl.h>
#include <sys/poll.h>

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <libnetmap.h>

static int do_abort = 0;

static void
sigint_h(int sig __unused)
{
	do_abort = 1;
	signal(SIGINT, SIG_DFL);
}

/*
 * How many slots do we (user application) have on this
 * set of queues ?
 */
static int
rx_slots_avail(struct nmport_d *d)
{
	u_int i, tot = 0;

	for (i = d->first_rx_ring; i <= d->last_rx_ring; i++) {
		tot += nm_ring_space(NETMAP_RXRING(d->nifp, i));
	}

	return tot;
}

/*
 * Move up to 'limit' pkts from rxring to txring, swapping buffers
 * if zerocopy is possible. Otherwise fall back on packet copying.
 */
static int
rings_move(struct netmap_ring *rxring, struct netmap_ring *txring, u_int limit)
{
	u_int j, k, m = 0;

	assert(rxring->flags == 0);
	assert(txring->flags == 0);

	j = rxring->head;
	k = txring->head;
	m = nm_ring_space(rxring);
	if (m < limit)
		limit = m;
	m = nm_ring_space(txring);
	if (m < limit)
		limit = m;
	m = limit;
	while (limit-- > 0) {
		struct netmap_slot *rs = &rxring->slot[j];
		struct netmap_slot *ts = &txring->slot[k];
		uint32_t pkt;

		ts->len = rs->len;
		pkt = ts->buf_idx;
		ts->buf_idx = rs->buf_idx;
		rs->buf_idx = pkt;
		/* report the buffer change. */
		ts->flags |= NS_BUF_CHANGED;
		rs->flags |= NS_BUF_CHANGED;

		/*
		 * Copy the NS_MOREFRAG from rs to ts, leaving any
		 * other flags unchanged.
		 */
		ts->flags = (ts->flags & ~NS_MOREFRAG) | (rs->flags & NS_MOREFRAG);
		j = nm_ring_next(rxring, j);
		k = nm_ring_next(txring, k);
	}
	rxring->head = rxring->cur = j;
	txring->head = txring->cur = k;

	return (m);
}

/* Move packets from source port to destination port. */
static int
ports_move(struct nmport_d *src, struct nmport_d *dst, u_int limit)
{
	struct netmap_ring *txring, *rxring;
	u_int m = 0, si = src->first_rx_ring, di = dst->first_tx_ring;

	while (si <= src->last_rx_ring && di <= dst->last_tx_ring) {
		rxring = NETMAP_RXRING(src->nifp, si);
		txring = NETMAP_TXRING(dst->nifp, di);
		if (nm_ring_empty(rxring)) {
			si++;
			continue;
		}
		if (nm_ring_empty(txring)) {
			di++;
			continue;
		}
		m += rings_move(rxring, txring, limit);
	}

	return (m);
}

static void
usage(void)
{
	fprintf(stderr, "usage: %s [-h] -i <iface1> -i <iface2>\n",
	    getprogname());
	exit(1);
}

int
main(int argc, char **argv)
{
	struct pollfd pollfd[2];
	struct nmport_d *pa = NULL, *pb = NULL;
	char *ifa = NULL, *ifb = NULL;
	uint64_t atob, btoa;
	int ch;

	while ((ch = getopt(argc, argv, "hi:")) != -1) {
		switch (ch) {
		default:
		case 'h':
			usage();
			break;
		case 'i':
			if (ifa == NULL)
				ifa = optarg;
			else if (ifb == NULL)
				ifb = optarg;
			else
				D("%s ignored, already have 2 interfaces",
					optarg);
			break;
		}

	}
	argc -= optind;
	argv += optind;

	if (argc != 0 || ifa == NULL || ifb == NULL)
		usage();
	if (strcmp(ifa, ifb) == 0)
		errx(1, "specific interfaces must be distinct");

	pa = nmport_open(ifa);
	if (pa == NULL)
		errx(1, "cannot open %s", ifa);
	pb = nmport_open(ifb);
	if (pb == NULL)
		errx(1, "cannot open %s", ifa);

	memset(pollfd, 0, sizeof(pollfd));
	pollfd[0].fd = pa->fd;
	pollfd[1].fd = pb->fd;

	signal(SIGINT, sigint_h);

	atob = btoa = 0;
	while (!do_abort) {
		int n0, n1, ret;

		pollfd[0].events = pollfd[1].events = 0;
		pollfd[0].revents = pollfd[1].revents = 0;

		n0 = rx_slots_avail(pa);
		n1 = rx_slots_avail(pb);
		if (n0)
			pollfd[1].events |= POLLOUT;
		else
			pollfd[0].events |= POLLIN;
		if (n1)
			pollfd[0].events |= POLLOUT;
		else
			pollfd[1].events |= POLLIN;

		ret = poll(pollfd, 2, -1);
		if (ret < 0) {
			if (errno == EINTR)
				break;
			err(1, "poll");
		}
		if (pollfd[0].revents & POLLERR)
			errx(1, "poll error on iface1");
		if (pollfd[1].revents & POLLERR)
			errx(1, "poll error on iface2");
		if (pollfd[0].revents & POLLOUT)
			btoa += ports_move(pb, pa, 128);
		if (pollfd[1].revents & POLLOUT)
			atob += ports_move(pa, pb, 128);
	}
	nmport_close(pb);
	nmport_close(pa);

	printf("%ju %ju\n", (uintmax_t)atob, (uintmax_t)btoa);

	return (0);
}
