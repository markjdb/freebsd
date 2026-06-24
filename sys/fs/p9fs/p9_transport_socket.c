/*
 * Copyright (c) 2026 Mark Johnston <markj@FreeBSD.org>
 *
 * SDPX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/uio.h>

#include <netinet/in.h>

#include <fs/p9fs/p9_client.h>
#include <fs/p9fs/p9_transport.h>

struct p9_hdr {
	uint32_t size;
	uint8_t type;
	uint16_t tag;
} __packed;

struct p9_socket_req {
	uint32_t size;
	uint16_t tag;
	bool done;
	LIST_ENTRY(p9_socket_req) link;
};

struct p9_socket_softc {
	struct socket	*so;
	LIST_HEAD(, p9_socket_req) reqs;
};

static MALLOC_DEFINE(M_P9SOCK, "p9socket", "9P socket transport structures");

static so_upcall_t p9_socket_upcall;

static int
p9_socket_create(struct mount *mp, const char *mount_tag, void **handlep)
{
	struct sockaddr *sa;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
	struct p9_socket_softc *sc;
	struct socket *so;
	char *opt;
	struct in6_addr addr6;
	in_addr_t addr;
	int af, error, port;

	error = vfs_getopt(mp->mnt_optnew, "port", (void **)&opt, NULL);
	if (error == 0) {
		error = sscanf(opt, "%d", &port);
		if (error != 1 || port < 1 || port > 65535) {
			vfs_mount_error(mp, "illegal port: %s", opt);
			return (EINVAL);
		}
	} else {
		port = 564;
	}

	if (inet_pton(AF_INET, mount_tag, &addr) == 0) {
		if (inet_pton(AF_INET6, mount_tag, &addr6) == 0) {
			vfs_mount_error(mp, "invalid address: %s", mount_tag);
			return (EINVAL);
		}
		af = AF_INET6;
		memset(&sin6, 0, sizeof(sin6));
		sin6.sin6_len = sizeof(sin6);
		sin6.sin6_family = AF_INET6;
		sin6.sin6_addr = addr6;
		sin6.sin6_port = htons(port);
		sa = (struct sockaddr *)&sin6;
	} else {
		af = AF_INET;
		memset(&sin, 0, sizeof(sin));
		sin.sin_len = sizeof(sin);
		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = addr;
		sin.sin_port = htons(port);
		sa = (struct sockaddr *)&sin;
	}

	error = socreate(af, &so, SOCK_STREAM, IPPROTO_TCP, mp->mnt_cred,
	    curthread);
	if (error != 0)
		return (error);

	error = soconnect(so, sa, curthread);
	if (error != 0) {
		soclose(so);
		vfs_mount_error(mp, "cannot connect to %s: %d", mount_tag,
		    error);
		return (error);
	}
	SOCK_LOCK(so);
	while ((so->so_state & SS_ISCONNECTING) && so->so_error == 0) {
		error = msleep(&so->so_timeo, &so->so_lock, PSOCK, "9pconn", 0);
		if (error != 0)
			break;
	}
	if (error == 0) {
		error = so->so_error;
		so->so_error = 0;
	}
	SOCK_UNLOCK(so);
	if (error != 0) {
		soclose(so);
		return (error);
	}

	sc = malloc(sizeof(*sc), M_P9SOCK, M_WAITOK | M_ZERO);
	sc->so = so;
	LIST_INIT(&sc->reqs);
	*handlep = sc;

	SOCK_RECVBUF_LOCK(so);
	soupcall_set(so, SO_RCV, p9_socket_upcall, sc);
	SOCK_RECVBUF_UNLOCK(so);

	return (0);
}

static void
p9_socket_close(void *handle)
{
	struct p9_socket_softc *sc;

	sc = handle;
	SOCK_RECVBUF_LOCK(sc->so);
	soupcall_clear(sc->so, SO_RCV);
	SOCK_RECVBUF_UNLOCK(sc->so);
	soclose(sc->so);
	free(sc, M_P9SOCK);
}

static bool
p9_socket_gethdr(struct socket *so, struct p9_hdr *hdr)
{
	int cc;

	SOCK_RECVBUF_LOCK_ASSERT(so);

	cc = sbavail(&so->so_rcv);
	if (cc < sizeof(*hdr))
		return (false);
	m_copydata(so->so_rcv.sb_mb, 0, sizeof(*hdr), (void *)hdr);
	hdr->size = le32toh(hdr->size);
	return (cc >= hdr->size);
}

static int
p9_socket_upcall(struct socket *so, void *arg, int flags)
{
	struct p9_socket_softc *sc;
	struct p9_hdr hdr;

	SOCK_RECVBUF_LOCK_ASSERT(so);

	sc = arg;
	if (p9_socket_gethdr(so, &hdr)) {
		struct p9_socket_req *preq;

		LIST_FOREACH(preq, &sc->reqs, link) {
			if (preq->tag == hdr.tag) {
				preq->size = hdr.size;
				preq->done = true;
				break;
			}
		}
	}
	return (SU_OK);
}

static int
p9_socket_request(void *handle, struct p9_req_t *req)
{
	struct p9_socket_req preq;
	struct p9_hdr hdr;
	struct p9_socket_softc *sc;
	struct socket *so;
	struct iovec iov;
	struct uio uio;
	int error;

	sc = handle;
	so = sc->so;

	iov.iov_base = req->tc->sdata;
	iov.iov_len = req->tc->size;
	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_offset = 0;
	uio.uio_resid = req->tc->size;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_rw = UIO_WRITE;
	uio.uio_td = curthread;

	preq.tag = req->tc->tag;
	preq.done = false;
	SOCK_RECVBUF_LOCK(so);
	LIST_INSERT_HEAD(&sc->reqs, &preq, link);
	SOCK_RECVBUF_UNLOCK(so);

	error = sosend(so, NULL, &uio, NULL, NULL, 0, curthread);
	if (error != 0) {
		SOCK_RECVBUF_LOCK(so);
		LIST_REMOVE(&preq, link);
		SOCK_RECVBUF_UNLOCK(so);
		printf("%s:%d %d\n", __func__, __LINE__, error);
		return (EIO);
	}

	SOCK_RECVBUF_LOCK(so);
	do {
		if (p9_socket_gethdr(so, &hdr) && hdr.tag == preq.tag)
			break;
		if ((so->so_rcv.sb_state & SBS_CANTRCVMORE) != 0) {
			error = EIO;
			break;
		}
		error = sbwait(so, SO_RCV);
	} while (error == 0 && !preq.done);
	LIST_REMOVE(&preq, link);
	if (error == 0 && (so->so_rcv.sb_state & SBS_CANTRCVMORE) != 0) {
		printf("%s:%d\n", __func__, __LINE__);
		error = EIO;
	}
	SOCK_RECVBUF_UNLOCK(so);

	if (error == 0) {
		int flags;

		iov.iov_base = req->rc->sdata;
		iov.iov_len = req->rc->capacity;
		uio.uio_iov = &iov;
		uio.uio_iovcnt = 1;
		uio.uio_offset = 0;
		uio.uio_resid = preq.size;
		uio.uio_segflg = UIO_SYSSPACE;
		uio.uio_rw = UIO_READ;
		uio.uio_td = curthread;

		flags = MSG_WAITALL;
		if (uio.uio_resid > req->rc->capacity) {
			printf("%s:%d\n", __func__, __LINE__);
			/* Protocol error. */
			(void)sodisconnect(so);
			error = EIO;
		} else if (soreceive(so, NULL, &uio, NULL, NULL, &flags) != 0) {
			printf("%s:%d\n", __func__, __LINE__);
			error = EIO;
		} else {
			KASSERT(uio.uio_resid == 0,
			    ("%s: short read uio %p", __func__, &uio));
			if (sbavail(&so->so_rcv) != 0)
				sorwakeup(so);
		}
	}

	return (error);
}

static struct p9_trans_module p9_trans_socket = {
	.name = "tcp",
	.create = p9_socket_create,
	.close = p9_socket_close,
	.request = p9_socket_request,
};

static void
p9fs_transport_socket_init(void *arg __unused)
{
	p9_register_trans(&p9_trans_socket);
}
SYSINIT(p9fs_transport_socket, SI_SUB_VFS, SI_ORDER_ANY,
    p9fs_transport_socket_init, NULL);
