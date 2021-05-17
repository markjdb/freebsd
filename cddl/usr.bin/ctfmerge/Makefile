# $FreeBSD$

.PATH: ${SRCTOP}/cddl/contrib/opensolaris/cmd/ctfmerge

PROG=		ctfmerge
SRCS=		ctfmerge.c

WARNS?=		1

CFLAGS+= -DIN_BASE
CFLAGS+= -I${SRCTOP}/cddl/contrib/opensolaris/lib/libctf/common
CFLAGS+= -I${SRCTOP}/sys/contrib/openzfs/include
CFLAGS+= -I${SRCTOP}/sys/contrib/openzfs/lib/libspl/include/
CFLAGS+= -I${SRCTOP}/sys/contrib/openzfs/lib/libspl/include/os/freebsd
CFLAGS+= -I${SRCTOP}/cddl/compat/opensolaris/include
CFLAGS+=	-I${SRCTOP}/sys/cddl/compat/opensolaris \
		-I${SRCTOP}/cddl/compat/opensolaris/include \
		-I${OPENSOLARIS_USR_DISTDIR} \
		-I${OPENSOLARIS_SYS_DISTDIR} \
		-I${OPENSOLARIS_USR_DISTDIR}/head \
		-I${OPENSOLARIS_SYS_DISTDIR}/uts/common
CFLAGS+= -DHAVE_ISSETUGID

LIBADD=		ctf spl elf z pthread

.include <bsd.prog.mk>
