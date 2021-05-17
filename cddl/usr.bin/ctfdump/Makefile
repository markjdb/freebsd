# $FreeBSD$

.PATH: ${SRCTOP}/cddl/contrib/opensolaris/cmd/ctfdump

PROG=		ctfdump
SRCS=		ctfdump.c

CWARNFLAGS.ctfdump.c+=	-Wno-unused-parameter \
			-Wno-sign-compare \
			-Wno-format \
			-Wno-cast-qual

CFLAGS+= -DIN_BASE
CFLAGS+= -I${SRCTOP}/cddl/contrib/opensolaris/lib/libctf/common
CFLAGS+= -I${SRCTOP}/sys/contrib/openzfs/include
CFLAGS+= -I${SRCTOP}/sys/contrib/openzfs/lib/libspl/include/
CFLAGS+= -I${SRCTOP}/sys/contrib/openzfs/lib/libspl/include/os/freebsd
CFLAGS+= -I${SRCTOP}/sys
CFLAGS+= -I${SRCTOP}/cddl/compat/opensolaris/include
CFLAGS+=	-I${OPENSOLARIS_USR_DISTDIR} \
		-I${OPENSOLARIS_SYS_DISTDIR} \
		-I${OPENSOLARIS_USR_DISTDIR}/head \
		-I${SRCTOP}/sys/cddl/compat/opensolaris \
		-I${SRCTOP}/cddl/compat/opensolaris/include \
		-I${OPENSOLARIS_SYS_DISTDIR}/uts/common
CFLAGS+= -DHAVE_ISSETUGID

LIBADD=		ctf

.include <bsd.prog.mk>
