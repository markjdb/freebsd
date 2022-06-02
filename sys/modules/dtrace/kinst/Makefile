SYSDIR?=	${SRCTOP}/sys

.PATH:		${SYSDIR}/cddl/dev/kinst

KMOD=		kinst
SRCS=		kinst.c

CFLAGS+=	${OPENZFS_CFLAGS} \
		-I${SYSDIR}/cddl/dev/kinst \
		-I${SYSDIR}/cddl/dev/dtrace/x86

.include <bsd.kmod.mk>

CFLAGS+=	-include ${SYSDIR}/cddl/compat/opensolaris/sys/debug_compat.h
CWARNFLAGS+=	${OPENZFS_CWARNFLAGS}
