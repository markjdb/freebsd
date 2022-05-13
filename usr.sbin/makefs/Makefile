#	$FreeBSD$

SRCDIR:=${.PARSEDIR:tA}

.include <src.opts.mk>

PROG=	makefs

CFLAGS+=-I${SRCDIR}

SRCS=	cd9660.c \
	ffs.c \
	makefs.c \
	msdos.c \
	mtree.c \
	walk.c \
	zfs2.c
MAN=	makefs.8

NO_WCAST_ALIGN=
CSTD=	c11

.include "${SRCDIR}/cd9660/Makefile.inc"
.include "${SRCDIR}/ffs/Makefile.inc"
.include "${SRCDIR}/msdos/Makefile.inc"
.include "${SRCDIR}/zfs/Makefile.inc"

CFLAGS+=-DHAVE_STRUCT_STAT_ST_FLAGS=1

.PATH: ${SRCTOP}/contrib/mtree
CFLAGS+=-I${SRCTOP}/contrib/mtree
SRCS+=	getid.c misc.c spec.c

.PATH: ${SRCTOP}/contrib/mknod
CFLAGS+=-I${SRCTOP}/contrib/mknod
SRCS+=	pack_dev.c

CFLAGS+=	-I${SRCTOP}/lib/libnetbsd
LIBADD=		netbsd util sbuf

HAS_TESTS=
SUBDIR.${MK_TESTS}+= tests

# XXXMJ conditional on ZFS support
#LIBADD+= nvpair spl zfs zpool

.include <bsd.prog.mk>

ZFSTOP= ${SRCTOP}/sys/contrib/openzfs

CFLAGS.zfs.c+=	-I${ZFSTOP}/include \
		-I${ZFSTOP}/lib/libspl/include \
		-I${ZFSTOP}/lib/libspl/include/os/freebsd \
		-include ${ZFSTOP}/include/os/freebsd/spl/sys/ccompile.h \
		-include ${SRCTOP}/sys/modules/zfs/zfs_config.h \
		-DIN_BASE \
		-DHAVE_ISSETUGID

CWARNFLAGS.nvlist.c?=	-Wno-cast-qual
CWARNFLAGS.skein.c?=	-Wno-missing-variable-declarations

CFLAGS+= -fsanitize=address -O0

CFLAGS.zfs2.c+=	-I${SRCDIR}/zfs \
		-I${SRCTOP}/sys/cddl/boot/zfs \
