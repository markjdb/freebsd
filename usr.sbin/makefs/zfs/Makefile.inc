.PATH:	${SRCDIR}/zfs
SRCS+=	nvlist.c

CFLAGS.nvlist.c+=	-I${SRCDIR}/zfs
CFLAGS.zfsimpl.c+=	-I${SRCDIR}/zfs \
			-I${SRCTOP}/sys/cddl/boot/zfs \
			-I${SRCTOP}/sys/cddl/contrib/opensolaris/uts/common \
			-I${SRCTOP}/sys/cddl/contrib/opensolaris/common/lz4 \
			-I${ZFSTOP}/include \
			-I${ZFSTOP}/include/os/freebsd/zfs

.PATH:	${SRCTOP}/sys/crypto/skein
SRCS+=	skein.c skein_block.c

.PATH:	${SRCTOP}/sys/cddl/contrib/opensolaris/common/lz4
SRCS+=	lz4.c
