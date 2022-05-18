.PATH:	${SRCDIR}/zfs

SRCS+=	nvlist.c

CFLAGS.nvlist.c+= -Wno-cast-qual
