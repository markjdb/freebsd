.PATH:	${SRCTOP}/tools/tools/netmap

BINDIR=	${TESTSBASE}/sys/netmap/ifnet

PROG=	pkt-gen

CFLAGS+= -DNO_PCAP
LIBADD=	netmap pthread
WARNS?=	3

MK_MAN=	no

.include <bsd.prog.mk>
