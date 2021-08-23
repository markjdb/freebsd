#	@(#)Makefile	8.1 (Berkeley) 6/6/93
# $FreeBSD$

.include <src.opts.mk>

CONFGROUPS=	CONFS SYSLOGD_D
CONFS=	syslog.conf
PROG=	syslogd
MAN=	syslog.conf.5 syslogd.8
SRCS=	syslogd.c \
	cap_config.c

.PATH: ${SRCTOP}/usr.bin/wall
SRCS+= ttymsg.c

LIBADD= util

.if ${MK_CASPER} != "no"
CFLAGS+= -DWITH_CASPER
LIBADD+= casper nv
.endif

.if ${MK_INET_SUPPORT} != "no"
CFLAGS+= -DINET
.endif
.if ${MK_INET6_SUPPORT} != "no"
CFLAGS+= -DINET6
.endif

SYSLOGD_D=
SYSLOGD_DDIR=	/etc/syslog.d
.if ${MK_FTP} != "no"
SYSLOGD_D+=	ftp.conf
.endif

.if ${MK_LPR} != "no"
SYSLOGD_D+=	lpr.conf
.endif

.if ${MK_PPP} != "no"
SYSLOGD_D+=	ppp.conf
.endif

CFLAGS+= -I${SRCTOP}/usr.bin/wall

.include <bsd.prog.mk>
