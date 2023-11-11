PACKAGES=	bhyve
FILESDIR=	${SHAREDIR}/bhyve/gdb

.if ${MACHINE_ARCH} == "amd64"
FILES+=		amd64.xml
.endif

.if ${MACHINE_ARCH} == "aarch64"
FILES+=		aarch64-core.xml
.endif

.include <bsd.prog.mk>
