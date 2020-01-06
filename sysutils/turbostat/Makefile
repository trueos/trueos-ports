# $FreeBSD$

PORTNAME=	turbostat
PORTVERSION=	5.3  # Turbostat itself has a version, but we don't bother
CATEGORIES=	sysutils
MASTER_SITES=	https://raw.githubusercontent.com/torvalds/linux/v${PORTVERSION}/ 

TURBOSTAT_DIR= tools/power/x86/turbostat/
ASM_DIR= arch/x86/include/asm/
X86ASM_DIR= tools/arch/x86/include/uapi/asm/
GENERICASM_DIR= tools/include/uapi/asm-generic/
DISTFILES=	${TURBOSTAT_DIR}${PORTNAME}.c \
			${TURBOSTAT_DIR}${PORTNAME}.8 \
			${ASM_DIR}intel-family.h \
			${ASM_DIR}msr-index.h \
			tools/include/linux/bits.h \
			${X86ASM_DIR}bitsperlong.h \
            ${GENERICASM_DIR}bitsperlong.h

DIST_SUBDIR=	${PORTNAME}-${PORTVERSION}

MAINTAINER=	d.scott.phillips@intel.com
COMMENT=	Report power statistics for Intel CPUs

LICENSE=	GPLv2

ONLY_FOR_ARCHS=	amd64

NO_WRKSUBDIR=yes
PLIST_FILES=	sbin/turbostat man/man8/turbostat.8.gz

post-extract:

do-extract:
	@${MKDIR} ${WRKSRC}/linux/asm/asm-generic
	${CP} ${_DISTDIR}/${TURBOSTAT_DIR}${PORTNAME}.c ${WRKSRC}
	${CP} ${_DISTDIR}/${TURBOSTAT_DIR}${PORTNAME}.8 ${WRKSRC}
	${CP} ${_DISTDIR}/tools/include/linux/bits.h ${WRKSRC}/linux
	${CP} ${_DISTDIR}/${X86ASM_DIR}bitsperlong.h ${WRKSRC}/linux/asm
	${CP} ${_DISTDIR}/${ASM_DIR}intel-family.h ${WRKSRC}
	${CP} ${_DISTDIR}/${ASM_DIR}msr-index.h ${WRKSRC}
	${CP} ${_DISTDIR}/${GENERICASM_DIR}bitsperlong.h ${WRKSRC}/linux/asm/asm-generic


do-build:
	cd ${WRKSRC} && ${CC} ${CFLAGS} -DMSRHEADER='"msr-index.h"' -DINTEL_FAMILY_HEADER='"intel-family.h"' -o ${PORTNAME} ${PORTNAME}.c -lutil

do-install:
	${INSTALL_PROGRAM} ${WRKSRC}/${PORTNAME} ${STAGEDIR}${PREFIX}/sbin
	${INSTALL_MAN} ${WRKSRC}/${PORTNAME}.8 ${STAGEDIR}${MANPREFIX}/man/man8

.include <bsd.port.mk>
