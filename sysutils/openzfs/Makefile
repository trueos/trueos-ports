# $FreeBSD$

PORTNAME=	openzfs
PORTVERSION=	2020010900
DISTVERSIONPREFIX=	v
CATEGORIES=	sysutils
PKGNAMESUFFIX?=

MAINTAINER=	kmoore@FreeBSD.org
COMMENT=	OpenZFS userland for FreeBSD

LICENSE=	CDDL

BROKEN_aarch64=	invokes x86 assembler

FLAVORS= userland debug tests python
debug_PKGNAMESUFFIX=	-debug
python_PKGNAMESUFFIX=	-python
tests_PKGNAMESUFFIX=	-tests

.if ${FLAVOR:U} == tests
OPTIONS_DEFAULT=	TESTS
.elif ${FLAVOR:U} == python
OPTIONS_DEFAULT= PYTHON
.elif ${FLAVOR:U} == debug
OPTIONS_DEFAULT= USERLAND DEBUG
RUN_DEPENDS+=	openzfs-kmod>=0:sysutils/openzfs-kmod
CONFLICTS_INSTALL=	openzfs
.else
OPTIONS_DEFAULT= USERLAND
RUN_DEPENDS+=	openzfs-kmod>=0:sysutils/openzfs-kmod
CONFLICTS_INSTALL=	openzfs-debug
.endif

GNU_CONFIGURE=  yes
CONFIGURE_ARGS=	--prefix=${PREFIX} --with-config="user"

USES+=		autoreconf:build libtool gmake gettext-runtime:run python:3.3+,build shebangfix ssl

SHEBANG_GLOB=	*.ksh *.kshlib *.cfg *.ksh.in *.sh
ksh_CMD=	${LOCALBASE}/bin/ksh93

USE_GITHUB=	yes
GH_ACCOUNT=	zfsonfreebsd
GH_PROJECT=	ZoF
GH_TAGNAME=	5cb486d

OPTIONS_DEFINE= USERLAND DEBUG PYTHON TESTS
OPTIONS_SUB=    yes

.include <bsd.port.pre.mk>

.if (${OSVERSION} < 1200504) || (${OSVERSION} >= 1300000 && ${OSVERSION} < 1300013)
IGNORE+=      needs FreeBSD 12/13 with AES-CCM support
.endif

.if ${PORT_OPTIONS:MDEBUG}
CONFIGURE_ARGS+=	--enable-debug --enable-debuginfo
.else
INSTALL_TARGET= install-strip
.endif

.if ${PORT_OPTIONS:MPYTHON}
CONFIGURE_ARGS+=	--with-python=${PYTHON_VER}
BUILD_DEPENDS+=	${PYTHON_PKGNAMEPREFIX}cffi>0:devel/py-cffi@${PY_FLAVOR}
RUN_DEPENDS+=	${PYTHON_PKGNAMEPREFIX}cffi>0:devel/py-cffi@${PY_FLAVOR}
PLIST_SUB+=     PYTHON=""
.else
CONFIGURE_ARGS+=	--without-python
PLIST_SUB+=     PYTHON="@comment "
.endif

.if ${PORT_OPTIONS:MTESTS}
RUN_DEPENDS+=	bash:shells/bash
RUN_DEPENDS+=	base64:converters/base64
RUN_DEPENDS+=	fio:benchmarks/fio
RUN_DEPENDS+=	gdb:devel/gdb
RUN_DEPENDS+=	hs-ShellCheck:devel/hs-ShellCheck
RUN_DEPENDS+=	ksh93:shells/ksh93
RUN_DEPENDS+=	python3:lang/python2
RUN_DEPENDS+=	python2:lang/python3
RUN_DEPENDS+=	sudo:lang/python3
RUN_DEPENDS+=	${PYTHON_PKGNAMEPREFIX}flake8>0:devel/py-flake8@${PY_FLAVOR}
.endif

pre-configure:
	cd ${WRKSRC} && ./autogen.sh

post-stage:
	${RM} -rf ${STAGEDIR}/usr/lib

.include <bsd.port.post.mk>
