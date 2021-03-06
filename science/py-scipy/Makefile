# Created by: ijliao
# $FreeBSD$

PORTNAME=	scipy
PORTVERSION=	1.2.2
PORTREVISION=	1
CATEGORIES=	science python
MASTER_SITES=	https://docs.scipy.org/doc/scipy-${PORTVERSION:R}.1/:doc \
		CHEESESHOP:source \
		SF:source
PKGNAMEPREFIX=	${PYTHON_PKGNAMEPREFIX}
DISTFILES=	${DISTNAME}${EXTRACT_SUFX}:source \
		scipy-ref-${PORTVERSION:R}.1.pdf:doc
EXTRACT_ONLY=	${DISTNAME}${EXTRACT_SUFX}

MAINTAINER=	python@FreeBSD.org
COMMENT=	Scientific tools for Python

LICENSE=	BSD3CLAUSE
LICENSE_FILE=	${WRKSRC}/LICENSE.txt

BUILD_DEPENDS=	${PYNUMPY}
RUN_DEPENDS=	${PYNUMPY}

USES=		fortran python shebangfix
USE_PYTHON=	autoplist concurrent distutils

LDFLAGS+=	-shared
PYDISTUTILS_BUILDARGS=	--fcompiler=gnu95
PYDISTUTILS_CONFIGUREARGS=	--fcompiler=gnu95

PORTDOCS=	scipy-ref-${PORTVERSION:R}.1.pdf

SHEBANG_FILES=	scipy/sparse/linalg/isolve/tests/test_gcrotmk.py

OPTIONS_DEFINE=	DOCS

post-patch:
# Syntax error with GCC 5
	@${REINPLACE_CMD} -e "s|) IF(| .AND. |" ${WRKSRC}/scipy/odr/odrpack/d_lpkbls.f
# This line help fix the plist error because autoplist list it as a file but it is a directory
	@${TOUCH} ${WRKSRC}/scipy/stats/tests/data/tmp

post-install:
	${FIND} ${STAGEDIR}${PYTHON_SITELIBDIR}/scipy/ -name '*.so' | ${XARGS} ${STRIP_CMD}

post-install-DOCS-on:
	@${MKDIR} ${STAGEDIR}${DOCSDIR}
	${INSTALL_DATA} ${DISTDIR}/${PORTDOCS} ${STAGEDIR}${DOCSDIR}

.include <bsd.port.mk>
