# Created by: Joe Maloney <jmaloney@ixsystems.com>
# $FreeBSD$

PORTNAME=	pcdm
<<<<<<< HEAD
PORTVERSION=	201803101421
=======
PORTVERSION=	201710031254
PORTREVISION=	3
>>>>>>> freebsd/master
CATEGORIES=	x11

MAINTAINER=	jmaloney@ixsystems.com
COMMENT=	QT5 based display manager for FreeBSD

LICENSE=	BSD2CLAUSE
LICENSE_FILE=	${WRKSRC}/../LICENSE

RUN_DEPENDS=    xorg-minimal>=0:x11/xorg-minimal \
		xhost:x11/xhost \
		setxkbmap:x11/setxkbmap \
		${LOCALBASE}/bin/qsudo:sysutils/qsudo

<<<<<<< HEAD
WRKSRC_SUBDIR=  src-qt5
MAKE_ARGS=      PREFIX=${STAGEDIR}${PREFIX}
USES=		compiler:c++11-lang gl qmake qt:5
=======
USES=		compiler:c++11-lang gl qmake qt:5 xorg
>>>>>>> freebsd/master
USE_QT=		core gui network svg multimedia imageformats \
		buildtools_build x11extras widgets concurrent linguisttools_build
USE_GL=		gl
USE_XORG=	x11
USE_OPENRC_SUBR=pcdm

MAKE_ARGS=	PREFIX=${STAGEDIR}${PREFIX}

CONFLICTS=      pcbsd-utils-qt*

USE_GITHUB=	yes
GH_ACCOUNT=	trueos
<<<<<<< HEAD
GH_PROJECT=	pcdm
GH_TAGNAME=	2091ea351f16ca13cd1ec050ae9eb95f32398462
=======
GH_TAGNAME=	690fdbdfc9fe482514161df1cd2bd994790c8a2d
>>>>>>> freebsd/master

.include <bsd.port.mk>
