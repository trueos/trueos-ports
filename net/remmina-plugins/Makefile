# Created by: Alexander Logvinov <avl@FreeBSD.org>
# $FreeBSD$

PORTNAME?=	remmina-plugins
DISTVERSION=	1.3.5
CATEGORIES=	net gnome

MAINTAINER?=	woodsb02@FreeBSD.org
COMMENT?=	Remmina plugin system

LICENSE?=	GPLv2+

.if defined(PKGNAMESUFFIX)

USE_GITLAB=	yes
GL_ACCOUNT=	Remmina
GL_PROJECT=	Remmina
GL_COMMIT=	e1a0ffd30a0d8e35ed86ec81ecb4719bb870d62c

.include "${.CURDIR}/../remmina-plugins/bsd.plugin.mk"

.else

USES=	metaport

OPTIONS_DEFINE=		EXEC KEYRING NX RDP SPICE TELEP VNC XDMCP WWW 
OPTIONS_DEFAULT=	EXEC KEYRING RDP SPICE TELEP VNC XDMCP WWW
EXEC_DESC=		Plugin to execute a command
KEYRING_DESC=		GNOME Keyring plugin
NX_DESC=		NX protocol plugin
RDP_DESC=		Remote Desktop Protocol plugin
SPICE_DESC=		Spice protocol plugin
TELEP_DESC=		Telepathy protocol plugin
VNC_DESC=		VNC protocol plugin
XDMCP_DESC=		XDMCP protocol plugin
WWW_DESC=		Plugin to open an authenticated web browser

EXEC_RUN_DEPENDS=	remmina-plugin-exec>=0:net/remmina-plugin-exec
KEYRING_RUN_DEPENDS=	remmina-plugin-secret>=0:net/remmina-plugin-secret
NX_RUN_DEPENDS=		remmina-plugin-nx>=0:net/remmina-plugin-nx
RDP_RUN_DEPENDS=	remmina-plugin-rdp>=0:net/remmina-plugin-rdp
SPICE_RUN_DEPENDS=	remmina-plugin-spice>=0:net/remmina-plugin-spice
TELEP_RUN_DEPENDS=	remmina-plugin-telepathy>=0:net/remmina-plugin-telepathy
VNC_RUN_DEPENDS=	remmina-plugin-vnc>=0:net/remmina-plugin-vnc
XDMCP_RUN_DEPENDS=	remmina-plugin-xdmcp>=0:net/remmina-plugin-xdmcp
WWW_RUN_DEPENDS=	remmina-plugin-www>=0:net/remmina-plugin-www

.include <bsd.port.mk>

.endif
