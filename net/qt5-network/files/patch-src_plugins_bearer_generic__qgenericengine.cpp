--- src/plugins/bearer/generic/qgenericengine.cpp.orig	2018-09-13 00:25:10.000000000 -0400
+++ src/plugins/bearer/generic/qgenericengine.cpp	2018-11-26 03:28:10.640751000 -0500
@@ -231,9 +231,13 @@
 QGenericEngine::QGenericEngine(QObject *parent)
 :   QBearerEngineImpl(parent)
 {
+
+#ifndef QT_NO_NETWORKINTERFACE
     //workaround for deadlock in __cxa_guard_acquire with webkit on macos x
     //initialise the Q_GLOBAL_STATIC in same thread as the AtomicallyInitializedStatic
     (void)QNetworkInterface::interfaceFromIndex(0);
+#endif
+
 }
 
 QGenericEngine::~QGenericEngine()
