--- linux/bits.h.orig	2019-11-20 21:11:33 UTC
+++ linux/bits.h
@@ -1,7 +1,7 @@
 /* SPDX-License-Identifier: GPL-2.0 */
 #ifndef __LINUX_BITS_H
 #define __LINUX_BITS_H
-#include <asm/bitsperlong.h>
+#include "asm/bitsperlong.h"
 
 #define BIT(nr)			(1UL << (nr))
 #define BIT_ULL(nr)		(1ULL << (nr))
