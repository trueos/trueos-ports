--- linux/asm/bitsperlong.h.orig	2019-11-20 21:11:45 UTC
+++ linux/asm/bitsperlong.h
@@ -8,6 +8,6 @@
 # define __BITS_PER_LONG 32
 #endif
 
-#include <asm-generic/bitsperlong.h>
+#include "asm-generic/bitsperlong.h"
 
 #endif /* __ASM_X86_BITSPERLONG_H */
