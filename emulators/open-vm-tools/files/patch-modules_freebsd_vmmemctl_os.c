--- modules/freebsd/vmmemctl/os.c.orig	2020-01-03 21:06:11 UTC
+++ modules/freebsd/vmmemctl/os.c
@@ -64,7 +64,7 @@
 
 typedef struct {
    /* system structures */
-   struct callout_handle callout_handle;
+   struct callout callout_handle;
 
    /* termination flag */
    volatile int stop;
@@ -678,7 +678,8 @@ vmmemctl_poll(void *data) // IN
    if (!t->stop) {
       /* invoke registered handler, rearm timer */
       Balloon_QueryAndExecute();
-      t->callout_handle = timeout(vmmemctl_poll, t, BALLOON_POLL_PERIOD * hz);
+      callout_reset(&t->callout_handle, BALLOON_POLL_PERIOD * hz, vmmemctl_poll,
+          t);
    }
 }
 
@@ -712,15 +713,16 @@ vmmemctl_init(void)
    }
 
    /* initialize timer state */
-   callout_handle_init(&state->timer.callout_handle);
+   callout_init(&state->timer.callout_handle, 0);
 
    os_pmap_init(pmap);
    os_balloonobject_create();
 
    /* Set up and start polling */
-   callout_handle_init(&t->callout_handle);
+   callout_init(&t->callout_handle, 0);
    t->stop = FALSE;
-   t->callout_handle = timeout(vmmemctl_poll, t, BALLOON_POLL_PERIOD * hz);
+   callout_reset(&t->callout_handle, BALLOON_POLL_PERIOD * hz, vmmemctl_poll,
+       t);
 
    vmmemctl_init_sysctl();
 
@@ -759,7 +761,7 @@ vmmemctl_cleanup(void)
 
    /* Stop polling */
    t->stop = TRUE;
-   untimeout(vmmemctl_poll, t, t->callout_handle);
+   callout_stop(&t->callout_handle);
 
    os_balloonobject_delete();
    os_pmap_free(pmap);
