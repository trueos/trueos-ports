--- turbostat.c.orig	2019-12-16 20:14:20 UTC
+++ turbostat.c
@@ -30,7 +30,31 @@
 #include <sched.h>
 #include <time.h>
 #include <cpuid.h>
+#ifdef __FreeBSD__
+#include <sys/types.h>
+#include <sys/param.h>
+#include <sys/cpuctl.h>
+#include <sys/cpuset.h>
+#include <sys/ioctl.h>
+#include <sys/sysctl.h>
+#include <sys/user.h>
+#include <elf.h>
+#include <libutil.h>
+#include <limits.h>
+
+#define cpu_set_t cpuset_t
+
+#define CPU_ALLOC(_ign)			({(cpuset_t*)malloc(sizeof(cpuset_t));})
+#define CPU_ALLOC_SIZE(_ign)		sizeof(cpuset_t)
+#define CPU_FREE			free
+#define CPU_ISSET_S(cpu, _ign, set)	(set && CPU_ISSET(cpu, set))
+#define CPU_SET_S(cpu, _ign, set)	CPU_SET(cpu, set)
+#define CPU_ZERO_S(_ign, set)		CPU_ZERO(set)
+#define sched_setaffinity(_x, _y, set)	cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_PID, -1, sizeof(cpuset_t), set)
+
+#else
 #include <linux/capability.h>
+#endif
 #include <errno.h>
 #include <math.h>
 
@@ -145,7 +169,9 @@ int ignore_stdin;
 #define MSR_CORE_ENERGY_STAT	0xc001029a
 #define MSR_PKG_ENERGY_STAT	0xc001029b
 
+#ifndef __FreeBSD__
 #define MAX(a, b) ((a) > (b) ? (a) : (b))
+#endif
 
 /*
  * buffer size used by sscanf() for added column names
@@ -357,6 +383,7 @@ int cpu_migrate(int cpu)
 	else
 		return 0;
 }
+
 int get_msr_fd(int cpu)
 {
 	char pathname[32];
@@ -367,18 +394,39 @@ int get_msr_fd(int cpu)
 	if (fd)
 		return fd;
 
+#ifdef __FreeBSD__
+	sprintf(pathname, "/dev/cpuctl%d", cpu);
+#else
 	sprintf(pathname, "/dev/cpu/%d/msr", cpu);
+#endif
 	fd = open(pathname, O_RDONLY);
 	if (fd < 0)
-		err(-1, "%s open failed, try chown or chmod +r /dev/cpu/*/msr, or run as root", pathname);
+		err(-1, "%s open failed, try chown or chmod +r "
+#ifdef __FreeBSD__
+		    "/dev/cpuctl*"
+#else
+		    "/dev/cpu/*/msr"
+#endif
+		    ", or run as root", pathname);
 
 	fd_percpu[cpu] = fd;
 
 	return fd;
 }
 
+#ifdef __FreeBSD__
 int get_msr(int cpu, off_t offset, unsigned long long *msr)
 {
+	cpuctl_msr_args_t args;
+	args.msr = offset;
+	if (ioctl(get_msr_fd(cpu), CPUCTL_RDMSR, &args))
+		err(1, "cpu%d: msr offset 0x%llx read failed", cpu, (unsigned long long)offset);
+	*msr = args.data;
+	return 0;
+}
+#else
+int get_msr(int cpu, off_t offset, unsigned long long *msr)
+{
 	ssize_t retval;
 
 	retval = pread(get_msr_fd(cpu), msr, sizeof(*msr), offset);
@@ -388,6 +436,7 @@ int get_msr(int cpu, off_t offset, unsigned long long 
 
 	return 0;
 }
+#endif
 
 /*
  * This list matches the column headers, except
@@ -2018,7 +2067,308 @@ done:
 	return 0;
 }
 
+#ifdef __FreeBSD__
+static int ncpus;
+static int maxcpu;
+struct cpuset_list {
+	cpuset_t	*sets;
+	size_t		len;
+	size_t		cap;
+};
+static struct cpuset_list packages = {0};
+static struct cpuset_list cores = {0};
+
+static void cpuset_list_ensure_space(struct cpuset_list *list) {
+	if (list->cap > list->len)
+		return;
+
+	if (list->cap)
+		list->cap *= 2;
+	else
+		list->cap = 2;
+
+	list->sets = realloc(list->sets, list->cap * sizeof(cpuset_t));
+}
+
+static cpuset_t parse_cpu_mask(const char *i) {
+	int count, mask_offset;
+	i = strstr(i, "mask=\"");
+	if (!i)
+		errx(1, "failed to parse topology_spec");
+	i += sizeof("mask=\"") - 1;
+
+	char sep;
+	cpuset_t out;
+	uint64_t *_out = (uint64_t *)&out;
+	CPU_ZERO(&out);
+
+	do {
+		int len;
+                if (sscanf(i, "%lx%c%n", _out, &sep, &len) != 2)
+			errx(1, "failed to parse topology_spec");
+                _out++;
+                i += len;
+	} while (sep == ',');
+
+	return out;
+}
+
+static void read_topology_spec(void)
+{
+	char *spec, *i;
+	size_t sz = 0;
+
+	if (sysctlbyname("kern.sched.topology_spec", NULL, &sz, NULL, 0) != ENOMEM)
+		err(1, "sysctl: kern.sched.topology_spec: failed");
+	spec = malloc(sz + 1);
+	if (spec == NULL)
+		err(1, "malloc: failed");
+	if (sysctlbyname("kern.sched.topology_spec", spec, &sz, NULL, 0))
+		err(1, "sysctl: kern.sched.topology_spec: failed");
+
+	/* Skip the entire system entry. */
+	i = strstr(spec, "<cpu");
+	if (!i)
+		errx(1, "read_topology_spec: parse failed");
+
+	cpuset_t last;
+	CPU_ZERO(&last);
+
+    char spectok[sizeof(spec)];
+	strcpy(spectok,spec);
+
+
+	while ((i = strstr(i + 1, "<cpu")) != NULL) {
+		cpuset_t set = parse_cpu_mask(i);
+
+		if (CPU_OVERLAP(&last, &set)) {
+			cpuset_list_ensure_space(&packages);
+			cores.len--;
+			CPU_COPY(cores.sets + cores.len, packages.sets + packages.len);
+			packages.len++;
+		}
+
+		cpuset_list_ensure_space(&cores);
+		CPU_COPY(&set, cores.sets + cores.len);
+		cores.len++;
+		CPU_COPY(&set, &last);
+	}
+
+	if (!packages.len) {
+		cpuset_list_ensure_space(&packages);
+		CPU_ZERO(packages.sets);
+
+		for (int i = 0; i < cores.len; i++)
+			CPU_OR(packages.sets, cores.sets + i);
+		packages.len++;
+	}
+
+	ncpus = 0;
+	for (int i = 0; i < packages.len; i++)
+		ncpus += CPU_COUNT(packages.sets + i);
+}
+
+int get_physical_package_id(int cpu)
+{
+	for (int i = 0; i < packages.len; i++) {
+		if (!CPU_ISSET(cpu, packages.sets + i))
+			continue;
+
+		return i;
+	}
+	return -1;
+}
+
+int get_core_id(int cpu)
+{
+	int package_id = get_physical_package_id(cpu);
+	if (package_id < 0)
+		return -1;
+
+	const cpuset_t *package = packages.sets + package_id;
+
+	for (int i = 0, j = -1; i < cores.len; i++) {
+		if (CPU_OVERLAP(package, cores.sets + i))
+			j++;
+
+		if (!CPU_ISSET(cpu, cores.sets + i))
+			continue;
+
+		return j;
+	}
+	return -1;
+}
+
+static int get_cpu_position_in_core(int cpu)
+{
+	for (int i = 0; i < cores.len; i++) {
+		if (!CPU_ISSET(cpu, cores.sets + i))
+			continue;
+
+		cpuset_t s;
+		CPU_COPY(cores.sets + i, &s);
+		for (int j = 0; !CPU_EMPTY(&s); j++) {
+			int ffs = CPU_FFS(&s) - 1;
+			if (ffs == cpu)
+				return j;
+			CPU_CLR(ffs, &s);
+		}
+
+		return -1;
+	}
+
+	return -1;
+}
+
+static int get_num_ht_siblings(int cpu)
+{
+	for (int i = 0; i < cores.len; i++) {
+		if (!CPU_ISSET(cpu, cores.sets + i))
+			continue;
+
+		return CPU_COUNT(cores.sets + i);
+	}
+
+	return 1;
+}
+
+int cpu_is_first_core_in_package(int cpu)
+{
+	int package = get_physical_package_id(cpu);
+	if (package < 0)
+		return -1;
+
+	return CPU_FFS(packages.sets + package) - 1 == cpu;
+}
+/* TODO: Report Actual Die info */
+int get_die_id(int cpu)
+{
+	return -1;
+}
+
+int get_physical_node_id(struct cpu_topology *thiscpu)
+{
+    return -1;
+}
+
+int get_thread_siblings(struct cpu_topology *thiscpu)
+{
+	return -1;
+}
+
+void set_max_cpu_num(void)
+{
+		printf("set_mac_cpu_num");
+}
+
+
+#else
 /*
+ * cpu_is_first_core_in_package(cpu)
+ * return 1 if given CPU is 1st core in package
+ */
+int cpu_is_first_core_in_package(int cpu)
+{
+	return cpu == parse_int_file("/sys/devices/system/cpu/cpu%d/topology/core_siblings_list", cpu);
+}
+
+int get_physical_package_id(int cpu)
+{
+	return parse_int_file("/sys/devices/system/cpu/cpu%d/topology/physical_package_id", cpu);
+}
+
+int get_die_id(int cpu)
+{
+	return parse_int_file("/sys/devices/system/cpu/cpu%d/topology/die_id", cpu);
+}
+
+int get_core_id(int cpu)
+{
+	return parse_int_file("/sys/devices/system/cpu/cpu%d/topology/core_id", cpu);
+}
+
+int get_physical_node_id(struct cpu_topology *thiscpu)
+{
+	char path[80];
+	FILE *filep;
+	int i;
+	int cpu = thiscpu->logical_cpu_id;
+
+	for (i = 0; i <= topo.max_cpu_num; i++) {
+		sprintf(path, "/sys/devices/system/cpu/cpu%d/node%i/cpulist",
+			cpu, i);
+		filep = fopen(path, "r");
+		if (!filep)
+			continue;
+		fclose(filep);
+		return i;
+	}
+	return -1;
+}
+
+int get_thread_siblings(struct cpu_topology *thiscpu)
+{
+	char path[80], character;
+	FILE *filep;
+	unsigned long map;
+	int so, shift, sib_core;
+	int cpu = thiscpu->logical_cpu_id;
+	int offset = topo.max_cpu_num + 1;
+	size_t size;
+	int thread_id = 0;
+
+	thiscpu->put_ids = CPU_ALLOC((topo.max_cpu_num + 1));
+	if (thiscpu->thread_id < 0)
+		thiscpu->thread_id = thread_id++;
+	if (!thiscpu->put_ids)
+		return -1;
+
+	size = CPU_ALLOC_SIZE((topo.max_cpu_num + 1));
+	CPU_ZERO_S(size, thiscpu->put_ids);
+
+	sprintf(path,
+		"/sys/devices/system/cpu/cpu%d/topology/thread_siblings", cpu);
+	filep = fopen_or_die(path, "r");
+	do {
+		offset -= BITMASK_SIZE;
+		if (fscanf(filep, "%lx%c", &map, &character) != 2)
+			err(1, "%s: failed to parse file", path);
+		for (shift = 0; shift < BITMASK_SIZE; shift++) {
+			if ((map >> shift) & 0x1) {
+				so = shift + offset;
+				sib_core = get_core_id(so);
+				if (sib_core == thiscpu->physical_core_id) {
+					CPU_SET_S(so, size, thiscpu->put_ids);
+					if ((so != cpu) &&
+					    (cpus[so].thread_id < 0))
+						cpus[so].thread_id =
+								    thread_id++;
+				}
+			}
+		}
+	} while (!strncmp(&character, ",", 1));
+	fclose(filep);
+
+	return CPU_COUNT_S(size, thiscpu->put_ids);
+}
+
+void set_max_cpu_num(void)
+{
+	FILE *filep;
+	unsigned long dummy;
+
+	topo.max_cpu_num = 0;
+	filep = fopen_or_die(
+			"/sys/devices/system/cpu/cpu0/topology/thread_siblings",
+			"r");
+	while (fscanf(filep, "%lx,", &dummy) == 1)
+		topo.max_cpu_num += BITMASK_SIZE;
+	fclose(filep);
+	topo.max_cpu_num--; /* 0 based */
+}
+
+#endif
+/*
  * MSR_PKG_CST_CONFIG_CONTROL decoding for pkg_cstate_limit:
  * If you change the values, note they are used both in comparisons
  * (>= PCL__7) and to index pkg_cstate_limit_strings[].
@@ -2540,30 +2890,7 @@ int parse_int_file(const char *fmt, ...)
 	return value;
 }
 
-/*
- * cpu_is_first_core_in_package(cpu)
- * return 1 if given CPU is 1st core in package
- */
-int cpu_is_first_core_in_package(int cpu)
-{
-	return cpu == parse_int_file("/sys/devices/system/cpu/cpu%d/topology/core_siblings_list", cpu);
-}
 
-int get_physical_package_id(int cpu)
-{
-	return parse_int_file("/sys/devices/system/cpu/cpu%d/topology/physical_package_id", cpu);
-}
-
-int get_die_id(int cpu)
-{
-	return parse_int_file("/sys/devices/system/cpu/cpu%d/topology/die_id", cpu);
-}
-
-int get_core_id(int cpu)
-{
-	return parse_int_file("/sys/devices/system/cpu/cpu%d/topology/core_id", cpu);
-}
-
 void set_node_data(void)
 {
 	int pkg, node, lnode, cpu, cpux;
@@ -2605,71 +2932,8 @@ void set_node_data(void)
 	}
 }
 
-int get_physical_node_id(struct cpu_topology *thiscpu)
-{
-	char path[80];
-	FILE *filep;
-	int i;
-	int cpu = thiscpu->logical_cpu_id;
 
-	for (i = 0; i <= topo.max_cpu_num; i++) {
-		sprintf(path, "/sys/devices/system/cpu/cpu%d/node%i/cpulist",
-			cpu, i);
-		filep = fopen(path, "r");
-		if (!filep)
-			continue;
-		fclose(filep);
-		return i;
-	}
-	return -1;
-}
 
-int get_thread_siblings(struct cpu_topology *thiscpu)
-{
-	char path[80], character;
-	FILE *filep;
-	unsigned long map;
-	int so, shift, sib_core;
-	int cpu = thiscpu->logical_cpu_id;
-	int offset = topo.max_cpu_num + 1;
-	size_t size;
-	int thread_id = 0;
-
-	thiscpu->put_ids = CPU_ALLOC((topo.max_cpu_num + 1));
-	if (thiscpu->thread_id < 0)
-		thiscpu->thread_id = thread_id++;
-	if (!thiscpu->put_ids)
-		return -1;
-
-	size = CPU_ALLOC_SIZE((topo.max_cpu_num + 1));
-	CPU_ZERO_S(size, thiscpu->put_ids);
-
-	sprintf(path,
-		"/sys/devices/system/cpu/cpu%d/topology/thread_siblings", cpu);
-	filep = fopen_or_die(path, "r");
-	do {
-		offset -= BITMASK_SIZE;
-		if (fscanf(filep, "%lx%c", &map, &character) != 2)
-			err(1, "%s: failed to parse file", path);
-		for (shift = 0; shift < BITMASK_SIZE; shift++) {
-			if ((map >> shift) & 0x1) {
-				so = shift + offset;
-				sib_core = get_core_id(so);
-				if (sib_core == thiscpu->physical_core_id) {
-					CPU_SET_S(so, size, thiscpu->put_ids);
-					if ((so != cpu) &&
-					    (cpus[so].thread_id < 0))
-						cpus[so].thread_id =
-								    thread_id++;
-				}
-			}
-		}
-	} while (!strncmp(&character, ",", 1));
-	fclose(filep);
-
-	return CPU_COUNT_S(size, thiscpu->put_ids);
-}
-
 /*
  * run func(thread, core, package) in topology order
  * skip non-present cpus
@@ -2724,6 +2988,22 @@ int for_all_cpus_2(int (func)(struct thread_data *, st
 	return 0;
 }
 
+#ifdef __FreeBSD__
+int for_all_proc_cpus(int (func)(int))
+{
+	int retval;
+
+	if (!ncpus)
+		read_topology_spec();
+
+	for (long i = 0; i < ncpus; i++) {
+		retval = func(i);
+		if (retval)
+			return retval;
+	}
+	return 0;
+}
+#else
 /*
  * run func(cpu) on every cpu in /proc/stat
  * return max_cpu number
@@ -2754,6 +3034,7 @@ int for_all_proc_cpus(int (func)(int))
 	fclose(fp);
 	return 0;
 }
+#endif
 
 void re_initialize(void)
 {
@@ -2762,21 +3043,7 @@ void re_initialize(void)
 	printf("turbostat: re-initialized with num_cpus %d\n", topo.num_cpus);
 }
 
-void set_max_cpu_num(void)
-{
-	FILE *filep;
-	unsigned long dummy;
 
-	topo.max_cpu_num = 0;
-	filep = fopen_or_die(
-			"/sys/devices/system/cpu/cpu0/topology/thread_siblings",
-			"r");
-	while (fscanf(filep, "%lx,", &dummy) == 1)
-		topo.max_cpu_num += BITMASK_SIZE;
-	fclose(filep);
-	topo.max_cpu_num--; /* 0 based */
-}
-
 /*
  * count_cpus()
  * remember the last one seen, it will be the max
@@ -2798,6 +3065,89 @@ int init_thread_id(int cpu)
 	return 0;
 }
 
+#ifdef __FreeBSD__
+static struct {
+	uint64_t intr_num;
+	uint64_t cpu_num;
+} *intr_map = NULL;
+static size_t intr_map_len = 0;
+static size_t intr_map_cap = 0;
+
+static void ensure_intr_map(void)
+{
+	if (intr_map_cap > intr_map_len)
+		return;
+
+	if (intr_map_cap)
+		intr_map_cap *= 2;
+	else
+		intr_map_cap = 2;
+
+	intr_map = realloc(intr_map, intr_map_cap * sizeof(*intr_map));
+}
+
+static void init_intr_map(void)
+{
+	size_t sz = 0;
+	if (sysctlbyname("hw.intrs", NULL, &sz, NULL, 0)) {
+		warn("sysctl: hw.intrs: per-cpu interrupt data will be unavailable");
+		return;
+	}
+	char *intrs = alloca(sz);
+	if (sysctlbyname("hw.intrs", intrs, &sz, NULL, 0)) {
+		warn("sysctl: hw.intrs: per-cpu interrupt data will be unavailable");
+		return;
+	}
+
+	char *i = intrs;
+	char *j;
+	while ((j = strstr(i, "@cpu")) != NULL) {
+		char *k;
+		for (k = j; k > i && *k != ':'; k--)
+			;
+		if (*k != ':')
+			errx(1, "init_intr_map: parse failed");
+		k++;
+		uint64_t intr_num;
+		if (sscanf(k, "%ld", &intr_num) != 1)
+			errx(1, "init_intr_map: parse failed");
+		j += 4;
+		uint64_t cpu_num;
+		if (sscanf(j, "%ld", &cpu_num) != 1)
+			errx(1, "init_intr_map: parse failed");
+		ensure_intr_map();
+		intr_map[intr_map_len].intr_num = intr_num;
+		intr_map[intr_map_len].cpu_num = cpu_num;
+		intr_map_len++;
+
+		i = j;
+	}
+}
+
+int snapshot_proc_interrupts(void)
+{
+	if (!intr_map)
+		init_intr_map();
+
+	size_t sz = 0;
+	if (sysctlbyname("hw.intrcnt", NULL, &sz, NULL, 0))
+		err(1, "sysctl: hw.intrcnt: failed");
+	uint64_t *intrcnt = alloca(sz);
+	if (sysctlbyname("hw.intrcnt", intrcnt, &sz, NULL, 0))
+		err(1, "sysctl: hw.intrcnt: failed");
+
+	for (int i = 0; i < topo.num_cpus; i++)
+		irqs_per_cpu[i] = 0;
+	for (int i = 0; i < intr_map_len; i++)
+		irqs_per_cpu[intr_map[i].cpu_num] += intrcnt[intr_map[i].intr_num];
+
+	return 0;
+}
+int snapshot_proc_sysfs_files(void)
+{
+		return 0;
+}
+#else
 /*
  * snapshot_proc_interrupts()
  *
@@ -2861,6 +3211,7 @@ int snapshot_proc_interrupts(void)
 	}
 	return 0;
 }
+
 /*
  * snapshot_gfx_rc6_ms()
  *
@@ -2989,6 +3340,7 @@ int snapshot_proc_sysfs_files(void)
 
 	return 0;
 }
+#endif
 
 int exit_requested;
 
@@ -3140,6 +3492,18 @@ restart:
 	}
 }
 
+#ifdef __FreeBSD__
+#define check_dev_msr()
+
+void check_permissions()
+{
+	if (eaccess("/dev/cpuctl0", F_OK))
+		err(errno, "/dev/cpuctl0 missing, kldload cpuctl");
+	if (eaccess("/dev/cpuctl0", R_OK))
+		err(errno, "cannot read /dev/cpuctl0, (run as root?)");
+}
+
+#else
 void check_dev_msr()
 {
 	struct stat sb;
@@ -3188,6 +3552,7 @@ void check_permissions()
 	if (do_exit)
 		exit(-6);
 }
+#endif
 
 /*
  * NHM adds support for additional MSRs:
@@ -5192,8 +5557,21 @@ void setup_all_buffers(void)
 	for_all_proc_cpus(initialize_counters);
 }
 
+#ifdef __FreeBSD__
 void set_base_cpu(void)
 {
+	struct kinfo_proc *proc = kinfo_getproc(getpid());
+	if (!proc || proc->ki_oncpu == NOCPU)
+		err(-ENODEV, "Failed to lookup curcpu");
+	base_cpu = proc->ki_oncpu;
+	free(proc);
+
+	if (debug > 1)
+		fprintf(outf, "base_cpu = %d\n", base_cpu);
+}
+#else
+void set_base_cpu(void)
+{
 	base_cpu = sched_getcpu();
 	if (base_cpu < 0)
 		err(-ENODEV, "No valid cpus found");
@@ -5201,6 +5579,7 @@ void set_base_cpu(void)
 	if (debug > 1)
 		fprintf(outf, "base_cpu = %d\n", base_cpu);
 }
+#endif
 
 void turbostat_init()
 {
@@ -5769,7 +6148,9 @@ int main(int argc, char **argv)
 	if (!quiet)
 		print_version();
 
-	probe_sysfs();
+    #ifndef __FreeBSD__
+		probe_sysfs();
+    #endif
 
 	turbostat_init();
 
