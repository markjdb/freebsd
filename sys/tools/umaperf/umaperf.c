#ifdef __FreeBSD__
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/counter.h>
#include <sys/kernel.h>
#include <sys/libkern.h>
#include <sys/epoch.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/kthread.h>
#include <sys/conf.h>
#include <sys/smp.h>
#include <sys/smr.h>
#include <sys/sched.h>

#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/uma.h>
#include <vm/uma_int.h>

static const char *umaperf_system = "FreeBSD";

#else

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/random.h>
#include <linux/delay.h>
#include <linux/ktime.h>
#include <linux/mm.h>
#include <linux/gfp.h>
#include <linux/cpu.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/atomic.h>
#include <linux/kthread.h>
#include <linux/rculist.h>
#include "slab.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jeffrey W. Roberson");
MODULE_DESCRIPTION("Allocator perf test");
MODULE_VERSION("0.01");

static inline uintptr_t
atomic_swap_ptr(volatile uintptr_t *p, uintptr_t v)
{
	return (atomic64_xchg((atomic64_t *)p, v));
}

static inline int 
atomic_cmpset_ptr(volatile uintptr_t *p, uintptr_t old, uintptr_t new)
{

	return (atomic64_cmpxchg((atomic64_t *)p, old, new) == old);
}

static inline void
atomic_subtract_64(volatile uint64_t *p, int n)
{

	atomic64_sub(n, (atomic64_t *)p);
}

static inline uint64_t
atomic_fetchadd_64(volatile uint64_t *p, int n)
{

	return (atomic64_add_return(n, (atomic64_t *)p) - n);
}


static inline void
atomic_add_int(volatile int *p, int n)
{

	atomic_add(n, (atomic_t *)p);
}

#define	atomic_thread_fence_seq_cst()	barrier()
#define	critical_enter()	do { } while(0)
#define	critical_exit()		do { } while(0)
#define	get_cyclecount()	get_cycles()

#define	random()		get_random_u32()

#define	MAXCPU			NR_CPUS
#define	mp_ncpus		num_online_cpus()
#define	vm_ndomains		nr_online_nodes

typedef struct kmem_cache	*uma_zone_t;
#define	uma_zalloc(x, f)	kmem_cache_alloc((x), (f))
#define	uma_zfree(x, p)		kmem_cache_free((x), (p))

#define	M_WAITOK		GFP_KERNEL

typedef ktime_t			sbintime_t;
#define	sbinuptime()		ktime_get()
#define	sbttons(x)		ktime_to_ns((x))
#define	sbttoms(x)		ktime_to_ms((x))
#define	kthread_add(fn, upc, proc, newtdp, flags, pages, fmt, ...)	\
do {									\
	struct task_struct *_t = kthread_create(			\
	    (int(*)(void *))fn, upc, fmt, ##__VA_ARGS__);		\
	if (upc != NULL)						\
		kthread_bind(_t, (upc)->upc_cpu);			\
	wake_up_process(_t);						\
} while (0)
/* #define	printf(fmt, ...)	printk(KERN_WARNING fmt, ##__VA_ARGS__) */
#define	printf			printk
#define	uma_zcreate(name, size, ctor, dtor, init, fini, align, flags)	\
    kmem_cache_create((name), (size), (align), flags, NULL)
#define	uma_zdestroy(x)		kmem_cache_destroy((x))
#define	UMA_ALIGN_CACHE		64
#define	CACHE_LINE_SIZE		64

typedef struct rcu_head		*epoch_context_t;

#define	bzero(x, l)		memset((x), 0, (l))

#define	hz			HZ
#define	pause(s, t)		msleep((t))

#define	kern_yield(x)		cond_resched()
#define	kthread_exit()		do { } while(0)

#define	ticks			jiffies

#define	MAX(a,b)		(((a)>(b))?(a):(b))
#define	MIN(a,b)		(((a)<(b))?(a):(b))

#define	cpu_spinwait()		cpu_relax()

struct epoch_tracker { };

#define	nitems(x)		(sizeof((x)) / sizeof((x)[0]))

static size_t
uma_zone_memory(uma_zone_t zone)
{
	struct kmem_cache_node *n;
	size_t sz;
	int node;

	sz = 0;
	for_each_kmem_cache_node(zone, node, n)
		sz += atomic_long_read(&n->nr_slabs);
	/* XXX This is just the partial list. */

	return (sz * PAGE_SIZE);
}

static const char *umaperf_system = "Linux";

#endif

struct umaperf_cpu {
	volatile uintptr_t upc_head;
	volatile uint64_t upc_len;
	long		upc_allocs __aligned(CACHE_LINE_SIZE);
	long		upc_frees;
	long		upc_dequeues;	/* Number of dequeues. */
	long		upc_enqueues;	/* Number of enqueues. */
	long		upc_maxfree;	/* Maximum dequeue length */
	long		upc_maxmem;	/* Maximum zone memory. */
	int		upc_self;	/* self index. */
	int		upc_cpu;	/* cpu to bind to. */
	int		upc_dbase;	/* Base index of destination cpus. */
	int		upc_dlen;	/* Length of dest cpus. */
	struct epoch_tracker	upc_tracker;
} __aligned(CACHE_LINE_SIZE * 2);

struct umaperf_pkt {
	struct umaperf_pkt *p_next;
};

static enum {
	PLAIN,
#ifdef __FreeBSD__
	SMR,
	LAZY_SMR,
	DEFER_SMR,
	EPOCH,
	EPOCH_PRE,
#else
	RCU,
#if 0
	RCU_TYPESTABLE,
#endif
#endif
} umaperf_type = PLAIN;

static char *umaperf_type_name[] = {
	[PLAIN] = 	"PLAIN",
#ifdef __FreeBSD__
	[SMR] = 	"SMR",
	[LAZY_SMR] = 	"SMR_LAZY",
	[DEFER_SMR] = 	"SMR_DEFERRED",
	[EPOCH] = 	"EPOCH",
	[EPOCH_PRE] = 	"EPOCH_PREEMPT"
#else
	[RCU] =		"RCU",
#if 0
	[RCU_TYPESTABLE] = "RCU_TYPESTABLE"
#endif
#endif
};

static enum {
	RANDOM,
	LOCAL,
	REMOTE,
} umaperf_locality = LOCAL;

static char *umaperf_locality_name[] = {
	[RANDOM] =	"RANDOM",
	[LOCAL] =	"LOCAL",
	[REMOTE] =	"REMOTE"
};

static struct umaperf_cpu	up_cpu[MAXCPU];
static int umaperf_cpus;
static volatile int umaperf_started;
static volatile int umaperf_completed;
static int umaperf_pkts = 100;
static int umaperf_queue_limit = 16384;
static int umaperf_stat_interval = 200000 / 1000;
static int umaperf_test_time = 10;
static int umaperf_test_runs = 5;
static int umaperf_yield_frac = 0;
static int umaperf_zone_size = 1024;
static int umaperf_zero_size = 64;
static uma_zone_t umaperf_zone;
#ifdef __FreeBSD__
static int umaperf_smr_defer = 32;	/* up to 32 writes. */
static smr_t umaperf_smr;
static epoch_t umaperf_epoch;
#endif

static inline void
umaperf_enter(struct umaperf_cpu *upc)
{

	switch (umaperf_type) {
	case PLAIN:
		break;
#ifdef __FreeBSD__
	case SMR:
	case DEFER_SMR:
		smr_enter(umaperf_smr);
		break;
	case LAZY_SMR:
		smr_lazy_enter(umaperf_smr);
		break;
	case EPOCH:
		epoch_enter(umaperf_epoch);
		break;
	case EPOCH_PRE:
		epoch_enter_preempt(umaperf_epoch, &upc->upc_tracker);
		break;
#else
	case RCU:
		rcu_read_lock();
		break;
#endif
	}
}

static inline void
umaperf_exit(struct umaperf_cpu *upc)
{

	switch (umaperf_type) {
	case PLAIN:
		break;
#ifdef __FreeBSD__
	case SMR:
	case DEFER_SMR:
		smr_exit(umaperf_smr);
		break;
	case LAZY_SMR:
		smr_lazy_exit(umaperf_smr);
		break;
	case EPOCH:
		epoch_exit(umaperf_epoch);
		break;
	case EPOCH_PRE:
		epoch_exit_preempt(umaperf_epoch, &upc->upc_tracker);
		break;
#else
	case RCU:
		rcu_read_unlock();
		break;
#endif
	}
}

static void
umaperf_free_cb(epoch_context_t ctx)
{

	uma_zfree(umaperf_zone, ctx);
}

static void
umaperf_free(struct umaperf_pkt *p)
{

	switch (umaperf_type) {
	case PLAIN:
		uma_zfree(umaperf_zone, p);
		break;
#ifdef __FreeBSD__
	case SMR:
	case DEFER_SMR:
	case LAZY_SMR:
		uma_zfree_smr(umaperf_zone, p);
		break;
	case EPOCH:
	case EPOCH_PRE:
		epoch_call(umaperf_epoch, umaperf_free_cb, (epoch_context_t)p);
		break;
#else
	case RCU:
		call_rcu((epoch_context_t)p, umaperf_free_cb);
		break;
#endif
	}
}

static struct umaperf_pkt *
umaperf_alloc(void)
{

	switch (umaperf_type) {
#ifdef __FreeBSD__
	case SMR:
	case DEFER_SMR:
	case LAZY_SMR:
		return uma_zalloc_smr(umaperf_zone, M_WAITOK);
	case EPOCH:
	case EPOCH_PRE:
#else
	case RCU:
#endif
	default:
	case PLAIN:
		return uma_zalloc(umaperf_zone, M_WAITOK);
	}
}

static void
umaperf_dequeue(struct umaperf_cpu *upc)
{
	struct umaperf_pkt *p, *n;
	int cnt;

	/*
	 * Dequeue and free local packets.
	 */
	umaperf_enter(upc);
	p = (struct umaperf_pkt *)atomic_swap_ptr(&upc->upc_head,
	    (uintptr_t)NULL);
	umaperf_exit(upc);
	if (p == NULL)
		return;
	for (cnt = 0; p != NULL; p = n, cnt++) {
		n = p->p_next;
		umaperf_free(p);
	}
	if (umaperf_queue_limit != 0)
		atomic_subtract_64(&upc->upc_len, cnt);
	upc->upc_dequeues++;
	upc->upc_frees += cnt;
	upc->upc_maxfree = MAX(upc->upc_maxfree, cnt);
}

static bool
umaperf_enqueue(struct umaperf_cpu *self, struct umaperf_cpu *upc,
    struct umaperf_pkt *head, struct umaperf_pkt *tail, int cnt)
{

	if (umaperf_queue_limit != 0 &&
	    atomic_fetchadd_64(&upc->upc_len, cnt) >= umaperf_queue_limit) {
		atomic_subtract_64(&upc->upc_len, cnt);
		return (false);
	}

	/*
	 * Enqueue singly linked list.
	 */
	umaperf_enter(self);
	do {
		tail->p_next = (struct umaperf_pkt *)upc->upc_head;
	} while (atomic_cmpset_ptr(&upc->upc_head, (uintptr_t)tail->p_next,
	    (uintptr_t)head) == 0);
	umaperf_exit(self);
	self->upc_enqueues++;
	self->upc_allocs += cnt;

	return (true);
}

static void
umaperf_thread_setup(struct umaperf_cpu *upc)
{
#ifdef __FreeBSD__
	thread_lock(curthread);
	sched_class(curthread, PRI_ITHD);
	sched_prio(curthread, PVM);
	if (upc != NULL)
		sched_bind(curthread, upc->upc_cpu);
	thread_unlock(curthread);
#endif
	/* Binding after running is not exported on linux. */
}

static long
umaperf_yield_time(void)
{

	if (umaperf_yield_frac)
		return (ticks +  hz / umaperf_yield_frac);
	return (0);
}

static void
umaperf_send(struct umaperf_cpu *upc)
{
	struct umaperf_pkt *head, *tail, *p;
	int i, c;

	/*
	 * Allocate and touch multiple packets.
	 */
	head = tail = p = NULL;
	for (i = 0; i < umaperf_pkts; i++) {
		p = umaperf_alloc();
		bzero(p, umaperf_zero_size);
		if (head == NULL)
			head = p;
		else
			tail->p_next = p;
		tail = p;
	}

	/*
	 * Loop looking for a cpu to send work to.
	 */
	do {
		c = random() % upc->upc_dlen;
	} while (!umaperf_enqueue(upc, &up_cpu[c + upc->upc_dbase],
	    head, tail, umaperf_pkts));
}

sbintime_t umaperf_start_time;
sbintime_t umaperf_end_time;

static void
umaperf_thread(void *arg)
{
	struct umaperf_cpu *upc = arg;
	unsigned long switchtime;
	unsigned long exittime;
	bool completed;
	int i;

	umaperf_thread_setup(upc);
	if (atomic_fetchadd_int(&umaperf_started, 1) + 1 == umaperf_cpus)
		umaperf_start_time = sbinuptime();
	while (umaperf_started != umaperf_cpus)
		pause("prf", 1);

	exittime = ticks + (umaperf_test_time * hz);
	switchtime = umaperf_yield_time();
	completed = false;
	i = 0;
	while (umaperf_completed != umaperf_started) {
		if (ticks < exittime) {
			umaperf_send(upc);
		} else if (!completed) {
			completed = true;
			if (atomic_fetchadd_int(&umaperf_completed, 1) + 1 ==
			    umaperf_cpus)
				umaperf_end_time = sbinuptime();
		}
		if ((i % umaperf_stat_interval) == 0)
			upc->upc_maxmem = MAX(upc->upc_maxmem,
			    uma_zone_memory(umaperf_zone));

		/*
		 * Process local work.
		 */
		umaperf_dequeue(upc);

		if (umaperf_yield_frac && (long)(switchtime - ticks) < 0) {
			kern_yield(PRI_USER);
			switchtime = umaperf_yield_time();
		}
	}
	pause("prf", 1);
	umaperf_dequeue(upc);
	kthread_exit();
}

volatile uint32_t dummy = 0xdeadbeef;

static long 
umaperf_section_time(void)
{
	sbintime_t start, total;
	int cnt = 500000;
	int i;

	critical_enter();
	start = sbinuptime();
	switch (umaperf_type) {
#ifdef __linux__
	case RCU:
#endif
	case PLAIN:
		for (i = 1; i < cnt+1; i++) {
			dummy += i;
		}
		break;
#ifdef __FreeBSD__
	case SMR:
	case DEFER_SMR:
		for (i = 0; i < cnt; i++) {
			smr_enter(umaperf_smr);
			dummy += i;
			smr_exit(umaperf_smr);
		}
		break;
	case LAZY_SMR:
		for (i = 0; i < cnt; i++) {
			smr_lazy_enter(umaperf_smr);
			dummy += i;
			smr_lazy_exit(umaperf_smr);
		}
		break;
	case EPOCH:
		for (i = 0; i < cnt; i++) {
			epoch_enter(umaperf_epoch);
			dummy += i;
			epoch_exit(umaperf_epoch);
		}
		break;
	case EPOCH_PRE:
		{
			struct epoch_tracker et;
			for (i = 0; i < cnt; i++) {
				epoch_enter_preempt(umaperf_epoch, &et);
				dummy += i;
				epoch_exit_preempt(umaperf_epoch, &et);
			}
			break;
		}
#endif
	}
	critical_exit();
	total = sbinuptime() - start;
	start = total / cnt;

	return ((long)sbttons(start));
}

static void
umaperf_start(void *unused)
{
	long allocs, frees, pkts, maxfree, minfree, dequeues, sectime;
	long maxmem, maxsum;
	sbintime_t total;
	int i;

	umaperf_thread_setup(NULL);
	sectime = umaperf_section_time();
	umaperf_started = 0;
	umaperf_completed = 0;
	for (i = 0; i < umaperf_cpus; i++)
		kthread_add((void (*)(void *))umaperf_thread,
		    &up_cpu[i], curproc, NULL, 0, 0, "umaperf-%d", i);

	while (umaperf_completed != umaperf_cpus) {
		pause("prf", hz/2);
#if 0	/* DEBUG */
		printf("Running: %d, completed: %d, current: %d, Memory overhead: %ldMB\n",
		    umaperf_started, umaperf_completed,
		    uma_zone_get_cur(umaperf_zone),
		    (long)uma_zone_memory(umaperf_zone) / 1024 / 1024);
#endif
	}
	total = umaperf_end_time - umaperf_start_time;
	maxsum = maxmem = allocs = frees = maxfree = dequeues = 0;
	minfree = LONG_MAX;
	for (i = 0; i < umaperf_cpus; i++) {
		allocs += up_cpu[i].upc_allocs;
		frees += up_cpu[i].upc_frees;
		dequeues += up_cpu[i].upc_dequeues;
		maxfree = MAX(maxfree, up_cpu[i].upc_maxfree);
		minfree = MIN(minfree, up_cpu[i].upc_maxfree);
		maxsum += up_cpu[i].upc_maxfree;
		maxmem = MAX(maxmem, up_cpu[i].upc_maxmem);
	}
	if (dequeues == 0 || sbttoms(total) == 0) {
		printf("Test error.  dequeues %ld, allocs %ld, frees %ld, time %ld\n",
		    dequeues, allocs, frees, (long)total);
		return;
	}
	dequeues = frees / dequeues;
	pkts = (allocs/sbttoms(total)) * 1000;
	printf("UMAPERF: %s Type: %s, affinity: %s, ncpu: %d, numa domains: %d\n",
	    umaperf_system,
	    umaperf_type_name[umaperf_type],
	    umaperf_locality_name[umaperf_locality],
	    umaperf_cpus, vm_ndomains);
	printf("UMAPERF: ops: %ld, size: %d, zero size: %d, yields/s: %d\n",
	    allocs, umaperf_zone_size, umaperf_zero_size, umaperf_yield_frac);
	printf("UMAPERF: time: %ldms, section time: %ldns, memory: %ldM, ops/s/cpu: %ld\n",
	    (long)sbttoms(total), sectime, maxmem / 1024 / 1024,
	    pkts/umaperf_cpus);
	printf("UMAPERF: queue max: %ld, minmax: %ld, maxsum: %ld, queue average: %ld\n",
	    maxfree, minfree, maxsum, dequeues);
	printf("UMAPERF CSV,%s,%s,%s,%d,%d,%ld,%d,%d,%d,%ld,%ld,%ld,%ld,%ld,%ld,%ld,%ld\n",
	    umaperf_system,
	    umaperf_type_name[umaperf_type],
	    umaperf_locality_name[umaperf_locality], umaperf_cpus, vm_ndomains,
	    allocs, umaperf_zone_size, umaperf_zero_size, umaperf_yield_frac,
	    (long)sbttoms(total), sectime, maxfree, minfree, maxsum, dequeues,
	    maxmem, pkts/umaperf_cpus);
}

static void
umaperf_init_cpus(void)
{
	struct umaperf_cpu *upc;
	int dcpus, dbase, ucpus;
	int i, j, d;

	umaperf_cpus = mp_ncpus;
	bzero(&up_cpu, sizeof(up_cpu));
	ucpus = 0;

	if (umaperf_locality == RANDOM) {
		dcpus = umaperf_cpus;
		dbase = 0;
	} else {
		dcpus = umaperf_cpus / vm_ndomains;
		dbase = dcpus;
	}

#ifdef __FreeBSD__
	for (j = 0; j < vm_ndomains; j++) {
		if (umaperf_locality == REMOTE)
			d = (j + 1) % vm_ndomains;
		else
			d = j;
		for (i = 0; i < dcpus; i++) {
			upc = &up_cpu[ucpus];
			upc->upc_self = ucpus++;
			upc->upc_cpu = i + dcpus * j;
			upc->upc_dbase = dbase * d;
			upc->upc_dlen = dcpus;
		}
	}
#else
	const struct cpumask *cpus;
	for_each_node(j) {
		if (umaperf_locality == REMOTE)
			d = (j + 1) % vm_ndomains;
		else
			d = j;
		cpus = cpumask_of_node(j);
		for_each_cpu(i, cpus) {
			upc = &up_cpu[ucpus];
			upc->upc_self = ucpus++;
			upc->upc_cpu = i;
			upc->upc_dbase = dbase * d;
			upc->upc_dlen = dcpus;
		}
	}
#endif
}

static void
umaperf_fini(void)
{

#ifdef __FreeBSD__
	if (umaperf_epoch != NULL)
		epoch_free(umaperf_epoch);
	umaperf_epoch = NULL;
	umaperf_smr = NULL;
#else
	synchronize_rcu();
#endif
	if (umaperf_zone != NULL)
		uma_zdestroy(umaperf_zone);
	umaperf_zone = NULL;
}

static void
umaperf_init(void)
{
	int flags;

	if (umaperf_zone != NULL)
		umaperf_fini();

#ifdef __FreeBSD__
	flags = UMA_ZONE_MAXBUCKET;
	if (umaperf_locality == LOCAL)
		flags |= UMA_ZONE_FIRSTTOUCH;
	else
		flags |= UMA_ZONE_ROUNDROBIN;
#endif
	switch (umaperf_type) {
#ifdef __FreeBSD__
	case PLAIN:
		break;
	case SMR:
		umaperf_smr = smr_create("umaperf", 0, 0);
		break;
	case DEFER_SMR:
		umaperf_smr = smr_create("umaperf", umaperf_smr_defer,
		    SMR_DEFERRED);
		break;
	case LAZY_SMR:
		umaperf_smr = smr_create("umaperf", 0, SMR_LAZY);
		break;
	case EPOCH:
		umaperf_epoch = epoch_alloc("umaperf", 0);
		break;
	case EPOCH_PRE:
		umaperf_epoch = epoch_alloc("umaperf", EPOCH_PREEMPT);
		break;
#else
	case PLAIN:
		/* Set to prevent slab merging so we get independent stats. */
	case RCU:
		flags = SLAB_NOLEAKTRACE;
		break;
#endif
	}

	umaperf_zone = uma_zcreate("umaperf", umaperf_zone_size,
	    NULL, NULL, NULL, NULL, UMA_ALIGN_CACHE, flags);
#ifdef __FreeBSD__
	if (umaperf_smr != NULL)
		uma_zone_set_smr(umaperf_zone, umaperf_smr);
#endif
	umaperf_init_cpus();
}

static void
umaperf_run(void)
{
	int i;

	for (i = 0; i < umaperf_test_runs; i++) {
		umaperf_init();
		umaperf_start(NULL);
		pause("testslp", hz);
	}
}

static void
umaperf_test(void *unused)
{
	static int sizes[] = { 128, 256, 512, 1024, 2048, 4096 };
	static int zeros[] = { 128, 256, 512, 1024 };
	static int locality[] = { RANDOM, LOCAL, REMOTE};
#ifdef __FreeBSD__
	static int types[] = { PLAIN, SMR, LAZY_SMR, EPOCH };
	static int yields[] = { 0, 0, 0, 100 };
#else
	/* Linux requires yields or it will crash. */
	static int types[] = { PLAIN, RCU };
	static int yields[] = { 100, 100 };
#endif
#if 0
	static int sizes[] = { 64 };
	static int zeros[] = { 64 };
	static int types[] = { PLAIN };
	static int locality[] = { LOCAL };
	static int yields[] = { 0 };
#endif
	int s, z, t, l;

	printf("UMAPERF CSV,header,system,type,locality,cpus,domains,"
	    "ops,size,zero,yields,time,sectiontime,maxfree,minfree,maxsum,"
	    "avgfree,maxmem,cpuops\n");

	for (t = 0; t < nitems(types); t++) {
		umaperf_type = types[t];
		umaperf_yield_frac = yields[t];
		for (l = 0; l < nitems(locality); l++) {
			umaperf_locality = locality[l];
			umaperf_zero_size = 64;
			for (s = 0; s < nitems(sizes); s++) {
				umaperf_zone_size = sizes[s];
				umaperf_run();
			}
			umaperf_zone_size = 1024;
			for (z = 0; z < nitems(zeros); z++) {
				umaperf_zero_size = zeros[z];
				umaperf_run();
			}
		}
	}
	kthread_exit();
}

#ifdef __FreeBSD__
static int
umaperf_modevent(module_t mod, int what, void *arg)
{

	switch (what) {
	case MOD_LOAD:
		kthread_add((void (*)(void *))umaperf_test,
		    NULL, curproc, NULL, 0, 0, "umaperf");
		break;
	case MOD_UNLOAD:
		umaperf_fini();
		break;
	default:
		break;
	}
	return (0);
}

moduledata_t umaperf_meta = {
	"umaperf",
	umaperf_modevent,
	NULL
};
DECLARE_MODULE(umaperf, umaperf_meta, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
MODULE_VERSION(umaperf, 1);
#else

static int __init
umaperf_modinit(void) {
	umaperf_init();
	kthread_add(umaperf_test,
	    &up_cpu[0], curproc, NULL, 0, 0, "umaperf");
	return 0;
}

static void __exit
umaperf_modexit(void) {
	umaperf_fini();
	printk(KERN_INFO "Goodbye, World!\n");
}
module_init(umaperf_modinit);
module_exit(umaperf_modexit);
#endif
