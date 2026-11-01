#!/usr/bin/env python3
"""Generate the GhostLock kernel profile (HOCON) for OPPO Find X7 Ultra PHY110.

Kernel: 6.1.141-android14-11-o-g984c12362a16 (android14-6.1 GKI, OPPO sm8650 tree)

Sources (all local, offline):
  - symbols.json  : kallsyms extracted from the device boot.img Image
  - BTF in Image  : struct layouts (verified 15/15 identical to the 6.1.145
                    baseline profile shipped in YuKongA/ghostlock-app)
  - device /proc/slabinfo : mm_struct object size (1024)
  - verified runtime facts: phys load 0xa8000000, DRAM base 0x80000000
    (PHYS_LAYOUT_PASS memstart=0x80000000 image_phys=0xa8000000, confirmed
    repeatedly on device by the 64560 chain)

Derivations:
  - selinux_enforcing  := selinux_state symbol address (BTF: enforcing @ +0)
  - slide_loggers_0_1  := loggers + 8   (derive.rs: loggers + ulog_value*8,
                          NF_LOG_TYPE_ULOG=1)
  - slide_boot_id      := sysctl_bootid (ctl_table entry, slide oracle)
"""
import json
import sys

BASE = "C:/Other/Andriod/ROM/phy110_extract"
IMAGE_BASE = 0xFFFFFFC008000000

RELEASE = "6.1.141-android14-11-o-g984c12362a16"

# task_struct offsets: BTF of THIS kernel (identical to 6.1.145 baseline, but
# taken from our own Image so the profile is self-consistent).
TASK = {
    "prio": 0x84,            # 132
    "normal_prio": 0x8C,     # 140
    "sched_task_group": 0x348,   # 840
    "pi_lock": 0x924,        # 2340
    "pi_waiters": 0x938,     # 2360
    "pi_top_task": 0x948,    # 2376
    "pi_blocked_on": 0x950,  # 2384
    "pid": 0x630,            # 1584
    "tgid": 0x634,           # 1588
    "atomic_flags": 0x5F0,   # 1520
    "real_cred": 0x830,      # 2096
    "cred": 0x838,           # 2104
    "comm": 0x848,           # 2120
    "tasks": 0x550,          # 1360
    "seccomp": 0x900,        # 2304
}


def off(syms, name):
    v = syms.get(name)
    if v is None:
        sys.exit(f"FATAL: symbol {name} missing from symbols.json")
    return int(v, 16) - IMAGE_BASE


def main():
    syms = json.load(open(f"{BASE}/symbols.json", encoding="utf-8"))

    o = {
        "empty_zero_page": off(syms, "empty_zero_page"),
        "init_task": off(syms, "init_task"),
        "init_cred": off(syms, "init_cred"),
        "root_task_group": off(syms, "root_task_group"),
        "selinux_enforcing": off(syms, "selinux_state"),  # BTF: enforcing @ +0
        "selinux_blob_sizes": off(syms, "selinux_blob_sizes"),
        "security_hook_heads": off(syms, "security_hook_heads"),
        "slide_nfulnl_logger": off(syms, "nfulnl_logger"),
        "slide_loggers_0_1": off(syms, "loggers") + 8,   # NF_LOG_TYPE_ULOG = 1
        "slide_boot_id": off(syms, "sysctl_bootid"),
    }

    conf = f'''# GhostLock kernel profile: {RELEASE}
# Generated for OPPO Find X7 Ultra (PHY110 / OP565FL1) from local Image analysis.
# task_struct fields BTF-verified identical to the upstream 6.1 baseline.
# phys values verified on-device (64560 PHYS_LAYOUT_PASS, multiple boots).

include "credential-6x.conf"
include "kernelsnitch-6x.conf"
release = "{RELEASE}"
schema_version = 1
kernel_major = 6
recommend_shizuku = 0
kernel_phys_load = {0xA8000000:#x}
kernel_phys_offset = {0x80000000:#x}
route {{
  tcp_zerocopy {{
    compact_waiter = 1
  }}
}}
fallback {{
  to = "select_stack"
  route {{
    select_stack {{
      waiter_shift = 1
    }}
  }}
}}
kernelsnitch {{
  collisions = 4
  mm_struct_sz = 1024
}}
task_struct {{
'''
    for k, v in TASK.items():
        conf += f"  {k} = {v}\n"
    conf += "}\noffset {\n"
    for k, v in o.items():
        conf += f"  {k} = {v:#x}\n"
    conf += "}\n"

    out = f"{BASE}/ghostlock-phy110.conf"
    open(out, "w", encoding="utf-8").write(conf)
    print(f"wrote {out}")
    print()
    for k, v in o.items():
        print(f"  {k:24s} {v:#x}")


if __name__ == "__main__":
    main()
