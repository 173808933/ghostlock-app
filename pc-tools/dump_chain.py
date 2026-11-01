#!/usr/bin/env python3
"""Dump the getsockopt / futex call chains from the target Image.

Purpose: find the stack local that hosts `struct tcp_zerocopy_receive zc`
inside do_tcp_getsockopt (inlined tcp_zerocopy_receive), and the
`struct rt_mutex_waiter` local inside futex_wait_requeue_pi, so we can compute
the zc->waiter delta the tcp_zerocopy route hardcodes.

This is the exploratory half; derive_tcp.py does the final arithmetic.

Usage: dump_chain.py [Image] [symbols.json]
"""
import json
import re
import sys

import capstone

IMAGE = sys.argv[1] if len(sys.argv) > 1 else "Image"
SYMS = sys.argv[2] if len(sys.argv) > 2 else "symbols.json"
BASE = 0xFFFFFFC008000000
CAP = 0x1200

data = open(IMAGE, "rb").read()
syms = {k: int(v, 16) for k, v in json.load(open(SYMS, encoding="utf-8")).items()}
offs = {k: v - BASE for k, v in syms.items()}
sorted_offsets = sorted(offs.values())
addr2name = {v - BASE: k for k, v in syms.items()}

md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
md.detail = True


def sym_off(name):
    if name not in offs:
        sys.exit(f"FATAL: symbol {name} missing")
    return offs[name]


def disasm(name, cap=CAP):
    start = sym_off(name)
    higher = next((o for o in sorted_offsets if o > start), start + cap)
    stop = min(start + cap, higher)
    return list(md.disasm(data[start:stop], start))


def frame(name, insns):
    """(total frame, list of (offset, description)) from the prologue."""
    total = 0
    sub_seen = False
    events = []
    for ins in insns:
        m = re.search(r"(?i)stp\s+x29,\s*x30,\s*\[sp,\s*#-0x([0-9a-f]+)\]!", ins.op_str)
        if m:
            total += int(m.group(1), 16)
            events.append((int(m.group(1), 16), "stp x29,x30,[sp,#-..]!"))
        if not sub_seen:
            m = re.search(r"(?i)sub\s+sp,\s*sp,\s*#0x([0-9a-f]+)", ins.op_str)
            if m:
                total += int(m.group(1), 16)
                sub_seen = True
                events.append((int(m.group(1), 16), "sub sp,sp,#.."))
    return total, events


def targets(insns):
    out = []
    for ins in insns:
        if ins.mnemonic in ("bl", "b") and ins.operands and ins.operands[0].type == capstone.arm64.ARM64_OP_IMM:
            t = ins.operands[0].imm
            out.append((ins.mnemonic, t, addr2name.get(t, "?")))
        if ins.mnemonic == "blr":
            out.append(("blr", 0, "(indirect)"))
    return out


def report(name):
    insns = disasm(name)
    tot, ev = frame(name, insns)
    print(f"\n===== {name} @ {sym_off(name):#x}  len={len(insns)}  frame=0x{tot:x} =====")
    print(f"  prologue: {[(hex(a), d) for a, d in ev]}")
    tg = [(m, hex(t), n) for m, t, n in targets(insns)]
    print(f"  calls: {tg[:40]}")
    # interesting stack locals
    adds = []
    for ins in insns:
        m = re.search(r"(?i)add\s+(x\d+|w\d+),\s*sp,\s*#0x([0-9a-f]+)", ins.op_str)
        if m:
            adds.append((m.group(1).lower(), int(m.group(2), 16)))
    uniq = sorted({(r, i) for r, i in adds})
    print(f"  add <reg>,sp,#imm: {[(r, hex(i)) for r, i in uniq]}")
    movs = sorted({int(m.group(1), 16) for ins in insns
                   for m in [re.search(r"(?i)\bmov\s+w\d+,\s*#0x([0-9a-f]+)", ins.op_str)] if m})
    print(f"  mov wN,#imm: {[hex(v) for v in movs]}")
    return insns


for n in ["__arm64_sys_getsockopt", "__sys_getsockopt", "sock_common_getsockopt",
          "tcp_getsockopt", "do_tcp_getsockopt",
          "__arm64_sys_futex", "do_futex", "futex_wait_requeue_pi"]:
    report(n)
