#!/usr/bin/env python3
"""Derive the tcp_zerocopy stack delta for the target kernel Image.

The tcp_zerocopy route punches a getsockopt stack frame over a stale
rt_mutex_waiter left behind by an earlier futex_wait_requeue_pi.  It hardcodes

    zc[0x18] -> waiter->?            (copybuf_address)
    zc[0x20] -> waiter->?            (copybuf_len)
    zc[0x28] -> waiter->task
    zc[0x30] -> waiter->lock

which is only correct when  waiter_addr == zc_addr + 0x08 on the 6.1 layout
(task@0x30, lock@0x38) or +0x28 on the 6.6 layout (task@0x50, lock@0x58).

This tool measures the real delta from the Image:

    waiter_addr = -(Σ futex frames)     + waiter_local   (futex_wait_requeue_pi)
    zc_addr     = -(Σ getsockopt frames) + zc_local      (do_tcp_getsockopt)
    delta       = waiter_addr - zc_addr

Analogous to tools/derive_pselect.py (same frame-sum convention).

Usage: derive_tcp.py [Image] [symbols.json]
"""
import json
import re
import sys

import capstone

IMAGE = sys.argv[1] if len(sys.argv) > 1 else "Image"
SYMS = sys.argv[2] if len(sys.argv) > 2 else "symbols.json"
BASE = 0xFFFFFFC008000000
CAP = 0x3000

data = open(IMAGE, "rb").read()
syms = {k: int(v, 16) for k, v in json.load(open(SYMS, encoding="utf-8")).items()}
offs = {k: v - BASE for k, v in syms.items()}
so = sorted(offs.values())
addr2 = {v - BASE: k for k, v in syms.items()}

md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
md.detail = True


def lines(name, cap=CAP):
    s = offs[name]
    h = next((o for o in so if o > s), s + cap)
    return [
        (x.address, f"{x.mnemonic}\t{x.op_str}")
        for x in md.disasm(data[s:min(s + cap, h)], s)
    ], (s, min(s + cap, h))


def frame(name):
    """Return the function's own prologue allocation."""
    L, _ = lines(name)
    total = 0
    sub_done = False
    ev = []
    for _, l in L:
        m = re.match(r"(?i)^stp\tx29, x30, \[sp, #-0x([0-9a-f]+)\]!", l)
        if m:
            total += int(m.group(1), 16)
            ev.append(("stp", int(m.group(1), 16)))
        if not sub_done:
            m = re.match(r"(?i)^sub\tsp, sp, #0x([0-9a-f]+)", l)
            if m:
                total += int(m.group(1), 16)
                sub_done = True
                ev.append(("sub", int(m.group(1), 16)))
    return total, ev


def calls(name):
    s = offs[name]
    h = next((o for o in so if o > s), s + CAP)
    out = []
    for x in md.disasm(data[s:min(s + CAP, h)], s):
        if x.mnemonic in ("bl", "b") and x.operands and \
                x.operands[0].type == capstone.arm64.ARM64_OP_IMM:
            out.append((x.mnemonic, x.operands[0].imm, addr2.get(x.operands[0].imm, "?")))
        elif x.mnemonic == "blr":
            out.append(("blr", -1, "(indirect)"))
    return out


print("=== frames (own prologue) ===")
cand = ["__arm64_sys_getsockopt", "__sys_getsockopt", "sock_getsockopt",
        "sock_common_getsockopt", "tcp_getsockopt", "do_tcp_getsockopt",
        "__arm64_sys_futex", "do_futex", "futex_wait_requeue_pi"]
fr = {}
for n in cand:
    f, ev = frame(n)
    fr[n] = f
    print(f"  {n:28s} 0x{f:x}   {[(k, hex(v)) for k, v in ev]}")

print("\n=== link checks ===")
for n in ["__arm64_sys_getsockopt", "__sys_getsockopt", "sock_getsockopt",
          "sock_common_getsockopt", "tcp_getsockopt", "do_tcp_getsockopt"]:
    cs = calls(n)
    keep = [c for c in cs if any(k in c[2] for k in
            ("getsockopt", "sock_", "tcp_", "copy_", "memset", "fdget"))]
    print(f"  {n:28s} -> {keep[:12]}")

# ---- futex waiter local -------------------------------------------------
F, _ = lines("futex_wait_requeue_pi")
waiter_local = None
for i, (_, l) in enumerate(F):
    m = re.match(r"(?i)^mov\tw2, #0x58\b", l)
    if not m:
        continue
    for j in range(i - 1, max(-1, i - 4), -1):
        mm = re.match(r"(?i)^add\t(x\d+), sp, #0x([0-9a-f]+)", F[j][1])
        if mm:
            waiter_local = int(mm.group(2), 16)
            break
    if waiter_local is not None:
        break
print(f"\n=== futex_wait_requeue_pi: rt_mutex_waiter memset(size 0x58) at sp+{hex(waiter_local) if waiter_local is not None else 'N/A'} ===")

# ---- zc local ----------------------------------------------------------
D, _ = lines("do_tcp_getsockopt")
adds = {}
for _, l in D:
    m = re.match(r"(?i)^add\t(x\d+), sp, #0x([0-9a-f]+)", l)
    if m:
        adds.setdefault(int(m.group(2), 16), set()).add(m.group(1).lower())
print(f"=== do_tcp_getsockopt: add xN, sp, #imm -> {sorted((hex(k), sorted(v)) for k, v in adds.items())} ===")

# the zc struct is handed to tcp_zerocopy_vm_insert_batch; find the bl and the
# register that holds sp+imm at that point
insert = offs["tcp_zerocopy_vm_insert_batch"]
zc_cands = []
for i, (addr, l) in enumerate(D):
    if not re.match(r"(?i)^bl\t#0x%x$" % insert, l):
        continue
    regs = []
    for j in range(max(0, i - 12), i):
        mm = re.match(r"(?i)^add\t(x\d+), sp, #0x([0-9a-f]+)", D[j][1])
        if mm:
            regs.append((mm.group(1).lower(), int(mm.group(2), 16)))
    print(f"\n  bl tcp_zerocopy_vm_insert_batch at 0x{addr:x}: add sp refs {[(r, hex(v)) for r, v in regs]}")
    zc_cands.append(regs)
print(f"\n  insert_batch bl count = {len(zc_cands)}")

# ---- arithmetic --------------------------------------------------------
gs_sum = fr["__arm64_sys_getsockopt"] + fr["sock_getsockopt"] + \
         fr["tcp_getsockopt"] + fr["do_tcp_getsockopt"]
futex_sum = fr["__arm64_sys_futex"] + fr["futex_wait_requeue_pi"]
print(f"\n=== sums ===\n  getsockopt chain sum (sys+sock_getsockopt+tcp_getsockopt+do_tcp_getsockopt) = 0x{gs_sum:x}")
print(f"  futex chain sum (__arm64_sys_futex + futex_wait_requeue_pi) = 0x{futex_sum:x}")
if waiter_local is not None:
    waiter_abs = -futex_sum + waiter_local
    print(f"  waiter_abs = {waiter_abs:+#x}   (frame_sum 0x{futex_sum:x}, local +0x{waiter_local:x})")
    for off in sorted(adds):
        zc_abs = -gs_sum + off
        delta = waiter_abs - zc_abs
        print(f"    zc_local +0x{off:<5x} -> zc_abs {zc_abs:+#x}  delta(waiter-zc) = {delta:+#x} ({delta})")
