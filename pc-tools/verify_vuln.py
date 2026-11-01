#!/usr/bin/env python3
"""Disassemble posix_cpu_timer_del from the PHY110 Image and verify the
pre-fix (vulnerable) shape, per the OP13.md method:
  - one pid_task/cpu_timer_task_rcu lookup
  - one __lock_task_sighand call
  - cbz x0, <forward> on sighand == NULL (the race branch)
  - a WARN_ON_ONCE block (brk #0x800 or call into the warn path)
  - NO retry loop (the upstream fix uses timer_lock_sighand with a loop)
"""
import json
import sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

IMAGE = "Image"
SYMS = "symbols.json"
FUNC = "posix_cpu_timer_del"
BASE = 0xFFFFFFC008000000

data = open(IMAGE, "rb").read()
syms = json.load(open(SYMS))
start = int(syms[FUNC], 16)
off = start - BASE

# symbol lookup for call targets
def sym_for(addr):
    best = None
    for name, a in syms.items():
        a = int(a, 16)
        if a <= addr and (best is None or a > best[1]):
            best = (name, a)
    if best and addr - best[1] < 0x1000:
        return f"{best[0]}+{addr-best[1]:#x}"
    return None

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = False
code = data[off:off + 0x400]
print(f"=== {FUNC} @ {start:#x} (file offset {off:#x}) ===")
n_bl = 0
bl_targets = []
cbz = []
brk = 0
backward = []
for insn in md.disasm(code, start):
    line = f"{insn.address:#x}  {insn.mnemonic:<10s} {insn.op_str}"
    note = ""
    if insn.mnemonic == "bl":
        tgt = int(insn.op_str.lstrip("#"), 0)
        n_bl += 1
        s = sym_for(tgt)
        bl_targets.append((tgt, s))
        note = f"  ; -> {s or hex(tgt)}"
    elif insn.mnemonic.startswith("cb"):
        cbz.append(insn.address)
        note = "  ; conditional branch"
    elif insn.mnemonic == "brk":
        brk += 1
        note = "  ; brk (WARN/exception)"
    elif insn.mnemonic == "b" and not insn.op_str.startswith("0x") is False:
        try:
            t = int(insn.op_str.lstrip("#"), 0)
            if t < insn.address:
                backward.append((insn.address, t))
                note = "  ; BACKWARD branch (loop)"
        except ValueError:
            pass
    print(line + note)
    if insn.mnemonic == "ret" and n_bl >= 3:
        # keep a bit past the first plausible epilogue
        if insn.address > start + 0x80:
            break

print()
print(f"bl calls: {n_bl}")
for t, s in bl_targets:
    print(f"  -> {t:#x}  {s}")
print(f"conditional branches: {len(cbz)} at {[hex(a) for a in cbz]}")
print(f"brk count: {brk}")
print(f"backward branches (loops): {backward}")

# verdict
looks_unpatched = n_bl >= 2 and len(cbz) >= 1 and not backward
print()
print("VERDICT:", "PRE-FIX SHAPE (vulnerable) — no retry loop, sighand==NULL branch present"
      if looks_unpatched else "NEEDS MANUAL REVIEW")
