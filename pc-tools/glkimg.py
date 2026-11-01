#!/usr/bin/env python3
"""glkimg.py — arm64 Image + kallsyms 的通用反汇编层（任意机型可用）

和旧脚本的区别（都是「换机型就翻车」的点）：
  1. **基址不写死**：旧代码固定 BASE=0xFFFFFFC008000000（VA_BITS=39/4K 页的 GKI 布局）。
     16K 页 / VA_BITS=48 的内核 `_text` 在别的地址，写死基址会把每条函数的字节读错，
     而且不会报错——只会得到看起来合理但完全错误的栈帧。
     这里基址取符号表里的 `_text`（缺则取最小地址），并做区间校验。
  2. **调用链用 BFS**：LTO 内联程度逐 build 不同（do_futex 有时被内联掉、
     sock_common_setsockopt 有时被内联），固定 2 层/固定列表会漏。BFS 在真实 bl 边图上
     找最短链，跨层数自适应。
  3. **copy 站点不只认 x0**：不同编译器会把目标寄存器换掉，只要 `bl <copy_fn>` 前
     有 `add xN, sp, #L` + `mov w2, #S` 就算，并回报寄存器名。
"""
import bisect
import json
import struct

import capstone

DEFAULT_BASE = 0xFFFFFFC008000000

# 内核里 user-copy 的三种入口名（arm64 各版本不同）
COPY_FUNCS = {"__arch_copy_from_user", "_copy_from_user", "copy_from_user",
              "__copy_from_user", "arm64_copy_from_user", "raw_copy_from_user"}


class Image:
    def __init__(self, image_path, sym_path, base=None):
        self.data = open(image_path, "rb").read()
        raw = json.load(open(sym_path, encoding="utf-8"))
        self.syms = {k: int(v, 16) for k, v in raw.items()}
        if base is None:
            base = self.syms.get("_text") or min(self.syms.values())
        self.base = base
        self.base_ok = 0xFFFF000000000000 <= base <= 0xFFFFFFFFFFFFFFFF
        self.items = sorted((v, k) for k, v in self.syms.items())
        self.starts = [a for a, _ in self.items]
        self.md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
        self._cache = {}

    # ------------------------------------------------------------------ 基础
    def off(self, name):
        return self.syms[name] - self.base

    def size_of(self, name):
        a = self.syms[name]
        i = bisect.bisect_left(self.starts, a)
        if i + 1 < len(self.items):
            return max(4, self.items[i + 1][0] - a)
        return 0x1000

    def owner(self, addr):
        i = bisect.bisect_right(self.starts, addr) - 1
        return self.items[i][1] if i >= 0 else "?"

    def dis(self, name, cap=None):
        if name in self._cache:
            return self._cache[name]
        o = self.off(name)
        if o < 0 or o >= len(self.data):
            self._cache[name] = []
            return []
        n = min(cap or self.size_of(name), self.size_of(name), len(self.data) - o)
        buf = self.data[o:o + n]
        base = self.syms[name]
        # 逐条解码并在遇到非法指令时前进 4 字节重新同步：
        # 函数中间可能夹着字面量池/跳转表，capstone 一旦遇到就整段停下，
        # 之前的版本因此看不到函数后半部分的拷贝站点（6.6 就是这样漏掉的）。
        out, p = [], 0
        while p < len(buf):
            got = False
            for x in self.md.disasm(buf[p:], base + p):
                out.append(x)
                p += x.size
                got = True
                break
            if not got:
                p += 4
        self._cache[name] = out
        return out

    # ------------------------------------------------------------------ 栈帧
    def frame(self, name):
        """函数自身栈帧 = 入口 pre-index stp/str + 第一条 sub sp"""
        total = 0
        sub_done = False
        for x in self.dis(name)[:24]:
            op = x.op_str
            if x.mnemonic in ("stp", "str") and op.endswith("!") and "[sp, #-0x" in op:
                total += int(op.split("#-0x")[1].rstrip("]!"), 16)
            elif not sub_done and x.mnemonic == "sub" and op.startswith("sp, sp, #0x"):
                total += int(op.split("#")[1], 16)
                sub_done = True
            elif x.mnemonic in ("bl", "b", "ret") and (total or sub_done):
                break
        return total

    # ------------------------------------------------------------------ 调用图
    def calls(self, name):
        out = []
        for x in self.dis(name):
            if x.mnemonic == "bl" and x.op_str.startswith("#"):
                t = int(x.op_str[1:], 16)
                o = self.owner(t)
                if o != "?":
                    out.append(o)
        return out

    def chain(self, src, dst, max_depth=5):
        """真实 bl 边上的最短调用链 [src, …, dst]；找不到返回 None"""
        if src not in self.syms or dst not in self.syms:
            return None
        if src == dst:
            return [src]
        prev = {src: None}
        frontier = [src]
        for _ in range(max_depth):
            nxt = []
            for cur in frontier:
                for t in self.calls(cur):
                    if t in prev:
                        continue
                    prev[t] = cur
                    if t == dst:
                        path = [t]
                        while prev[path[0]] is not None:
                            path.insert(0, prev[path[0]])
                        return path
                    nxt.append(t)
            frontier = nxt
            if not frontier:
                break
        return None

    # ------------------------------------------------------------------ copy 站点
    def find_copy_sites(self, func, size_hint=None, require_sp=True):
        """返回 [{dst, local, size, at}]：`add xN, sp, #L` + `mov w2, #S` + `bl <copy>`

        size_hint 给了就只留该长度（比 fpsimd 0x200 / greqs 0x108）。
        require_sp=False 时，目标缓冲不在本函数栈帧里（由调用者传入）也算一条，
        此时 local 为 None —— 6.6 的 read_fpsimd_context 就是这种。
        """
        ins = self.dis(func)
        hits = []
        for i, x in enumerate(ins):
            if x.mnemonic != "bl" or not x.op_str.startswith("#"):
                continue
            if self.owner(int(x.op_str[1:], 16)) not in COPY_FUNCS:
                continue
            size = dst = local = None
            for y in reversed(ins[max(0, i - 8):i]):
                if size is None and y.mnemonic in ("mov", "movz") and y.op_str.startswith("w2, #0x"):
                    size = int(y.op_str.split("#")[1], 16)
                if local is None and y.mnemonic == "add" and ", sp, #0x" in y.op_str:
                    parts = [p.strip() for p in y.op_str.split(",")]
                    if len(parts) == 3:
                        dst, local = parts[0], int(parts[2].lstrip("#"), 16)
                if size is not None and local is not None:
                    break
            if size is None:
                continue
            if size_hint is not None and size != size_hint:
                continue
            if local is None:
                if not require_sp:
                    hits.append({"dst": "reg", "local": None, "size": size, "at": x.address})
                continue
            hits.append({"dst": dst, "local": local, "size": size, "at": x.address})
        return hits

    def find_local_memset(self, func, size):
        """`add xN, sp, #W` + `mov w2, #<size>` + `bl memset`，返回 W 列表"""
        ins = self.dis(func)
        out = []
        for i, x in enumerate(ins):
            if x.mnemonic != "add" or ", sp, #0x" not in x.op_str:
                continue
            window = ins[i + 1:i + 6]
            has_size = any(y.mnemonic in ("mov", "movz") and y.op_str.startswith("w2, #")
                           and int(y.op_str.split("#")[1], 16) == size for y in window)
            has_memset = any(y.mnemonic == "bl" and y.op_str.startswith("#")
                             and self.owner(int(y.op_str[1:], 16)) == "memset" for y in window)
            if has_size and has_memset:
                out.append(int(x.op_str.split("#")[1], 16))
        return sorted(set(out))

    # ------------------------------------------------------------------ 漏洞存在性
    def remove_waiter_patched(self):
        """上游修复把 remove_waiter 里的 current 换成 waiter->task ⇒ 不再 mrs sp_el0"""
        if "remove_waiter" not in self.syms:
            return None
        return not any(x.mnemonic == "mrs" and "sp_el0" in x.op_str
                       for x in self.dis("remove_waiter"))

    # ------------------------------------------------------------------ BTF
    def btf(self):
        return btf_structs(self.data)


# --------------------------------------------------------------------------- BTF 解析
def _find_btf(data):
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
    """{结构名: (size, {成员: 字节偏移})}；没有 BTF 返回 {}"""
    hit = _find_btf(data)
    if not hit:
        return {}
    base, hdr_len, type_off, type_len, str_off, str_len = hit
    strs = data[base + hdr_len + str_off: base + hdr_len + str_off + str_len]

    def s(o):
        e = strs.find(b"\x00", o)
        return strs[o:e].decode("utf-8", "replace") if 0 <= o < len(strs) else ""

    VAR_LEN = {3: 12, 4: 12, 5: 12, 6: 8, 13: 8, 15: 12, 19: 12}
    out, p = {}, base + hdr_len + type_off
    end = p + type_len
    while p + 12 <= end and p + 12 <= len(data):
        name_off, info, size_or_type = struct.unpack_from("<III", data, p)
        kind, vlen = (info >> 24) & 0x1F, info & 0xFFFF
        if kind == 4:
            members, q = {}, p + 12
            for _ in range(vlen):
                m_name, _t, m_off = struct.unpack_from("<III", data, q)
                members[s(m_name)] = (m_off & 0xFFFFFF) >> 3
                q += 12
            out[s(name_off)] = (size_or_type, members)
            p = q
        else:
            p += 12 + VAR_LEN.get(kind, 0) * vlen
    return out
