#!/usr/bin/env python3
"""
structs.py — 结构偏移解析：BTF 优先，无 BTF 时用「代码推导 + 族表兜底」

为什么需要
----------
官方 extract_rs 在镜像没有内嵌 BTF 时（MediaTek / 部分 5.x）会把所有结构偏移输出为 None
（resolve_structs 直接返回 None 集合），也就是**生成不出可用 profile**。

我们的做法分两级：
  1. **代码推导**（与 BTF 无关，直接从反汇编里抠）：
       - pi_lock        ← remove_waiter 里 `add xN, current, #A`
       - pi_blocked_on  ← remove_waiter 里 `str xzr, [current, #B]`
       - prio           ← task_prio 里 `ldr w0, [x0, #P]`
       - real_cred/cred ← commit_creds 里相邻两条 `str x?, [task, #X] / [#X+8]`
     这几项恰好是布防与 cred 修复最关键的字段，逐镜像实测，不靠猜。
  2. **族表兜底**（只在代码推导不到时用）：
       6.1 的表来自 11 个真实内核 build 的 BTF，逐字段一致；5.15/6.6/6.12 标 low 置信度。

置信度
------
  high    : BTF 解析成功（与官方同等）
  medium  : 无 BTF，关键字段代码推导成功 + 6.1 族表补齐
  low     : 无 BTF，且族表未经验证（5.15/6.6/6.12）—— profile 可用但必须真机验证

用法（库；也可单独跑做体检）
    python structs.py <Image> <symbols.json>
"""
import json
import re
import sys

try:
    import capstone
except ImportError:
    sys.exit("需要 capstone: pip install capstone")

BASE = 0xFFFFFFC008000000

# task_struct 全部 15 个字段（GLK1 需要的）
TASK_FIELDS = ["prio", "normal_prio", "sched_task_group", "pi_lock", "pi_waiters",
               "pi_top_task", "pi_blocked_on", "pid", "tgid", "atomic_flags",
               "real_cred", "cred", "comm", "tasks", "seccomp"]

# 族表：仅 6.1 是**实证**的（11 个 build 的 BTF 逐字段一致），其余为未验证占位
FAMILY_TABLE = {
    "6.1": {  # 11 个 build 实测一致：PHY110 8 + Pad3 3 + GT5 1
        "prio": 132, "normal_prio": 140, "sched_task_group": 840, "pi_lock": 2340,
        "pi_waiters": 2360, "pi_top_task": 2376, "pi_blocked_on": 2384, "pid": 1584,
        "tgid": 1588, "atomic_flags": 1520, "real_cred": 2096, "cred": 2104,
        "comm": 2120, "tasks": 1360, "seccomp": 2304,
        "cred_size": 176, "cred_usage": 0, "cred_caps": 48,
        "cred_user": 128, "cred_user_ns": 136, "cred_ucounts": 144, "cred_group_info": 152,
        "waiter_size": 88, "waiter_task": 48, "waiter_lock": 56,
    },
    # 以下三个族没有实测样本，留空表示"未知"，绝不编数
    "6.6": {},
    "6.12": {},
    "5.15": {},
}


def family_of(release):
    m = re.match(r"(\d+)\.(\d+)", release or "")
    return f"{m.group(1)}.{m.group(2)}" if m else ""


# --------------------------------------------------------------------------- BTF
def _find_btf(data):
    import struct
    pos = 0
    while True:
        i = data.find(struct.pack("<H", 0xEB9F), pos)
        if i < 0:
            return None
        try:
            magic, version, flags, hdr_len, type_off, type_len, str_off, str_len = \
                struct.unpack_from("<HBBIIIII", data, i)
        except Exception:                                     # noqa: BLE001
            return None
        if version == 1 and hdr_len >= 24 and type_len > 1000 and str_len > 100 \
                and i + hdr_len + str_off + str_len <= len(data):
            return i, hdr_len, type_off, type_len, str_off, str_len
        pos = i + 1


def btf_structs(data):
    """返回 {结构名: (size, {成员: 字节偏移})}；无 BTF 返回 {}"""
    import struct
    hit = _find_btf(data)
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


# --------------------------------------------------------------------------- 代码推导
class _Img:
    def __init__(self, image_path, sym_path):
        self.data = open(image_path, "rb").read()
        raw = json.load(open(sym_path, encoding="utf-8"))
        self.syms = {k: int(v, 16) for k, v in raw.items()}
        # 基址不写死：16K 页 / VA_BITS=48 的内核 _text 不在 0xffffffc008000000
        self.base = self.syms.get("_text") or min(self.syms.values())
        self.md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)

    def dis(self, name, cap=0x1800):
        a = self.syms[name]
        return list(self.md.disasm(self.data[a - self.base: a - self.base + cap], a))


def _derive_from_code(img):
    """从反汇编抠 pi_lock / pi_blocked_on / prio / real_cred+cred；返回 (dict, notes)"""
    got, notes = {}, []

    # remove_waiter: mrs xC, sp_el0 → add xD, xC, #pi_lock ; str xzr, [xC, #pi_blocked_on]
    if "remove_waiter" in img.syms:
        ins = img.dis("remove_waiter")
        cur = None
        for x in ins:
            if x.mnemonic == "mrs" and "sp_el0" in x.op_str:
                cur = x.op_str.split(",")[0].strip()
                break
        if cur:
            for x in ins:
                if x.mnemonic == "add":
                    parts = [p.strip() for p in x.op_str.split(",")]
                    if len(parts) == 3 and parts[1] == cur and re.fullmatch(r"#0x[0-9a-f]+", parts[2]):
                        got["pi_lock"] = int(parts[2][1:], 16)
                if x.mnemonic == "str" and x.op_str.startswith("xzr,") and cur in x.op_str:
                    m = re.search(r"#0x([0-9a-f]+)\]", x.op_str)
                    if m:
                        got["pi_blocked_on"] = int(m.group(1), 16)
        else:
            notes.append("remove_waiter 里没有 mrs sp_el0（可能已修补）")

    # task_prio: `ldr wN, [x0, #prio]`（返回值可能先落 w8 再减 nice 偏移，只看 load）
    if "task_prio" in img.syms:
        for x in img.dis("task_prio", 0x40):
            if x.mnemonic in ("ldr", "ldur") and re.match(r"w\d+, \[x0", x.op_str):
                m = re.search(r"#0x([0-9a-f]+)\]", x.op_str)
                if m:
                    got["prio"] = int(m.group(1), 16)
                break

    # commit_creds: 开头成对读 [task, #real_cred] / [#cred]（也可能成对写）
    if "commit_creds" in img.syms:
        ins = img.dis("commit_creds", 0x200)
        seq = []           # (base_reg, off)
        for x in ins:
            m = re.match(r"([wx]\d+), \[(x\d+), #0x([0-9a-f]+)\]$", x.op_str)
            if m and x.mnemonic in ("ldr", "ldur", "str"):
                seq.append((m.group(2), int(m.group(3), 16)))
            elif x.mnemonic in ("bl", "b") and seq:
                break
        for i in range(len(seq) - 1):
            (b1, o1), (b2, o2) = seq[i], seq[i + 1]
            if b1 == b2 and o2 == o1 + 8:
                got["real_cred"], got["cred"] = o1, o2
                break
    return got, notes


# --------------------------------------------------------------------------- 统一入口
def resolve(image_path, sym_path, release=None):
    """返回 {fields, source, confidence, notes, derived}"""
    img = _Img(image_path, sym_path)
    structs = btf_structs(img.data)
    fam = family_of(release)

    if structs and "task_struct" in structs and "cred" in structs and "rt_mutex_waiter" in structs:
        _tsz, tm = structs["task_struct"]
        _csz, cm = structs["cred"]
        wsz, wm = structs["rt_mutex_waiter"]
        fields = {k: tm[k] for k in TASK_FIELDS if k in tm}
        fields.update({
            "cred_size": _csz, "cred_usage": cm.get("usage"), "cred_caps": cm.get("cap_permitted"),
            "cred_user": cm.get("user"), "cred_user_ns": cm.get("user_ns"),
            "cred_ucounts": cm.get("ucounts"), "cred_group_info": cm.get("group_info"),
            "waiter_size": wsz, "waiter_task": wm.get("task"), "waiter_lock": wm.get("lock"),
            "mm_struct_size": structs["mm_struct"][0] if "mm_struct" in structs else None,
        })
        return {"fields": fields, "source": "BTF", "confidence": "high",
                "notes": ["BTF 解析成功，与官方同等"], "derived": {}}

    # 无 BTF：代码推导 + 族表
    got, notes = _derive_from_code(img)
    table = dict(FAMILY_TABLE.get(fam, {}))
    fields, derived_from_table = {}, []
    for k in TASK_FIELDS:
        if k in got:
            fields[k] = got[k]
        elif k in table:
            fields[k] = table[k]
            derived_from_table.append(k)
        else:
            fields[k] = None
    for k in ("cred_size", "cred_usage", "cred_caps", "cred_user", "cred_user_ns",
              "cred_ucounts", "cred_group_info", "waiter_size", "waiter_task", "waiter_lock"):
        fields[k] = table.get(k)

    if got:
        notes.append("无 BTF：pi_lock/pi_blocked_on/prio/cred 由反汇编推导，"
                     "其余来自 " + (fam or "未知") + " 族表")
    else:
        notes.append("无 BTF 且代码推导失败")

    if fam == "6.1" and table:
        conf = "medium"
    elif table:
        conf = "low"
        notes.append(f"{fam} 族表无实测样本，字段未经证实")
    else:
        conf = "low"
        notes.append(f"{fam or '未知'} 族没有任何兜底数据")

    return {"fields": fields, "source": "code+family" if got else "family",
            "confidence": conf, "notes": notes, "derived": got}


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    data = open(sys.argv[1], "rb").read()
    m = re.search(rb"Linux version ([0-9]\S+)", data)
    release = m.group(1).decode() if m else None
    r = resolve(sys.argv[1], sys.argv[2], release)
    print(f"release = {release}   family = {family_of(release) or '未知'}")
    print(f"来源={r['source']}  置信度={r['confidence']}")
    for n in r["notes"]:
        print("  -", n)
    print()
    for k in TASK_FIELDS:
        v = r["fields"].get(k)
        if v is None:
            src = "—"
        elif r["source"] == "BTF":
            src = "BTF"
        elif k in r["derived"]:
            src = "代码推导"
        else:
            src = "族表"
        print(f"  {k:20s} {('-' if v is None else hex(v)):>8s}   {src}")
    print()
    for k in ("cred_size", "cred_caps", "cred_user", "waiter_size", "waiter_task", "waiter_lock"):
        print(f"  {k:20s} {r['fields'].get(k)}")
