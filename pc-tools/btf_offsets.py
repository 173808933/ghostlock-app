"""Extract BTF struct offsets from a raw arm64 kernel Image.

Finds the .BTF blob by its header magic, parses BTF_KIND_STRUCT member lists,
and prints the offsets of the fields the GhostLock profile depends on.
Used to verify that task_struct / cred / rt_mutex_waiter layouts are unchanged
across builds (same SoC tree + same clang, but verified, never assumed).
"""
import struct
import sys
from pathlib import Path

IMAGE = Path(sys.argv[1] if len(sys.argv) > 1 else "Image")
data = IMAGE.read_bytes()

BTF_MAGIC = 0xEB9F


def find_btf():
    needle = struct.pack("<H", BTF_MAGIC)
    pos = 0
    while True:
        i = data.find(needle, pos)
        if i < 0:
            return None
        magic, version, flags, hdr_len, type_off, type_len, str_off, str_len = \
            struct.unpack_from("<HBBI IIII".replace(" ", ""), data, i)
        if version == 1 and hdr_len == 24 and str_off == type_off + type_len \
                and i + str_off + str_len <= len(data) and type_len > 1000 and str_len > 100:
            return i, (hdr_len, type_off, type_len, str_off, str_len)
        pos = i + 1


hit = find_btf()
if not hit:
    sys.exit("BTF not found in Image")
base, (hdr_len, type_off, type_len, str_off, str_len) = hit
print(f"BTF @ {base:#x}: types [{type_off:#x}, +{type_len:#x}) strings [{str_off:#x}, +{str_len:#x})")

strs = data[base + hdr_len + str_off: base + hdr_len + str_off + str_len]


def strat(off):
    e = strs.find(b"\x00", off)
    return strs[off:e].decode("utf-8", "replace")


# --- walk types ---
structs = {}   # name -> {member: (offset, bits)}
ints = {}
# BTF kind enum (linux/bpf.h): 0 UNKN, 1 INT, 2 PTR, 3 ARRAY, 4 STRUCT, 5 UNION,
# 6 ENUM, 7 FWD, 8 TYPEDEF, 9 VOLATILE, 10 CONST, 11 RESTRICT, 12 FUNC,
# 13 FUNC_PROTO, 14 VAR, 15 DATASEC, 16 FLOAT, 17 DECL_TAG, 18 TYPE_TAG, 19 ENUM64
VAR_LEN = {  # extra bytes per vlen entry beyond the 12-byte btf_type header
    3: 12,   # ARRAY: 1 entry (btf_array)
    4: 12,   # STRUCT: btf_member
    5: 12,   # UNION: btf_member
    6: 8,    # ENUM: btf_enum
    13: 8,   # FUNC_PROTO: btf_param
    15: 12,  # DATASEC: btf_var_secinfo
    19: 12,  # ENUM64: btf_enum64
}

p = base + hdr_len + type_off
end = p + type_len
while p + 12 <= end:
    name_off, info, size_or_type = struct.unpack_from("<III", data, p)
    kind = (info >> 24) & 0x1F
    vlen = info & 0xFFFF
    kflag = (info >> 31) & 1
    if kind == 4:  # BTF_KIND_STRUCT
        name = strat(name_off)
        members = {}
        q = p + 12
        for _ in range(vlen):
            m_name, m_type, m_off = struct.unpack_from("<III", data, q)
            # btf_member.offset: bits 0-23 = bit offset, bits 24-31 = bitfield size
            members[strat(m_name)] = ((m_off & 0xFFFFFF) >> 3, m_off >> 24)
            q += 12
        structs[name] = {"size": size_or_type, "members": members}
        p = q
    elif kind == 1:  # BTF_KIND_INT
        ints[strat(name_off)] = (size_or_type, (info >> 24) & 0xFF, (info >> 16) & 0xFF)
        p += 12
    elif kind == 14:  # VAR
        p += 16
    else:
        p += 12 + VAR_LEN.get(kind, 0) * vlen

print(f"structs parsed: {len(structs)}")

WANT = {
    "task_struct": ["prio", "normal_prio", "sched_task_group", "pi_lock", "pi_waiters",
                    "pi_top_task", "pi_blocked_on", "pid", "tgid", "atomic_flags",
                    "real_cred", "cred", "comm", "tasks", "seccomp"],
    "cred": ["usage", "cap_inheritable", "cap_permitted", "cap_effective", "cap_bset",
             "security"],
    "rt_mutex_waiter": ["task", "lock", "wake_state", "prio", "deadline", "ww_ctx"],
    "mm_struct": ["mm_users", "mm_count"],
}
for sname, fields in WANT.items():
    s = structs.get(sname)
    if not s:
        print(f"\n[{sname}] NOT IN BTF")
        continue
    print(f"\n[{sname}] size={s['size']}")
    for f in fields:
        if f in s["members"]:
            off, bits = s["members"][f]
            print(f"   {f:20s} @ {off}")
        else:
            avail = [m for m in s["members"] if f in m]
            print(f"   {f:20s} NOT FOUND (similar: {avail[:5]})")
