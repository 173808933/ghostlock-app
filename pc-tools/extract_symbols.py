#!/usr/bin/env python3
"""Extract kallsyms from PHY110 kernel Image using validated anchors.

Anchors (validated by cross-checks):
  offsets_off   0x12b6c20  (longest ascending u32 run, num_syms=102903)
  relative_base 0xffffffc008000000 (u64 at offsets_off + 4*num_syms + 4)
  num_syms field 0x131b408
  names_start   0x131b410  (record walk of 102903 records ends at 0x1473a81)
  markers       0x1473a88  (402 entries, markers[1]=0xc39 matches names walk)
  token_table   0x14bf6b8  (902 bytes, token_index validated at 0x14bfa40)
"""
import json
import struct
import sys
from pathlib import Path

IMAGE = Path(sys.argv[1] if len(sys.argv) > 1 else "Image")
OUT = Path(sys.argv[2] if len(sys.argv) > 2 else "symbols.json")

data = IMAGE.read_bytes()

offsets_off = 0x12b6c20
num_syms = 102903
base = struct.unpack_from("<Q", data, offsets_off + 4 * num_syms + 4)[0]
assert base == 0xFFFFFFC008000000, hex(base)
names_start = 0x131b410
markers_off = 0x1473a88
token_table = 0x14bf6b8

# markers
n_markers = num_syms // 256 + 1
markers = struct.unpack_from(f"<{n_markers}I", data, markers_off)
assert markers[0] == 0
assert all(markers[i] > markers[i - 1] for i in range(1, n_markers)), "markers not increasing"

# token table: build offset -> string map (name byte -> token_index -> table offset -> string)
tok_by_off = {}
p = token_table
for _ in range(256):
    end = data.find(b"\x00", p)
    tok_by_off[p - token_table] = data[p:end]
    p = end + 1
token_index = struct.unpack_from("<256H", data, p + 2)  # 2 bytes padding after table
assert len(set(token_index)) == 256
# sanity: every token_index value must point at a token start
assert all(v in tok_by_off for v in token_index), "token_index points outside token table"

# names walk with marker cross-check
symbols = []
p = names_start
for i in range(num_syms):
    if i % 256 == 0 and i > 0:
        assert p - names_start == markers[i // 256], f"marker mismatch at {i}"
    ln = data[p]
    rec = data[p + 1:p + 1 + ln]
    p += 1 + ln
    name = bytearray()
    for b in rec:
        name += tok_by_off[token_index[b]]
    # kallsyms stores the symbol type character as the first name character
    stype = chr(name[0])
    sname = name[1:].decode("utf-8", "replace")
    addr = base + struct.unpack_from("<I", data, offsets_off + 4 * i)[0]
    symbols.append((sname, stype, addr))

names_end = p
print(f"symbols={len(symbols)} names_end={names_end:#x} (markers end {markers_off + 4*n_markers:#x})")

OUT.write_text(json.dumps({n: hex(a) for n, t, a in symbols}, indent=0), encoding="utf-8")
print(f"wrote {OUT}")

# print the exploit-relevant symbols
WANT = ["init_task", "init_cred", "selinux_state", "selinux_blob_sizes", "kmalloc_caches",
        "anon_pipe_buf_ops", "ashmem_ioctl", "ashmem_open", "ashmem_release",
        "configfs_read_iter", "configfs_bin_write_iter", "memstart_addr", "kimage_voffset",
        "module_alloc_base", "misc_list", "uhid_misc", "uhid_fops", "sysctl_bootid",
        "random_table", "nfulnl_logger", "_sdata", "_edata", "_text", "posix_cpu_timer_del",
        "lock_task_sighand", "run_posix_cpu_timers", "release_posix_timer", "posix_timers_cache"]
symdict = {n: a for n, t, a in symbols}
for w in WANT:
    print(f"  {w:32s} {symdict.get(w, 'NOT FOUND')}")
