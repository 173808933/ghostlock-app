"""Auto-locating kallsyms extractor (build-agnostic).

Successor to extract_symbols.py (which hardcodes the PHY110_16.0.9.400 anchors).
Everything is re-derived per build:

  1. offsets array  = longest non-decreasing run of positive u32 < 0x8000000
                      (a leading 0 element = _text offset 0 is allowed)
  2. relative_base  = u64 in [0xffffffc000000000, 0xffffffff00000000)
                      located at array_end (+0/4 alignment padding)
  3. num_syms       = u64 right after relative_base
  4. names_start    = base_pos + 16
  5. markers        = scanned right after the names stream walk
                      (u32[0]==0, strictly ascending, num_syms//256+1 entries)
  6. token_table    = scanned after markers: 256 NUL-terminated strings
                      followed by 256 distinct u16 offsets into the table

Every stage is cross-checked; the name walk asserts marker[i] == stream offset,
which makes a wrong anchors set fail loudly instead of silently.
"""
import json
import struct
import sys
from pathlib import Path

import numpy as np

IMAGE = Path(sys.argv[1] if len(sys.argv) > 1 else "Image")
OUT = Path(sys.argv[2] if len(sys.argv) > 2 else "symbols.json")

data = IMAGE.read_bytes()
print(f"image: {IMAGE} ({len(data)} bytes)")


def find_offsets_run():
    a = np.frombuffer(data, dtype="<u4")
    ok = (a > 0) & (a < 0x8000000)
    good = ok[:-1] & ok[1:] & (a[:-1] <= a[1:])
    best_len, best_start, cur_len, cur_start = 0, -1, 0, 0
    for i in np.flatnonzero(good):
        if i == cur_start + cur_len:
            cur_len += 1
        else:
            cur_start, cur_len = i, 1
        if cur_len > best_len:
            best_len, best_start = cur_len, cur_start
    if best_len < 50000:
        raise SystemExit(f"no plausible kallsyms offsets run (len={best_len})")
    return best_start * 4, (best_start + best_len + 1) * 4  # byte range of positive run


def find_base(run_start, run_end):
    for probe in range(0, 9, 4):
        base = struct.unpack_from("<Q", data, run_end + probe)[0]
        # 只要求「内核高半区 + 页对齐」：4K 页 GKI 是 0xffffffc008000000，
        # 16K 页 / VA_BITS=48 的内核基址完全不同（曾在这里被卡死）
        if 0xFFFF000000000000 <= base < 0xFFFFFFFFFFFFFFFF and base % 0x1000 == 0:
            return run_end + probe, base
    raise SystemExit("relative_base u64 not found right after offsets run")


def find_markers(names_end, num_syms):
    """Markers can sit a few bytes after the names stream (alignment padding),
    so every byte offset in a small window is probed."""
    n_markers = num_syms // 256 + 1
    for M in range(names_end - 8, names_end + 0x40):
        if M < 0:
            continue
        markers = struct.unpack_from(f"<{n_markers}I", data, M)
        if markers[0] != 0:
            continue
        if not all(markers[i] > markers[i - 1] for i in range(1, n_markers)):
            continue
        span = markers[-1]
        if span <= 0 or span > 0x400000:
            continue
        return M, markers, span
    raise SystemExit("markers array not found after names stream")


def find_token_table(lo, hi):
    """Locate the 256-token string table by scanning printable runs in [lo, hi).

    The table is a run of NUL-terminated printable-ASCII fragments (~900 bytes).
    Its start can sit a few bytes into a longer printable run (other string data
    may precede it), so every start offset inside each run is probed. The
    token_index (256 distinct u16 pointing into the table) follows at +0 or +2.
    """
    a = np.frombuffer(data[lo:hi], dtype=np.uint8)
    pn = (a > 0x20) & (a < 0x7F) | (a == 0)
    idx = np.flatnonzero(pn)
    runs = []
    if len(idx):
        start = prev = idx[0]
        for i in idx[1:]:
            if i != prev + 1:
                if prev - start + 1 >= 700:
                    runs.append((lo + int(start), lo + int(prev) + 1))
                start = i
            prev = i
        if prev - start + 1 >= 700:
            runs.append((lo + int(start), lo + int(prev) + 1))

    def validate(T):
        q = T
        tok_starts = set()
        for _ in range(256):
            z = data.find(b"\x00", q)
            if z < 0 or z == q or z - q > 48:
                return None
            tok_starts.add(q - T)
            q = z + 1
        span = q - T
        if not (800 <= span <= 1300):
            return None
        return span, tok_starts

    for s, e in runs:
        for T in range(s, min(s + 300, e - 800)):
            v = validate(T)
            if v is None:
                continue
            span, tok_starts = v
            table_end = T + span
            for pad in range(0, 16):
                index = struct.unpack_from("<256H", data, table_end + pad)
                if len(set(index)) != 256:
                    continue
                # every index value must point AT a token start (not merely be
                # in range — a table detected one string too early shifts every
                # token offset and produces plausible-but-wrong indices)
                if all(x < span and x in tok_starts for x in index):
                    return T, index
    raise SystemExit(f"token table not found in [{lo:#x}, {hi:#x})")


run_start, run_end = find_offsets_run()
base_pos, base = find_base(run_start, run_end)
run_len = (run_end - run_start) // 4          # 非零元素的个数


def layout_candidates():
    """两种 kallsyms 布局：

      A (≤6.1)   offsets[] · relative_base(u64) · num_syms(u64) · names · markers …
      B (≥6.4)   num_syms · names · markers · token_table · token_index · offsets[] · relative_base

    B 的 num_syms 不在 relative_base 旁边，只能按「值 ≈ offsets 数组长度」反查，
    再用 markers 交叉校验确认，不靠猜。
    """
    for probe in range(0, 17, 4):
        v = struct.unpack_from("<Q", data, base_pos + 8 + probe)[0]
        if 5000 < v < 2_000_000:
            yield int(v), base_pos + 16 + probe, "A:num_syms 紧跟 relative_base"
    for k in range(max(5000, run_len - 4), run_len + 9):
        pat = struct.pack("<I", k)
        pos = 0
        while True:
            i = data.find(pat, pos)
            if i < 0:
                break
            pos = i + 1
            if i >= base_pos:
                break
            for st in (i + 4, i + 8, i + 12):
                if st < base_pos:
                    yield k, st, f"B:num_syms@{i:#x} 紧跟 names"


def try_layout(num_syms, names_start, label):
    p = names_start
    for _ in range(num_syms):
        ln = data[p]
        if ln == 0 or ln > 64:
            return None
        p += 1 + ln
    try:
        markers_off, markers, names_span = find_markers(p, num_syms)
    except SystemExit:
        return None
    return {"num_syms": num_syms, "names_start": names_start, "names_end": p,
            "markers_off": markers_off, "markers": markers, "names_span": names_span,
            "label": label}


chosen = None
for n, ns, label in layout_candidates():
    got = try_layout(n, ns, label)
    if got:
        chosen = got
        print(f"布局匹配: {label} (num_syms={n}, names@{ns:#x})")
        break
if chosen is None:
    raise SystemExit("两种 kallsyms 布局都校验失败（markers 交叉校验不过）")

num_syms = chosen["num_syms"]
names_start = chosen["names_start"]
markers_off = chosen["markers_off"]
markers = chosen["markers"]
names_span = chosen["names_span"]
offsets_off = run_end - 4 * num_syms
print(f"offsets_off = {offsets_off:#x}")
print(f"num_syms    = {num_syms}")
print(f"base        = {base:#x} @ {base_pos:#x}")
print(f"names_start = {names_start:#x}")
assert offsets_off >= 0, "offsets_off 为负：num_syms 不合理"

# --- names stream walk（带 marker 交叉校验）---
p = names_start
for _ in range(num_syms):
    ln = data[p]
    if ln == 0 or ln > 64:
        raise SystemExit(f"implausible name length {ln} at {p:#x} (names_start wrong?)")
    p += 1 + ln
names_end = p
print(f"names_end   = {names_end:#x} (span {names_end - names_start:#x})")

markers_end = markers_off + 4 * (num_syms // 256 + 1)
try:
    token_table, token_index = find_token_table(markers_end, markers_end + 0x80000)
except SystemExit:
    print("  (markers 后 512KB 未找到，回退全文件扫描)")
    token_table, token_index = find_token_table(0, len(data))
tok_by_off = {}
q = token_table
for _ in range(256):
    e = data.find(b"\x00", q)
    tok_by_off[q - token_table] = data[q:e]
    q = e + 1
print(f"token_table = {token_table:#x} (span {q - token_table} bytes)")

# --- full walk with marker cross-check + decompression ---
symbols = []
p = names_start
for i in range(num_syms):
    if i % 256 == 0 and i > 0:
        assert p - names_start == markers[i // 256], f"marker mismatch at symbol {i}"
    ln = data[p]
    rec = data[p + 1 : p + 1 + ln]
    p += 1 + ln
    name = bytearray()
    for b in rec:
        name += tok_by_off[token_index[b]]
    stype = chr(name[0])
    sname = name[1:].decode("utf-8", "replace")
    addr = base + struct.unpack_from("<I", data, offsets_off + 4 * i)[0]
    symbols.append((sname, stype, addr))

print(f"symbols={len(symbols)}")
OUT.write_text(json.dumps({n: hex(a) for n, t, a in symbols}, indent=0), encoding="utf-8")
print(f"wrote {OUT}")

WANT = ["init_task", "init_cred", "selinux_state", "selinux_blob_sizes", "kmalloc_caches",
        "anon_pipe_buf_ops", "ashmem_ioctl", "ashmem_open", "ashmem_release",
        "configfs_read_iter", "configfs_bin_write_iter", "memstart_addr", "kimage_voffset",
        "module_alloc_base", "misc_list", "uhid_misc", "uhid_fops", "sysctl_bootid",
        "random_table", "nfulnl_logger", "_sdata", "_edata", "_text", "posix_cpu_timer_del",
        "lock_task_sighand", "run_posix_cpu_timers", "release_posix_timer", "posix_timers_cache"]
symdict = {n: a for n, t, a in symbols}
for w in WANT:
    print(f"  {w:32s} {symdict.get(w, 'NOT FOUND')}")
