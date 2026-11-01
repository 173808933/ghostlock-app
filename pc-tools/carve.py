#!/usr/bin/env python3
"""carve.py — 把任意形态的内核容器拆成可分析的 arm64 Image（只用标准库）

支持（真机 dump / 官方固件包里的各种形态）
------------------------------------------------
  AOSP boot.img v0/v1/v2/v3/v4      ANDROID! 魔数 + arm64 头校验
  raw Image / Image.gz-dtb          直接以 arm64 头开始
  压缩内核                          gzip / lz4(frame) / xz / zstd(需 zstandard) / bzip2
  vendor_boot.img                   VNDRBOOT：里面没有内核，但能给出 kernel_addr（MTK phys）
  OTA / 全量包 zip                  递归取 boot*.img
  带前缀的 OEM 头（MTK/Samsung）     魔数在前 2MB 内任意位置都能找到

对外
----
    import carve
    r = carve.unpack("boot.img")
    r["image"]        # bytes，已解压的 arm64 Image
    r["container"]    # "boot v2" / "raw Image" / "vendor_boot" ...
    r["page_size"]    # boot header 的页大小（4096/2048/…），raw Image 为 None
    r["release"]      # Linux version 串
    r["page_shift"]   # 内核页大小 shift（12=4K / 14=16K / 16=64K），拿不到为 None

    python carve.py <file> [--out DIR]     # 体检 + 可选落盘 Image
"""
import bz2
import io
import lzma
import os
import re
import struct
import sys
import zipfile
import zlib

BOOT_MAGIC = b"ANDROID!"
VNDRBOOT_MAGIC = b"VNDRBOOT"
ARM64_MAGIC = b"ARM\x64"

COMPRESS_MAGIC = [
    (b"\x1f\x8b\x08", "gzip"),
    (b"\x02\x21\x4c\x18", "lz4-legacy"),
    (b"\x04\x22\x4d\x18", "lz4"),
    (b"\x28\xb5\x2f\xfd", "zstd"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"BZh", "bzip2"),
]


# --------------------------------------------------------------------------- 压缩
def _lz4_block(src, seed=b""):
    """LZ4 block 解压（重叠拷贝逐字节，符合规范）

    seed = 前一个块的尾部（≤64KB）。块链接模式(block-linked)下 offset 可以指到
    前一个块里，必须带着历史窗口解，否则会解出垃圾或抛 offset 非法。
    """
    out = bytearray(seed)
    base = len(seed)
    i, n = 0, len(src)
    while i < n:
        token = src[i]
        i += 1
        lit = token >> 4
        if lit == 15:
            while True:
                b = src[i]
                i += 1
                lit += b
                if b != 255:
                    break
        out += src[i:i + lit]
        i += lit
        if i >= n:
            break
        offset = src[i] | (src[i + 1] << 8)
        i += 2
        mlen = token & 0x0F
        if mlen == 15:
            while True:
                b = src[i]
                i += 1
                mlen += b
                if b != 255:
                    break
        mlen += 4
        start = len(out) - offset
        if start < 0:
            raise ValueError("lz4: 非法 offset")
        for k in range(mlen):
            out.append(out[start + k])
    return bytes(out[base:])


def lz4_decompress(data):
    """LZ4 frame 解压（块独立/链接都可，跳过校验和）"""
    i, out = 0, bytearray()
    while i + 7 <= len(data):
        if data[i:i + 4] != b"\x04\x22\x4d\x18":
            break                                    # skippable frame / 结束
        i += 4
        flg, bd = data[i], data[i + 1]
        i += 2
        if flg & 0x08:                               # content size
            i += 8
        if flg & 0x01:                               # dict id
            i += 4
        i += 1                                       # header checksum
        bmax = {4: 0x10000, 5: 0x40000, 6: 0x100000, 7: 0x400000}.get((bd >> 4) & 7, 0x400000)
        linked = not (flg & 0x20)                    # bit5 = block independence
        while i + 4 <= len(data):
            bsize = struct.unpack_from("<I", data, i)[0]
            i += 4
            raw = bsize & 0x80000000
            bsize &= 0x7FFFFFFF
            if bsize == 0:
                break
            block = data[i:i + bsize]
            i += bsize
            if flg & 0x10:                           # block checksum
                i += 4
            if raw:
                out += block
            else:
                out += _lz4_block(block, bytes(out[-0x10000:]) if linked else b"")
        if flg & 0x04:                               # content checksum
            i += 4
    return bytes(out)


def lz4_legacy_decompress(data):
    """LZ4 legacy 帧（magic 0x184C2102）——AOSP/vivo 的 Image.lz4 常见这种老格式

    结构：magic，然后若干 [u32 size][block]；size 最高位=1 表示该块原样存储。
    """
    i, out = 0, bytearray()
    seen = False
    while i + 4 <= len(data):
        if data[i:i + 4] == b"\x02\x21\x4c\x18":
            i += 4
            seen = True
            continue
        size = struct.unpack_from("<I", data, i)[0]
        i += 4
        if size == 0:
            break
        raw = size & 0x80000000
        size &= 0x7FFFFFFF
        if size > 0x8000000 or i + size > len(data):
            break
        block = data[i:i + size]
        i += size
        out += block if raw else _lz4_block(block)
    return bytes(out) if seen else b""


def zstd_decompress(data):
    try:
        import zstandard                                # noqa: PLC0415
        return zstandard.ZstdDecompressor().decompressobj().decompress(data)
    except ImportError:
        pass
    try:                                                # 兜底：系统 zstd 可执行文件
        import subprocess                               # noqa: PLC0415
        r = subprocess.run(["zstd", "-dc"], input=data, capture_output=True)
        if r.returncode == 0:
            return r.stdout
    except OSError:
        pass
    raise RuntimeError("zstd 需要 `pip install zstandard` 或系统 zstd 命令")


def decompress_auto(data, depth=0):
    """按魔数解压，返回 (payload, label)；非压缩返回 (data, None)"""
    if depth > 3 or len(data) < 8:
        return data, None
    for magic, name in COMPRESS_MAGIC:
        if not data.startswith(magic):
            continue
        try:
            if name == "gzip":
                raw = zlib.decompressobj(31).decompress(data)
            elif name == "lz4":
                raw = lz4_decompress(data)
            elif name == "lz4-legacy":
                raw = lz4_legacy_decompress(data)
            elif name == "xz":
                raw = lzma.decompress(data)
            elif name == "bzip2":
                raw = bz2.decompress(data)
            else:
                raw = zstd_decompress(data)
        except Exception:                                # noqa: BLE001
            return data, None
        inner, more = decompress_auto(raw, depth + 1)
        return inner, name + ("+" + more if more else "")
    return data, None


# --------------------------------------------------------------------------- arm64 Image 校验
def _image_at(data, off):
    """off 处是否是一个合法的 arm64 Image 头；合法则返回 image_size"""
    if off < 0 or off + 0x40 > len(data):
        return None
    if data[off + 0x38:off + 0x3C] != ARM64_MAGIC:
        return None
    text_off = struct.unpack_from("<Q", data, off + 0x08)[0]
    img_size = struct.unpack_from("<Q", data, off + 0x10)[0]
    if text_off > 0x1000000:                    # 512K 对齐的偏移，容错放宽
        return None
    if not (0x400000 <= img_size <= 0x20000000):  # 4MB ~ 512MB
        return None
    if off + img_size > len(data):
        # 尾部缺失很常见：boot 里的 kernel_size 可能按 512K 对齐记账，
        # 压缩流解出来会短一截；只要缺得不多就按实际长度截断
        if len(data) - off < img_size * 0.8:
            return None
        return len(data) - off
    return img_size


def find_image(data, limit=0x200000):
    """在前 limit 字节里找 arm64 Image 起点，返回 (offset, size) 或 None"""
    pos = 0
    while True:
        pos = data.find(ARM64_MAGIC, pos, limit)
        if pos < 0:
            return None
        size = _image_at(data, pos - 0x38)
        if size:
            return pos - 0x38, size
        pos += 1


# --------------------------------------------------------------------------- boot header
def parse_boot_header(data, m=0):
    """ANDROID! 头解析；v3/v4 与 v0-v2 字段布局不同，必须分开读（vivo/新机型多是 v4）"""
    if data[m:m + 8] != BOOT_MAGIC or len(data) < m + 48:
        return None
    kernel_size = struct.unpack_from("<I", data, m + 8)[0]
    hv = struct.unpack_from("<I", data, m + 40)[0]
    if 3 <= hv <= 4:
        # v3/v4: kernel_size(8) ramdisk_size(12) os_version(16) header_size(20)
        ramdisk_size, os_version, header_size = struct.unpack_from("<III", data, m + 12)
        return {"kernel_size": kernel_size, "kernel_addr": 0,
                "ramdisk_size": ramdisk_size, "page_size": 4096,
                "header_version": hv, "os_version": os_version,
                "header_size": header_size, "magic_offset": m}
    f = struct.unpack_from("<10I", data, m + 8)
    (kernel_size, kernel_addr, ramdisk_size, ramdisk_addr, second_size,
     second_addr, tags_addr, page_size, hv, os_version) = f
    if page_size not in (0x800, 0x1000, 0x2000, 0x4000, 0x10000) or hv > 2:
        page_size, hv = 0x1000, 0
    return {
        "kernel_size": kernel_size, "kernel_addr": kernel_addr,
        "ramdisk_size": ramdisk_size, "page_size": page_size,
        "header_version": hv, "os_version": os_version,
        "magic_offset": m,
    }


def os_version_str(v):
    if not v:
        return None
    return (f"{v >> 25}.{(v >> 18) & 0x7F}.{(v >> 11) & 0x7F}"
            f"-{v & 0x7F}.{f'{(v >> 4) & 0x7F}' if v & 0xF else '0'}")


def parse_vendor_boot(data, m=0):
    if data[m:m + 8] != VNDRBOOT_MAGIC or len(data) < m + 32:
        return None
    version, page_size = struct.unpack_from("<II", data, m + 8)
    kernel_addr = struct.unpack_from("<I", data, m + 16)[0]
    return {"header_version": version, "page_size": page_size, "kernel_addr": kernel_addr}


# --------------------------------------------------------------------------- 页大小
def detect_page_shift(image):
    """内核页大小：优先 ikconfig（CONFIG_IKCONFIG 内嵌 gzip），否则 None"""
    i = image.find(b"IKCFG_ST")
    while i >= 0:
        blob = image[i + 8:]
        try:
            cfg = zlib.decompressobj(31).decompress(blob, 8 << 20)
        except zlib.error:
            cfg = b""
        if cfg:
            for shift, name in ((12, "4K"), (14, "16K"), (16, "64K")):
                if f"CONFIG_ARM64_{name}_PAGES=y".encode() in cfg:
                    return shift, "ikconfig"
            va = re.search(rb"CONFIG_ARM64_VA_BITS=(\d+)", cfg)
            if va and b"CONFIG_ARM64_4K_PAGES" not in cfg:
                pass
        i = image.find(b"IKCFG_ST", i + 8)
    # 裸字符串兜底（少数镜像把 config 以明文留了一份）
    for shift, name in ((12, "4K"), (14, "16K"), (16, "64K")):
        if f"CONFIG_ARM64_{name}_PAGES=y".encode() in image:
            return shift, "明文 CONFIG"
    return None, "unknown"


# --------------------------------------------------------------------------- 主入口
def _release(data):
    m = re.search(rb"Linux version (\S+)", data)
    return m.group(1).decode("latin-1") if m else None


def _result(kind, image, **kw):
    r = {"kind": kind, "image": image, "container": kw.pop("container", kind),
         "page_size": kw.pop("page_size", None), "header_version": kw.pop("header_version", None),
         "os_version": kw.pop("os_version", None), "image_offset": kw.pop("image_offset", 0),
         "decompress": kw.pop("decompress", None),
         "vendor_boot_kernel_addr": kw.pop("vendor_boot_kernel_addr", None),
         "notes": kw.pop("notes", [])}
    r.update(kw)
    if image:
        r["release"] = _release(image)
        r["page_shift"], r["page_shift_source"] = detect_page_shift(image)
    return r


def unpack(path, outdir=None, _depth=0):
    """任意内核容器 → dict（含已解压的 arm64 Image bytes）"""
    if not os.path.isfile(path):
        return _result("missing", None, notes=[f"文件不存在: {path}"])
    if zipfile.is_zipfile(path) and _depth < 2:
        with zipfile.ZipFile(path) as z:
            cands = [n for n in z.namelist()
                     if re.search(r"(^|/)boot[^/]*\.img$", n, re.I)]
            if not cands:
                cands = [n for n in z.namelist() if n.lower().endswith(".img")][:4]
            notes = [f"zip 内含 {len(z.namelist())} 项，取 {cands[:1]}"]
            if not cands:
                return _result("zip", None, notes=notes + ["zip 里没有 boot*.img"])
            tmp = os.path.join(outdir or os.path.dirname(os.path.abspath(path)), ".carve")
            os.makedirs(tmp, exist_ok=True)
            dst = os.path.join(tmp, os.path.basename(cands[0]))
            with z.open(cands[0]) as f, open(dst, "wb") as o:
                o.write(f.read())
        r = unpack(dst, outdir, _depth + 1)
        r.setdefault("notes", []).extend(notes)
        r["kind"] = "zip/" + r["kind"]
        return r

    data = open(path, "rb").read()
    if data[:4] == b"\x7fELF":
        return _result("elf", None, notes=["这是 vmlinux/ELF，不是 boot.img；"
                                           "请提供 boot.img 或裸 Image"])

    # vendor_boot：没有内核
    vb = parse_vendor_boot(data)
    if vb is None:
        vm = data.find(VNDRBOOT_MAGIC, 0, 0x200000)
        vb = parse_vendor_boot(data, vm) if vm > 0 else None
    if vb and vb["header_version"]:
        return _result("vendor_boot", None, page_size=vb["page_size"],
                       header_version=vb["header_version"],
                       vendor_boot_kernel_addr=vb["kernel_addr"] or None,
                       notes=["vendor_boot 不含内核；kernel_addr 可用于推 MTK phys"])

    hdr = parse_boot_header(data)
    if hdr is None:
        m = data.find(BOOT_MAGIC, 0, 0x200000)
        if m > 0:
            hdr = parse_boot_header(data, m)
    notes = []
    if hdr:
        notes.append(f"boot header v{hdr['header_version']}, page_size={hdr['page_size']}"
                     f", kernel_size={hdr['kernel_size']:,}")
        if hdr["magic_offset"]:
            notes.append(f"ANDROID! 在 +0x{hdr['magic_offset']:x}（OEM 前缀头）")

    # 1) 未压缩：直接找 arm64 头
    hit = find_image(data)
    if hit:
        off, size = hit
        # boot header 的 kernel_size 才是内核 blob 的边界；Image 自带的 image_size
        # 有时比它大（对齐/附带 DTB 的记账差异），取小的那侧，免得把 ramdisk 读进来
        if hdr and 0x400000 <= hdr["kernel_size"] < size:
            size = hdr["kernel_size"]
        return _result("boot" if hdr else "raw_image", data[off:off + size],
                       container=(f"boot v{hdr['header_version']}" if hdr else "raw Image"),
                       page_size=hdr["page_size"] if hdr else None,
                       header_version=hdr["header_version"] if hdr else None,
                       os_version=os_version_str(hdr["os_version"]) if hdr else None,
                       image_offset=off, notes=notes)

    # 2) 压缩：在候选起点逐个试解压
    starts = [0]
    if hdr:
        mo = hdr["magic_offset"]
        pg = hdr["page_size"]
        starts += [mo + pg, mo + pg * 2, mo]        # kernel 在第 1 页；v4 前面多一页签名
    for s in sorted(set(x for x in starts if 0 <= x < len(data) - 8)):
        payload, label = decompress_auto(data[s:])
        if not label:
            continue
        hit2 = find_image(payload, min(len(payload), 0x200000))
        if not hit2:
            continue
        off, size = hit2
        r = _result("boot" if hdr else "compressed_image", payload[off:off + size],
                    container=(f"boot v{hdr['header_version']}+{label}" if hdr else label),
                    page_size=hdr["page_size"] if hdr else None,
                    header_version=hdr["header_version"] if hdr else None,
                    os_version=os_version_str(hdr["os_version"]) if hdr else None,
                    image_offset=off, decompress=label, notes=notes)
        return r

    return _result("unknown", None, notes=notes + ["既没有 arm64 头也没有可解的压缩内核"])


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    outdir = None
    if "--out" in sys.argv:
        outdir = sys.argv[sys.argv.index("--out") + 1]
        args = [a for a in args if a != outdir]
    if not args:
        sys.exit(__doc__)
    for p in args:
        r = unpack(p)
        print("=" * 88)
        print(f"{p}")
        print(f"  kind={r['kind']}  container={r['container']}  image_offset=0x{r['image_offset']:x}")
        if r.get("decompress"):
            print(f"  解压={r['decompress']}")
        if r.get("os_version"):
            print(f"  os_version={r['os_version']}")
        print(f"  release={r.get('release')}")
        if r.get("image"):
            img = r["image"]
            print(f"  Image={len(img):,} bytes")
            ps = r.get("page_shift")
            print(f"  内核页大小={'?' if ps is None else (1 << ps)} "
                  f"({r.get('page_shift_source')})")
        for n in r.get("notes", []):
            print(f"  · {n}")
        if r.get("vendor_boot_kernel_addr"):
            print(f"  vendor_boot kernel_addr=0x{r['vendor_boot_kernel_addr']:x}")
        if outdir and r.get("image"):
            os.makedirs(outdir, exist_ok=True)
            dst = os.path.join(outdir, f"Image-{r.get('release') or 'unknown'}")
            open(dst, "wb").write(r["image"])
            print(f"  → {dst}")


if __name__ == "__main__":
    main()
