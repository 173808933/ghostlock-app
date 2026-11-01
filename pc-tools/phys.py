#!/usr/bin/env python3
"""
phys.py — 内核物理加载地址（kernel_phys_load / kernel_phys_offset）推导

为什么需要
----------
GLK1 里的这两个值决定「符号偏移 → 物理地址」的换算，选错就是 W1 目标算错。
官方 extract_rs 的来源优先级：
    --phys 覆盖 > xbl_config.img 的 FDT > uefi.img > vendor_boot.img 的 kernel_addr
    > 有 root 时读 /proc/iomem

三条静态来源（本工具都实现了）：
  1. **xbl_config.img**（qcom 正解）
     里面是一个或几个 FDT（常见外面套一层 ELF），`/soc/memorymap/memory@<addr>`
     节点用 `MemLabel = "Kernel"` 标出内核加载区，`MemLabel = "DDR"` 标出 DRAM 基址。
     → kernel_phys_load = Kernel 区地址，kernel_phys_offset = DDR 基址
  2. **vendor_boot.img 的 kernel_addr**（MediaTek 的官方路径）
     header: magic "VNDRBOOT"(0..8), header_version(8..12), page_size(12..16), kernel_addr(16..20)
     classify：kernel_addr 低 20 位 == 0x80000（ARM64 Image 的 512K 文本对齐）
               ⇒ phys_offset = kernel_addr − 0x80000；低 20 位 == 0 ⇒ 无独立 offset
  3. **qcom 默认值** 0xA8000000 / 0x80000000（11 个 qcom build 实证走通，但非通用定理）

用法
----
    python phys.py --xbl-config xbl_config.img
    python phys.py --vendor-boot vendor_boot.img
    python phys.py Image                        # 只报告平台线索与建议值
"""
import re
import struct
import sys

VNDRBOOT_MAGIC = b"VNDRBOOT"
FDT_MAGIC = b"\xd0\x0d\xfe\xed"
ARM64_TEXT_ALIGN = 0x80000          # 512 KiB，与官方一致

QCOM_DEFAULT = (0xA8000000, 0x80000000)


# --------------------------------------------------------------------------- FDT
def _fdt_walk(data, base):
    """返回 [(节点路径, {属性名: 值字节})]；结构块里遇到非法 token 就停"""
    (magic, total, off_struct, off_strings, off_rsv, ver, last_comp, boot_cpu,
     size_strings, size_struct) = struct.unpack_from(">10I", data, base)
    strings = data[base + off_strings: base + off_strings + size_strings]
    p = base + off_struct
    end = min(base + total, len(data))
    path, out = [], []
    while p + 4 <= end:
        tok = struct.unpack_from(">I", data, p)[0]
        p += 4
        if tok == 1:                                  # BEGIN_NODE
            e = data.find(b"\x00", p, end)
            if e < 0:
                break
            path.append(data[p:e].decode("utf-8", "replace"))
            out.append(("/" + "/".join(path), {}))
            p = (e + 1 + 3) & ~3
        elif tok == 2:                                # END_NODE
            if path:
                path.pop()
        elif tok == 3:                                # PROP
            if p + 8 > end:
                break
            ln, noff = struct.unpack_from(">II", data, p)
            p += 8
            e = strings.find(b"\x00", noff)
            name = strings[noff:e if e >= 0 else None].decode("utf-8", "replace")
            if p + ln > len(data):
                break
            if out:
                out[-1][1][name] = data[p:p + ln]
            p = (p + ln + 3) & ~3
        elif tok == 4:                                # NOP
            continue
        elif tok == 9:                                # END
            break
        else:
            break
    return out


def _label_addr(path, props):
    """从 memory@<addr> 节点取地址 + MemLabel"""
    name = path.rsplit("/", 1)[-1]
    m = re.search(r"@([0-9A-Fa-f]+)$", name)
    if not m:
        return None, None
    label = props.get("MemLabel", b"").rstrip(b"\x00").decode("utf-8", "replace")
    return int(m.group(1), 16), label


def from_xbl_config(path):
    """解析 xbl_config.img（ELF 包裹或裸 FDT 都行）→ (load, ddr_base, 明细)

    qcom 的 xbl_config 里通常有 2 个 FDT（小的给早期引导、大的全量），
    我们只需要 `/soc/memorymap` 里的 MemLabel=Kernel / DDR 两条。
    """
    data = open(path, "rb").read()
    offs, p = [], 0
    while True:
        i = data.find(FDT_MAGIC, p)
        if i < 0:
            break
        p = i + 4
        if i + 40 > len(data):
            continue
        total = struct.unpack_from(">I", data, i + 4)[0]
        if 0x200 <= total <= len(data) - i:
            offs.append(i)
    if not offs:
        raise ValueError("xbl_config 里没找到 FDT")
    kernels, ddrs = [], []
    for o in offs:
        for node, props in _fdt_walk(data, o):
            addr, label = _label_addr(node, props)
            if addr is None:
                continue
            if label == "Kernel":
                kernels.append((addr, node))
            elif label == "DDR":
                ddrs.append((addr, node))
    if not kernels:
        raise ValueError("xbl_config 的 memorymap 里没有 MemLabel=Kernel 的节点")
    load = max(a for a, _ in kernels)              # 取较高的那个（内核实际落点）
    ddr = max((a for a, _ in ddrs), default=None)
    return load, ddr, {"kernels": kernels, "ddrs": ddrs, "dtb_offsets": offs}


# --------------------------------------------------------------------------- vendor_boot
def classify_vendor_boot_addr(load):
    """按 MediaTek 的对齐约定从 kernel_addr 推 (load, offset|None)"""
    low = load & 0xFFFFF
    if low == ARM64_TEXT_ALIGN:
        return load, load - ARM64_TEXT_ALIGN
    if low == 0:
        return load, None
    raise ValueError(f"kernel_addr=0x{load:x} 的低 20 位是 0x{low:05x}，"
                     f"不符合已知 MTK 对齐（0x{ARM64_TEXT_ALIGN:x} 或 0），拒绝猜")


def from_vendor_boot(path):
    data = open(path, "rb").read(32)
    if len(data) < 20 or data[:8] != VNDRBOOT_MAGIC:
        raise ValueError("不是 vendor_boot.img（缺 VNDRBOOT 魔数）")
    version = struct.unpack_from("<I", data, 8)[0]
    if version < 3:
        raise ValueError(f"vendor_boot header_version={version}，需要 >= 3")
    load = struct.unpack_from("<I", data, 16)[0]
    return classify_vendor_boot_addr(load)


def platform_hint(image_bytes):
    """从镜像里猜平台（只做提示，不做判定）"""
    has_qcom = b"qcom," in image_bytes or b"Qualcomm" in image_bytes
    has_mtk = b"mediatek," in image_bytes or b"MTK" in image_bytes
    if has_mtk and not has_qcom:
        return "mediatek"
    if has_qcom and not has_mtk:
        return "qcom"
    if has_qcom and has_mtk:
        return "both"          # 通用 GKI 镜像常见：两家 DTS 都编进去了
    return "unknown"


def probe(image_path=None, vendor_boot=None, override=None, xbl_config=None):
    """返回 dict(load, offset, source, confidence, note)"""
    if override:
        load, off = override
        return {"load": load, "offset": off, "source": "--phys 覆盖",
                "confidence": "high", "note": "用户显式指定"}
    if xbl_config:
        try:
            load, ddr, det = from_xbl_config(xbl_config)
            return {"load": load, "offset": ddr, "source": "xbl_config memorymap",
                    "confidence": "high",
                    "note": f"MemLabel=Kernel@{load:#x}，DDR@{ddr:#x}（{len(det['dtb_offsets'])} 个 FDT）"
                            if ddr else f"MemLabel=Kernel@{load:#x}，未找到 DDR 标签"}
        except Exception as e:                             # noqa: BLE001
            return {"load": None, "offset": None, "source": "xbl_config 解析失败",
                    "confidence": "low", "note": str(e)}
    if vendor_boot:
        try:
            load, off = from_vendor_boot(vendor_boot)
            return {"load": load, "offset": off, "source": "vendor_boot kernel_addr",
                    "confidence": "high", "note": "官方 MTK 路径"}
        except Exception as e:                             # noqa: BLE001
            return {"load": None, "offset": None, "source": "vendor_boot 解析失败",
                    "confidence": "low", "note": str(e)}
    hint = "unknown"
    if image_path:
        hint = platform_hint(open(image_path, "rb").read())
    if hint in ("qcom", "both", "unknown"):
        return {"load": QCOM_DEFAULT[0], "offset": QCOM_DEFAULT[1], "source": "qcom 默认",
                "confidence": "medium",
                "note": "与 11 个 qcom build 一致，但未证实；给 xbl_config.img 可确认"}
    return {"load": None, "offset": None, "source": "MediaTek 且未给 vendor_boot",
            "confidence": "low", "note": "请提供 vendor_boot.img 或 --phys 显式值"}


if __name__ == "__main__":
    args = sys.argv[1:]
    if not args:
        sys.exit(__doc__)
    if args[0] == "--xbl-config":
        try:
            load, ddr, det = from_xbl_config(args[1])
            print(f"kernel_phys_load   = 0x{load:x}")
            print(f"kernel_phys_offset = {('0x%x' % ddr) if ddr else 'None'}")
            for a, n in det["kernels"]:
                print(f"  Kernel 区: 0x{a:x}  {n}")
            for a, n in det["ddrs"]:
                print(f"  DDR     : 0x{a:x}  {n}")
        except Exception as e:                             # noqa: BLE001
            sys.exit(f"失败: {e}")
    elif args[0] == "--vendor-boot":
        try:
            load, off = from_vendor_boot(args[1])
            print(f"kernel_phys_load   = 0x{load:x}")
            print(f"kernel_phys_offset = {'None' if off is None else hex(off)}")
        except Exception as e:                             # noqa: BLE001
            sys.exit(f"失败: {e}")
    else:
        r = probe(image_path=args[0])
        print(f"平台线索: {platform_hint(open(args[0], 'rb').read())}")
        print(f"建议 load=0x{r['load']:x} offset=0x{r['offset']:x}" if r["load"] is not None
              else "建议：无法静态确定（见 note）")
        print(f"来源={r['source']} 置信度={r['confidence']}\n  {r['note']}")
