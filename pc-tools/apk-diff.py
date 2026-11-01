#!/usr/bin/env python3
"""Compare two GhostLock APKs and list what the newer build added.

The official build number lives only in `AndroidManifest.xml` (versionCode);
there is no public changelog, so the reliable way to learn "what changed in
build N" is to diff the artifacts themselves:

  * manifest     versionCode / versionName / permissions
  * assets       new/removed kernel_profiles (which kernels became supported)
  * dex          new strings -> new UI text, log lines, config keys, class names
  * native .so   new strings -> new route/profile fields, shell snippets

Usage:
    python apk-diff.py NEW.apk [OLD.apk] [--full] [--json]

OLD defaults to the bundled 567 snapshot path if it exists (see OLD_DEFAULT).
Exit code is 0 when at least one category differs, 2 when the inputs are the
same version, 1 on error.
"""
import json
import os
import re
import struct
import sys
import zipfile

OLD_DEFAULT = r"C:\Users\XXL\Downloads\iQOO12 12Pro临时root\GhostLock_1.2.apk"

# Noise that carries no meaning about features: Kotlin synthetic names,
# desugaring plumbing, R8/inline markers.
NOISE = re.compile(
    r"(^\$|\$\$|^\d+$|^[^\w]+$|^L[a-z0-9/]+;$|^<|^\)|^\(|"
    r"_u24lambda|isInitialized|component\d|copy-default|access\$|"
    r"^\$i\$|lambda\$|^\d+L$|^v\d+$|^-[0-9]+$)"
)


def printable_strings(data, minlen=5):
    return {m.group().decode("ascii") for m in re.finditer(rb"[\x20-\x7e]{%d,}" % minlen, data)}


def dex_strings(blob):
    """All string_ids entries of one dex file (uleb128 length + MUTF-8)."""
    out = set()
    if len(blob) < 0x70 or blob[:4] != b"dex\n":
        return out
    try:
        size, off = struct.unpack_from("<II", blob, 0x38)
    except struct.error:
        return out
    for i in range(size):
        try:
            p = struct.unpack_from("<I", blob, off + 4 * i)[0]
            length = 0
            shift = 0
            while True:
                b = blob[p]
                p += 1
                length |= (b & 0x7F) << shift
                shift += 7
                if not b & 0x80:
                    break
            if length == 0 or length > 4096:
                continue
            out.add(blob[p:p + length].decode("utf-8", "replace"))
        except (struct.error, IndexError):
            continue
    return out


def resolve_aapt2():
    """aapt2 gives an exact versionCode; the binary-XML layout is not stable."""
    import shutil
    import glob
    for cand in (
        shutil.which("aapt2"),
        r"C:\Other\Andriod\toolchain\android-sdk\build-tools\37.0.0\aapt2.exe",
    ):
        if cand and os.path.isfile(cand):
            return cand
    for pat in (
        r"C:\Other\Andriod\toolchain\android-sdk\build-tools\*\aapt2.exe",
        os.path.expanduser("~/AppData/Local/Android/Sdk/build-tools/*/aapt2.exe"),
    ):
        hits = sorted(glob.glob(pat))
        if hits:
            return hits[-1]
    return None


def badging(path):
    """(versionCode, versionName) via aapt2, or (None, None)."""
    aapt2 = resolve_aapt2()
    if not aapt2:
        return None, None
    import subprocess
    try:
        out = subprocess.run([aapt2, "dump", "badging", path],
                             capture_output=True, text=True, timeout=120).stdout
    except (OSError, subprocess.SubprocessError):
        return None, None
    code = re.search(r"versionCode='(\d+)'", out)
    name = re.search(r"versionName='([^']*)'", out)
    return (int(code.group(1)) if code else None,
            name.group(1) if name else None)


def read_apk(path):
    info = {"path": os.path.abspath(path), "assets": set(), "dex": set(), "so": set(),
            "version_code": None, "version_name": None}
    info["version_code"], info["version_name"] = badging(path)
    with zipfile.ZipFile(path) as z:
        for name in z.namelist():
            if name.startswith("assets/"):
                info["assets"].add(name)
            elif re.fullmatch(r"classes\d*\.dex", name):
                info["dex"] |= dex_strings(z.read(name))
            elif name.startswith("lib/arm64-v8a/") and name.endswith(".so"):
                # keep the per-library provenance so a diff can say which .so grew
                for s in printable_strings(z.read(name)):
                    info["so"].add(f"{os.path.basename(name)}:{s}")
    return info


def meaningful(strings, old=None):
    """Drop synthetic noise; when an old set is given, keep only the new items."""
    picked = []
    for s in strings:
        if NOISE.search(s):
            continue
        if old is not None and s in old:
            continue
        picked.append(s)
    return sorted(picked)


def cluster(items, keywords):
    """Group diff lines by the feature keyword they mention."""
    out = {}
    for kw in keywords:
        hit = [s for s in items if kw in s.lower()]
        if hit:
            out[kw] = hit
    return out


def main(argv):
    args = [a for a in argv if not a.startswith("--")]
    flags = {a for a in argv if a.startswith("--")}
    if not args:
        sys.exit(__doc__)
    new_path = args[0]
    old_path = args[1] if len(args) > 1 else OLD_DEFAULT
    if not os.path.isfile(new_path):
        sys.exit(f"[FATAL] not found: {new_path}")
    if not os.path.isfile(old_path):
        sys.exit(f"[FATAL] old apk not found: {old_path} (pass it explicitly)")

    new = read_apk(new_path)
    old = read_apk(old_path)
    report = {
        "new": {"path": new["path"], "version_code": new["version_code"],
                "version_name": new["version_name"]},
        "old": {"path": old["path"], "version_code": old["version_code"],
                "version_name": old["version_name"]},
        "assets_added": sorted(new["assets"] - old["assets"]),
        "assets_removed": sorted(old["assets"] - new["assets"]),
        "dex_added": meaningful(new["dex"], old["dex"]),
        "dex_removed": meaningful(old["dex"], new["dex"]),
        "so_added": meaningful(new["so"], old["so"]),
        "so_removed": meaningful(old["so"], new["so"]),
    }
    report["profile_added"] = [
        os.path.basename(a)[:-5] for a in report["assets_added"]
        if a.startswith("assets/kernel_profiles/") and a.endswith(".conf")
        and not os.path.basename(a).startswith(("execution-", "credential-", "kernelsnitch-"))
        and "template" not in a
    ]
    report["feature_hits"] = cluster(
        report["dex_added"] + report["so_added"],
        ["ksud", "manager", "shizuku", "soft", "reboot", "profile", "extract",
         "payload", "ota", "vr_", "tracepoint", "attempt", "arm_", "waiter",
         "selinux", "seccomp", "vermagic", "kmi", "module", "log", "backup", "export"],
    )

    if "--json" in flags:
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0

    same = new["version_code"] == old["version_code"]
    print("=" * 74)
    print(f"new: {new_path}")
    print(f"     versionCode={new['version_code']} versionName={new['version_name']}")
    print(f"old: {old_path}")
    print(f"     versionCode={old['version_code']} versionName={old['version_name']}")
    print("=" * 74)
    if same:
        print("!! same versionCode: the two inputs are the same build\n")
        return 2

    def show(title, items, limit=None):
        print(f"\n### {title} ({len(items)})")
        if not items:
            print("   (none)")
            return
        shown = items if limit is None or "--full" in flags else items[:limit]
        for s in shown:
            print("   ", s[:150])
        if shown is not items and len(items) > len(shown):
            print(f"    ... {len(items) - len(shown)} more (--full)")

    show("new kernel profiles", report["profile_added"])
    show("new assets (non-profile)", [a for a in report["assets_added"]
                                     if not a.startswith("assets/kernel_profiles/")], 40)
    print(f"\n### profile/assets removed ({len(report['assets_removed'])})")
    for a in report["assets_removed"][:20]:
        print("   ", a)

    print("\n### feature keywords in the new strings")
    if not report["feature_hits"]:
        print("   (none)")
    for kw, hits in sorted(report["feature_hits"].items(), key=lambda kv: -len(kv[1])):
        print(f"   [{kw}] {len(hits)}")
        for s in hits[:6]:
            print("       ", s[:140])

    show("new dex strings (filtered)", report["dex_added"], 60)
    show("new native strings (filtered)", report["so_added"], 60)
    print(f"\n### removed dex strings (filtered): {len(report['dex_removed'])}")
    print(f"### removed native strings (filtered): {len(report['so_removed'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
