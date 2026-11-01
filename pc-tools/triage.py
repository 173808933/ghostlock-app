#!/usr/bin/env python3
"""triage.py — 兼容入口（原「硬门槛/软门槛」判定表已并入 auto.py）

保留这个文件是因为早期笔记/命令里引用的是它。现在它只把参数转给 auto.py，
判定口径完全一致（carve 解包 → 双容器推导 → BTF/代码推导结构 → phys → 页大小）。

    python tools/triage.py boot.img              # 等价于 auto.py boot.img
    python tools/triage.py --scan 目录 ...        # 批量
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    args = sys.argv[1:]
    if not args:
        sys.exit(__doc__)
    if args and args[0] == "--scan":
        args = args[1:]
    cmd = [sys.executable, os.path.join(HERE, "auto.py")] + args
    print("[i] triage.py 已并入 auto.py，转发执行", file=sys.stderr)
    sys.exit(subprocess.run(cmd).returncode)


if __name__ == "__main__":
    main()
