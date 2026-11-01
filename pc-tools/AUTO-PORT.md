# 任意机型自动判定（auto.py）

一条命令判断「手上这台机器的 boot.img 能不能走我们这条链路（sigret punch + futex PI）」，
纯静态，不需要设备、不需要官方 extract_rs。

```bash
PY=C:/Users/XXL/.workbuddy/binaries/python/envs/default/Scripts/python.exe

# 单机判定
$PY tools/auto.py boot.img
# 批量 + 直接产出可用 profile（GLK1）
$PY tools/auto.py 某目录/ --out 输出目录 --emit
# MTK：给 vendor_boot 让它自己推 phys
$PY tools/auto.py boot.img --vendor-boot vendor_boot.img
# qcom：给 xbl_config 证实 phys（读 memorymap 的 MemLabel=Kernel / DDR）
$PY tools/auto.py boot.img --xbl-config xbl_config.img
# 显式 phys / 不写 phys（沿用运行时内置值）
$PY tools/auto.py boot.img --phys 0xa8000000,0x80000000
$PY tools/auto.py boot.img --phys none
```

## 判决口径

| 结论 | 含义 |
|---|---|
| `✅ USABLE` | 补丁未打、futex 链可算、至少一条容器几何可行、结构偏移有依据 |
| `⚠️ RISKY` | 能算，但有未证实项（无 BTF 且族表未验证 / 页大小未知 / phys 只能给默认值） |
| `❌ N/A` | `remove_waiter` 已打补丁（漏洞不存在）/ futex 链不可得 / 两条容器几何都不可行 / profile 必需符号缺失 |

退出码：`0` 全 USABLE、`1` 有 RISKY、`2` 有 N/A。

## 能吃哪些形态（都实测过）

- AOSP boot **v0/v1/v2/v3/v4**（v3/v4 的字段布局和 v0 不同，已分开解析）
- 裸 `Image`、`Image.gz`、`Image.lz4`（frame 和 **legacy** 两种）、`Image.xz`、`Image.zst`
- 带 OEM 前缀头的镜像（魔数在前 2MB 内任意位置）
- 全量包 zip（自动取 `boot*.img`，递归）
- `vendor_boot.img`（不含内核，但能给出 `kernel_addr` → MTK phys）
- ELF/vmlinux：明确报「不是 boot.img」

## 内部流水线

```
carve.unpack        容器 → Image（含解压）      tools/carve.py
kallsyms            自动定位符号表             tools/extract_symbols_auto.py
                    两种布局都支持：≤6.1（num_syms 在 relative_base 后）
                                    ≥6.4（num_syms 在 names 前）
containers          A) sigret  rt_sigreturn 的 fpsimd 拷贝
                    B) multicast  setsockopt(MCAST_BLOCK_SOURCE) 的 greqs
                    两条都算，取可行的那条      tools/containers.py
structs             BTF 优先；无 BTF → 反汇编推导 + 族表   tools/structs.py
phys                xbl_config 的 memorymap（qcom 正解）/ vendor_boot kernel_addr（MTK）
                    / qcom 默认 / --phys                           tools/phys.py
page                ikconfig（CONFIG_ARM64_*_PAGES）
```

## 换机型时真正会翻车的六处（都已处理）

1. **内核基址写死**：`0xffffffc008000000` 只是 VA_BITS=39/4K 页的 GKI 布局。
   6.6 GKI 是 `0xffffffc080000000`，16K 页又是别的值。现在基址取符号表里的 `_text`。
2. **boot header v3/v4 字段顺序不同**：v0 的 `page_size@36` 在 v4 里是 `header_size@20` 之外的位置，
   按 v0 读会得到 `page_size=0` 并静默走错分支。
3. **压缩内核**：vivo/iQOO 的 v4 镜像常见 **LZ4 legacy**（`02 21 4C 18`），不是 frame 格式。
4. **kallsyms 布局在 6.4 换过**：`num_syms` 从 `relative_base` 后面挪到了 `names` 前面
   （6.6 实测：`num_syms@0x136e748`，`relative_base@0x1553670`，两者隔了 2MB）。
5. **dis 中途停下**：函数里夹字面量池时 capstone 会整段停，函数后半截的拷贝点看不到 →
   现在逐条解码、遇非法指令前进 4 字节重同步。
6. **waiter 定位方式变了**：≤6.1 是 `memset(&waiter, 0, 0x58)`；
   6.6 展开成 `stp xzr`，锚点改为 `rt_mutex_*_proxy_lock(…, &waiter, …)` 的 x1；
   并且 fpsimd 恢复被拆成独立函数 `read_fpsimd_context()`，拷贝目标由调用者传入
   （`add x0, sp, #0x60; bl read_fpsimd_context`），所以 local 从调用点取。

## 已实测的机型 / 内核

| 设备 | 内核 | 结论 |
|---|---|---|
| PHY110 ×8 build | 6.1.118 / 6.1.141 GKI | ✅ USABLE，sigret waiter_off=0xe8（与真机验证版逐字节一致） |
| OPD2401 (Pad 3) ×3 | 6.1.118 / 6.1.141 | ✅ USABLE，0xe8，产物 md5 与已生成版一致 |
| GT5 Pro | 6.1.141-android14-11-o-gffc54a6d2287 | ✅ USABLE，0xe8，GLK1 md5 = `da228a9d…`（真机验证版） |
| iQOO Z11 | 6.6.127-android15 | ❌ N/A：`remove_waiter` 已用 `waiter->task`（6.6 布局 task@0x50），补丁已打 |

推算：Z11 若未修补，sigret 几何为 `waiter_off=0x80 / buffer=0x200 / task=0x50 / lock=0x58`，
`mm_struct_sz=1280`（BTF sizeof=0x4c0 按 HWCACHE_ALIGN 128 向上取整），
`pi_lock=0x90c` 与反汇编 `add x21, x20, #0x90c` 完全吻合 —— 结构层在 6.6 上已交叉验证。

## 边界

- **内核 <5.10 直接判 N/A**：KernelSU late-load 只有 GKI 5.10/6.1/6.6 的 KMI 产物，
  4.x 非 GKI 厂商内核（例：OPPO PEDM00 的 `4.19.157-perf+`）没有可用 `.ko`，链路不成立。
  这类镜像不再去解 kallsyms（4.19 的 kallsyms 布局与 5.x 不同，`relative_base` 在 offsets 数组之前）。
- 4.19/5.4 这类没有 BTF 又是老形态的，结构偏移只能给 low，脚本会拒绝生成 GLK1。
- 页大小 16K/64K 的内核：本链路按 4K 页设计，只会标 RISKY，不要直接上机。
- 静态判定 ≠ 真机可用：静置 120s、同一开机只跑一次、panic 后必须重新重启，这些纪律不变。

## 手机端（APP 内）推导 —— 2026-10-31 起带判定

电脑端 `auto.py` 的判定逻辑已经搬进 APP：`libextract.so`（Rust）新增 **rt_sigreturn（sigret）几何推导**
与 `--analysis-json` 结构化输出，APP 的「设置 → 解析本地镜像 / 解析完整包链接」一次跑完就同时得到
**结论 + 可用配置**。

```
选 boot.img（可附 xbl_config.img）→ 解析
   → 判定卡：✅ 可用 / ⚠️ 待确认 / ❌ 不可用 + 路线 + waiter_off/D/depth/buffer
   → conf 存成「已导入配置」，release 与本机一致即自动生效
```

`--analysis-json` 关键字段（APP 读这些）：

```json
{
  "release": "...", "kernel_major": 6, "kernel_minor": 1,
  "primitive": {"patched": false, "detail": "remove_waiter@0xff9548 unpatched"},
  "punch": "sigret",
  "routes": [{"route": "sigret", "derived": true, "feasible": true,
              "waiter_off": 232, "d": 640, "depth": 408, "buffer": 512}],
  "verdict": {"level": "usable", "reasons": ["rt_sigreturn 写入窗口覆盖 futex waiter"]}
}
```

判定链与 `auto.py` 一致：`remove_waiter` 是否已修 → 内核 <5.10 → sigret 几何是否可行
（`0 ≤ D−depth` 且 `+0x40 ≤ buffer`）。判定为 sigret 时：

- conf 仍写在 `route.multicast_waiter` 槽位（native 从这一段读 waiter 字段），但 waiter_off/buffer
  换成 sigret 的数；
- APP 记住 `punch=sigret`（按 release 存 prefs），运行时自动设 `GL_PUNCH=sigret`；
- 内核太老 / 已修补 → 直接出 ❌ 并说明原因，不再报 kallsyms 解析失败。

回归（Rust 输出 vs 电脑端 `auto.py`，逐位一致）：

| 内核 | sigret 结论 |
|---|---|
| 6.1.118-o-g16ddc6ff732a（一加 Ace 3 Pro） | 0xe8（D 0x280 / depth 0x198） |
| 6.1.118-o-gac2e718ebee6（PHY110 16.0.1.300） | 0xe8 |
| 6.6.118-ge58033dc8ea6（PLW110） | 0x80（depth 0x200） |
| 6.1.145-maybe-dirty（iQOO 12） | 不可行（D 0x280 < depth 0x2d8，差 0x58） |
| 6.6.127（iQOO Z11，已修补） | ❌ 不可用（remove_waiter 已修） |
| 4.19.157-perf+（PEDM00） | ❌ 不可用（内核 <5.10） |
