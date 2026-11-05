# PHY110 分支：已验证的结论

本文件记录本分支相对上游的取舍中，**哪些有真机证据支撑、哪些只是推断**。
修改本分支前先读这份，避免重复踩已经踩过的坑。

## 一、哪些内核可用

判定口径：`remove_waiter()` 是否仍然 `mrs sp_el0` 取 `current`。

| 内核 | 机型 | 43499 | sigret 几何 | 备注 |
|---|---|---|---|---|
| `6.1.141-o-gffc54a6d2287` | Ace 3 Pro / K12s | 未修 | `0xe8` | **完整成功过**（含 W3、KernelSU 模块） |
| `6.1.141-o-ge9a81736fafc` | PHY110 16.0.7.200 | 未修 | `0xe8` | 成功过 |
| `6.1.141-o-g659d588fa0da` | 一加 12 | 未修 | `0xe8` | 静态推导，未上真机 |
| `6.1.141-o-g6ed3e67335d5` | 真我 GT7 Pro | 未修 | `0xe8` | W1 会卡在页选择（见第三节） |
| `6.1.157-o-g00d81d97d759` | Ace 3 Pro 1301 | **已修** | `0xe8` | 走不通 |
| `6.1.157-o-ga43993466696` | Neo7 | **已修** | `0xe8` | 走不通 |
| `6.12.58-o-gdd6fd5c98918` | vivo X300 Pro | **已修** | **不可行** | waiter 尾部 `0x330` > 拷贝上限 `0x200` |

规律：**6.1.157 是分界线**，这一批及以上的 6.1 内核，`remove_waiter` 都已修复。

同一个 6.1.141 分支内，`init_cred`、`selinux_enforcing`、`init_task` 三个偏移在各 build
之间**完全一致**（一加 12 与 Ace 3 Pro 逐字节相同），只有 `security_hook_heads` 会相差
1–2 KB。跨 build 复用 profile 时重点核对前者即可。

## 二、W1b 必须在 W1 之后排空

W1 完成时 futex 子系统仍处于饱和状态。紧接着的 W1b 碰撞扫描会在 route 中途被
SIGKILL：consumer 不释放、日志停在 `waiting route_done`、连退出码都来不及写。

跨这条边界的内存压力读数会从 `~2e5` 跳到 `~4e7`（`[mem] total=`）。实测加入 300ms
的 `sched_yield + usleep` 排空后，W1b 可以正常走完。

用 `sched_yield` 而不是 `usleep` 单独睡眠：需要有一个线程保持可运行状态，上一轮的
waiter 才能按时超时退出。

## 三、W1 的写入是"抽签"，不是确定性写入

`route_done success=1` 只说明 punch 打出去了，**不说明它落在 prepare_kernel_page
选中的那一页上**。verify 只能看到"目标没变"，无法区分几何错误和运气不好。

因此：

- `w1_attempts` 由 profile 决定（代码里 3 只是下限）。硬编码 3 曾让一个几何完全
  正确的 profile 报出 "Write 1 failed"。
- `6.1.141-o-g6ed3e67335d5` 上会出现另一种失败：spray 拿到的页 `bit16` 恒为 0，
  而 W1 要求 `(page_base >> 16) & 1 == 1`（否则写 `selinux_state.initialized` 的值
  是偶数，后续每次 SID 查找都会失败）。连续 5 次抽到同一段 64KB 区间，加次数救不了。

**`errno=35` 也不代表原语存在。** `CMP_REQUEUE_PI` 返回 `EDEADLK` 只说明 futex 的
死锁检测发现了一个环，这是 `rt_mutex` 的常规逻辑。43499 的漏洞点在**清理路径**：
`remove_waiter` 该用 `waiter->task` 却用了 `current`。修好之后，死锁照样能造、
`EDEADLK` 照样返回、`route_done` 照样 `success=1`，但 `pi_blocked_on` 被正确清理，
没有悬挂指针，punch 写过去什么也打不中——表现就是"参数全对、日志全绿、Write 失败"。

2026-11 在 iQOO Z9 Turbo+（`6.1.145-android14-11-maybe-dirty`）上就是这个组合：
`requeue try=200 ret=-1 errno=35` → `route_done success=1` → `Write 1 failed`，
而反汇编显示该内核 `remove_waiter` 已改用 `waiter->task`。

判断原语只有两条路：反汇编看 `remove_waiter` 里有没有 `mrs x?, sp_el0`，或者真机上
看 W1 能不能变 permissive。日志里的 errno 一概不能作数。

## 四、W3 在 app 流程可以成功

上游的 fork `b0r1s-69` 在 6.6.118 上记录过：`WriteMode::Zero` 写 `thread_info.flags`
会清掉全部 `TIF_*` 标志位和 filter 引用计数，导致 panic；掩码形式又因为写原语只能
携带 0 或合法内核指针而落不进去，结论是 app 流程的 W3 无解，只能走 Shizuku。

**这个结论不适用于 6.1.141。** 实测日志：

```
[*] seccomp finit_module probe = 0x16        (22 = EINVAL，syscall 进得去)
[+] child seccomp filter bypassed
[+] child seccomp fully bypassed (forked workers run filter-free)
[ksu] [+] KernelSU module loaded
```

zero-write 既没有 panic，也确实清掉了 filter。因此**不要给 profile 设
`w3_attempts = 0`** —— 那会主动放弃模块加载能力，而这颗内核本来拿得到。

W3 的命中率同样不高（一次成功样本里试了 5 轮 route），`w3_attempts = 6` 是合理的。

## 五、Shizuku 路径的 punch 传递

**跨进程唯一可靠的方式是 binder 参数**，不是文件，也不是 prefs。

UserService 跑在 uid 2000，app 的 `filesDir` 属主是 app uid，`punch.txt`
读出来是 `EACCES`，被 `runCatching` 吞成空串。日志里两侧对不上就是这么来的：

```
app 侧        <s> punch carrier='sigret' config=sigret render=sigret
service 侧    <s> punch: carrier='' prebuilt=false prefs=false -> default
```

所以 `runExploit(..., @nullable String punch, ...)` 直接带参数过去。判据：

```kotlin
val useSigret = punch == "sigret" || prebuiltBlob
```

判据只剩两条，没有第三条：

| 来源 | 覆盖场景 | 失效条件 |
|---|---|---|
| **binder `punch`** | 全部（app 解析后随调用送达） | AIDL 版本不匹配 |
| `prebuiltBlob` | assets 里带的校准 blob（天然是 sigret） | 该 release 没有 prebuilt |

`filesDir/punch.txt` 与 `punch_release`/`punch_mode` 两个 prefs 键已经删除。
它们各自因为权限（uid 2000 vs app 私有目录）和进程隔离（SharedPreferences
不跨进程）永远读不到，留在分支上只会让下一个人以为还有别的通道。

改 AIDL 后必须同步 bump `UserServiceArgs.version(...)`，否则 Shizuku 会复用
按旧接口解压出来的 dex，服务端仍是旧代码。

**验证（2026-11-04，6.1.141-o-gffc54a6d2287，Shizuku 模式）**

```
<s> punch: binder='sigret' carrier='' prebuilt=false prefs=false -> sigret
[*] multicast route enter ... punch=sigret
[+] SELinux permissive                 (W1 attempt 2)
[T+14626ms] Write 1 complete           (W1b attempt 1)
[*] child uid = 0                      (W2 attempt 1)
[+] no app seccomp filter (adb/shell flow); skipping W3
[T+23552ms] exploit complete
[+] KernelSU ready
```

整条链路 23.5 秒，W1 用掉两次抽签、W1b 与 W2 各一次。`carrier=''` 是预期值——
文件通道在这个方向上永远读不到，`binder=` 才是实际生效的那个。

app 侧解析集中在一处 `resolvePunch()`：`config.punch` → `renderResolvedForDebug()`
的 `punch` 行。direct 与 Shizuku 两条路径都调它，不再各写一份。
`punchOf()` 里曾用 `as? String`，遇到非字符串类型静默返回 null；`resolvePunch`
现在统一 trim 并过掉字面量 `"null"`。

## 六、不要把别人的 fork 改动直接套用

`reset_cpu_pin()` 曾被改成"保存/恢复调用者亲和性"（来自 QikseekDev 的 fork）。
在 PHY110 上点击执行后约 12 秒触发 panic。

原因：本流程开头 `pin_to_core(main_cpu=5)` 已经把主线程钉在 cpu 5，保存下来的 mask
只有 `{5}`；恢复后进程只能在 cpu 5 上运行，而 route 需要在 cpu 6 起 consumer。

上游那句 `memset(&cpuset, 0xff, ...)` 是**故意的**：它放大到所有在线 CPU，内核再与
在线集取交集。看起来粗糙，实际是对的。

**教训：合任何外部改动前，先确认自己的调用顺序和前置状态是否与对方一致。**

## 七、panic 后日志为何经常为空

三个原因叠加：

1. `main()` 一进来就解析 profile、算地址，第一个 `[T+]` 标记之前没有任何输出
2. 只有 `timer_mark` 和 `log_sync` 调用点会 `fsync`，普通 `pr_info` 只到页缓存
3. **日志归档走 FUSE**：`/sdcard` 的 `fsync` 只把数据交给 MediaProvider，MediaProvider
   真正写进 f2fs 是异步的；panic 时它也一起死，缓冲全丢

第 3 条是"文件有 216 字节、内容全是 NUL"的来源：size 通过 inode 更新提交了，
数据块还在 page cache 里。**只要 panic 就是必然，不是偶发。**

现在的分工：

| 位置 | 文件 | 特性 |
|---|---|---|
| app 私有目录 | `filesDir/.ghostlock_native.log` | f2fs 普通文件，`fsync` 真落盘；native 的 stdout 直接重定向到这里 |
| Download 归档 | `ghostlock-<entry>-<n>.log` | 用户可读，panic 时丢尾 |

落盘点（一次运行约十几次，不影响时序）：

- `main()` 首行 `native start`
- `log_startup_context()` 末尾（`p0 profile` 之后，即开始攻击前）
- `run_state::emit`（每个 stage 边界）
- `timer_mark`

正常退出时 app 清空私有目录那份，所以**文件非空就代表上次是异常结束**。
下次启动 `GhostlockApplication` 会把它搬到
`Download/<exportLocation>/<stamp>-recovered/ghostlock-native-crash.log`。

判读：

| 日志内容 | 说明 |
|---|---|
| 空文件 | native 没起来（动态链接 / seccomp / SELinux） |
| 只有 `native start` | 死在 profile 解码或地址解析 |
| 到 `p0 profile` 为止 | 死在开始攻击前（几何/地址计算） |
| 有 `[T+0ms] exploit start` | 死在攻击流程，看最后一个 T+ 标记 |

日志目录无法迁到 `/data/local/tmp`：该目录标签为 `shell_data_file`，
`untrusted_app` 域没有写权限。

## 八、已装 root 框架的设备不能作为靶机

已 root 的设备上再跑 exploit 会 panic —— 内核函数已被 inline hook 过，
`remove_waiter` / `security_*` / cred 路径都不是原版了。

判断方法：

```bash
adb shell su -c id            # 返回 uid=0 且 context=u:r:ksu:s0
adb shell su -c 'ls /data/adb/ksu'
adb shell su -c 'ls /data/adb/modules'
```

**但要看是哪种 root。** 实测两台 GT5 Pro：GhostLock late-load 进去的 KernelSU 是
**纯内存态**，重启后 `su` 直接不存在，`/data/adb` 里的文件虽然还在但不生效。

```bash
# 重启后立刻查，这一条就能分清
adb shell su -c id
```

- `su: inaccessible or not found` → 内存态，内核已回到原版，可以直接跑 exploit
- 返回 `uid=0 ... u:r:ksu:s0` → 配了开机自启（`boot-completed.d` / `service.d`），
  内核被重新 hook，必须先处理

真正需要"先删模块、再卸框架、再重启"的是后一种。对内存态而言卸载管理器即可，
`/data/adb` 残留不会自己加载。

同理，调度类模块（如 "sense 调度"）会改动 `sched_setattr` / `pick_next_task` 的行为，
直接破坏 PI 死锁的时序，表现为 `CMP_REQUEUE_PI` 之后卡在 `waiting route_done`。

## 九、同 uname 不等于同一内核

vivo 的内核 release 里 `-maybe-dirty` 不带 commit hash，所以**同一个 uname 下可以有
多个不同的内核**。iQOO 12 的三份 glk1 和 iQOO Z9 Turbo+ 的分析结果都是
`6.1.145-android14-11-maybe-dirty`，但：

| 样本 | `remove_waiter` | 43499 | 可用 |
|---|---|---|---|
| iQOO 12（三份 glk1，内容哈希区分） | 仍读 `current` | 未修 | ✅ multicast |
| iQOO Z9 Turbo+（`boot.img` 实测） | `waiter->task`，函数体内 0 处 `sp_el0` | 已修 | ❌ |

两者 `release` 字符串逐字节相同。**按 uname 匹配 profile 会串号**，用户看到"受支持"
却必然 `Write 1 failed`。

区分办法，按可靠性排序：

1. 反汇编 `remove_waiter`（最硬，工作量也最大）
2. `linux_banner` 里的编译器指纹（`Image` 偏移 `0x10d0108` 附近）：
   `Linux version ... clang version 17.0.2 (... d9f89f4d...)`——同一批构建会一致，
   但不同批次能分开
3. glk1 的内容哈希（`tools/` 的缓存键已经这么做了）

**凡是 `-maybe-dirty` 的 release，导入前必须确认 profile 的来源设备。**

## 十、成功率与温度

2026-11-05 在 GT5 Pro（`RMX3888` / `6.1.141-o-g6ed3e67335d5`）上做了 5 轮真机测试，
每轮都是"重启 → 静置 180s → 点执行"：

| 轮次 | 结果 | 失败点 |
|---|---|---|
| 1 | ✅ 完整成功（含 W3 与 KernelSU module loaded） | — |
| 2 | ❌ panic | W2 punch 之后（`T+18320ms PI route done` 后无输出） |
| 3 | ❌ panic | W1b spray 之后、route 之前 |
| 4 | ✅ 完整成功 | — |
| 5 | ❌ 失败 | — |

**成功率约 40%**，且失败点分布在整个 W1→W2 区间。

关键性质：**W1 失败是安全的**（打空 → `Write 1 failed` → 干净退出），
**W1b 和 W2 失败必然 panic**——它们写的是 page 结构 / `task->cred`，写偏就是内存破坏，
进程下一次访问就崩。所以"重试"的真实代价是重启，用户观感就是"一直失败"。

失败时几何与偏移全部正确（`W2 target = perf task + 0x838`，逐字节对上），差异只有
KASLR slide 和抽签运气。两次成功与三次失败的日志除地址外没有结构性差别。

**温度是已确认的相关因素**（实测）：

```
cpuss-0=45.7C  cpuss-1=45.3C  cpuss-2=46.1C  cpuss-3=45.7C
cpu-2-0-1=46.9C
cpu4=960MHz / 2438MHz   cpu5=1190MHz / 2438MHz   cpu6=1190MHz / 2438MHz
```

PI race 的窗口是硬编码的 `arm_hold=20000us`（20ms），consumer 必须在窗口内完成
`sched_setattr(nice=1)` 才能把优先级链踢起来。热节流压低频率后这一脚会迟到，
链断掉，punch 落偏。**设备刚开机就在 45~47°C、频率只有最大值的 39~49%**。

运行前会记录一行：

```
<k> thermal: cpuss-2=46.1C cpu-2-0-1=46.9C cpuss-0=45.7C (HOT - ...)
```

阈值 45°C 只提示不阻断。**收集足够多的"温度 × 结果"对照后再决定是否门控**——
目前两次成功时的温度没有记录，45°C 这个线还是经验值。
