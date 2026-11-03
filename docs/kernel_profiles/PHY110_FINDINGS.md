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

`GL_PUNCH` 只在这一处判定：

```kotlin
val useSigret = prebuiltBlob || carriedPunch == "sigret" || importedSigret
```

三个来源都必须保留，因为各自覆盖不同场景：

| 来源 | 覆盖场景 | 失效条件 |
|---|---|---|
| `prebuiltBlob` | assets 里带的校准 blob | 该 release 没有 prebuilt |
| `carriedPunch`（`filesDir/punch.txt`） | 手动导入、迁移过的 profile | 文件写失败 |
| `importedSigret`（prefs） | 走过 app 导入流程的 profile | **跨进程不可见** |

`SharedPreferences` 在 app 进程与 UserService 进程之间**不做同步**，各自缓存。
所以载体必须是文件，不能是 prefs。

写载体时优先取 `config.punch`，为空则扫描 `renderResolvedForDebug()` 的输出——
后者是 debug dump 用的那份文本，实测一定带 `punch` 行。

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
3. `/sdcard` 的 SELinux 标签是 `fuse`，`fsync` 只保证交给 MediaProvider

现在 `main()` 开头会先打一行并 `fsync`：

| 日志内容 | 判读 |
|---|---|
| 空文件 | native 没起来（动态链接 / seccomp / SELinux） |
| 只有 `native start` | 死在 profile 解码或地址解析 |
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

卸载 KernelSU 时注意：**只卸管理器不够**，模块目录残留会在重启后继续加载。正确顺序是
先删/禁用所有模块 → 卸载框架 → 重启 → 确认 `su` 失败 → 再跑 exploit。

同理，调度类模块（如 "sense 调度"）会改动 `sched_setattr` / `pick_next_task` 的行为，
直接破坏 PI 死锁的时序，表现为 `CMP_REQUEUE_PI` 之后卡在 `waiting route_done`。
