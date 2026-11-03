package com.ghostlock.app.data

import android.content.Context
import android.content.SharedPreferences
import android.os.SystemClock
import kotlin.math.abs

/**
 * PHY110 run discipline, encoded from the device-verified operating rules.
 *
 * Two hard rules were paid for with kernel panics on the reference device:
 *
 *  1. **Settle after boot.** Right after `sys.boot_completed=1` the system is
 *     still in its startup storm: on this device the measured loadavg stayed
 *     5.8-7.9 (8-core SoC) from uptime 195s to 271s and only fell to ~4 at
 *     324s. The race threads get descheduled, the punch lands but the PI walk
 *     dereferences garbage and the kernel panics. Measured evidence from the
 *     reference device: failed runs finished their first route at
 *     3193-4700ms, the verified successful run at 6509ms with the system
 *     idle. The gate is 120s by user choice; note the storm has been observed
 *     to last longer, so a panic right at the threshold means the system was
 *     still busy - simply wait longer before the next attempt.
 *
 *  2. **One run per boot.** A second exploit run in the same boot panics
 *     reliably (the futex subsystem is left armed). After a successful run,
 *     modules are activated with a *soft reboot* (`ksud soft-reboot`), never
 *     with a second exploit run.
 *
 * Both checks use [SystemClock] only: /proc/uptime and
 * /proc/sys/kernel/random/boot_id are NOT readable from the app's SELinux
 * domain (untrusted_app), so a file-based check silently degrades to "0s" and
 * would block forever.
 *
 * Same-boot detection cross-checks the monotonic clock against the wall
 * clock: within one boot the two advance by exactly the same amount, so
 * `(now_wall - last_wall) == (now_monotonic - last_monotonic)` identifies a
 * run in the current boot. After a reboot (panic-induced or manual) the two
 * diverge by the downtime plus the previous boot's uptime at run time, which
 * is always far beyond the tolerance below - that is what makes an
 * auto-reboot after a panic correctly re-arm the button instead of nagging
 * the user to restart a device that already restarted.
 */
object Phy110Guard {

    private const val PREFS = "phy110_guard"
    private const val KEY_LAST_RUN_ELAPSED = "last_run_elapsed_realtime"
    private const val KEY_LAST_RUN_WALL = "last_run_wall_clock"
    private const val KEY_LAST_RUN_TS = "last_run_ts"

    /** Minimum time since boot (seconds) before a run is allowed.
     * 180s: the first minutes after boot are dominated by app cold starts and
     * dex2oat, and the heap spray needs the slab to have settled. Two minutes
     * still let a run start while the launcher was thawing (loadavg 6-8),
     * which is exactly the state that turns W1 into a missed draw. */
    const val SETTLE_SECONDS: Int = 180

    /** Slack for the monotonic/wall cross-check (NTP jitter, scheduling). */
    private const val SAME_BOOT_TOLERANCE_MS = 5_000L

    @Volatile
    private var prefs: SharedPreferences? = null

    fun init(context: Context) {
        if (prefs == null) {
            synchronized(this) {
                if (prefs == null) {
                    prefs = context.applicationContext
                        .getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                }
            }
        }
    }

    /** Result of [check]: [ok] false means the run must not start. */
    data class Gate(val ok: Boolean, val message: String)

    fun check(): Gate {
        val uptimeMs = SystemClock.elapsedRealtime()
        val uptimeSeconds = (uptimeMs / 1000).toInt()
        if (uptimeMs < SETTLE_SECONDS * 1000L) {
            val wait = SETTLE_SECONDS - uptimeSeconds
            return Gate(
                false,
                "系统刚启动 ${uptimeSeconds}s（启动风暴期负载高，race 线程易被调度抖动打乱而 panic）。" +
                    "请等待约 ${wait}s 再运行，期间不要碰手机。",
            )
        }
        val lastElapsed = prefs?.getLong(KEY_LAST_RUN_ELAPSED, -1L) ?: -1L
        val lastWall = prefs?.getLong(KEY_LAST_RUN_WALL, -1L) ?: -1L
        if (lastElapsed >= 0 && lastWall >= 0) {
            val wallDelta = System.currentTimeMillis() - lastWall
            val monoDelta = uptimeMs - lastElapsed
            if (abs(wallDelta - monoDelta) <= SAME_BOOT_TOLERANCE_MS) {
                return Gate(
                    false,
                    "本次开机已经运行过一次 exploit。同一开机内第二次运行必然 panic（futex 子系统已布防）。" +
                        "请先重启手机；若 root 已获取，用「软重启」激活模块即可，不要重跑 exploit。",
                )
            }
        }
        return Gate(true, "")
    }

    /** Record that a run was started in the current boot. */
    fun markRun() {
        prefs?.edit()
            ?.putLong(KEY_LAST_RUN_ELAPSED, SystemClock.elapsedRealtime())
            ?.putLong(KEY_LAST_RUN_WALL, System.currentTimeMillis())
            ?.putLong(KEY_LAST_RUN_TS, System.currentTimeMillis())
            ?.apply()
    }
}
