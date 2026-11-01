package com.ghostlock.app.data

import android.content.Context

/**
 * Bundled prebuilt profiles: `assets/prebuilt/<release>.glk1`.
 *
 * Every bundled entry is a PHY110 (OPPO Find X7 Ultra) artifact calibrated
 * and verified on the real device. Statically derived profiles for sibling
 * devices on the same kernel tree are deliberately NOT bundled: those devices
 * are expected to run the on-device derivation (parse a boot/Image and import
 * the generated profile) so that an unverified blob can never reach a device
 * that never produced it.
 *
 * For PHY110 the blob is the exact profile that was calibrated on hardware:
 *
 *   magic 0x0D000721, version 2, frontend 1, backend 1, route 3
 *   (multicast_waiter: waiter_off=0xe8, buffer_size=0x200, task_offset=0x30,
 *    lock_offset=0x38) plus the tuned execution.* stages and
 *    execution.recommended_cpus (main=5, consumer=6).
 *
 * The HOCON converter cannot reproduce this blob byte for byte (the shipped
 * `ghostlock-phy110.conf` predates the multicast route calibration and
 * describes the tcp_zerocopy route instead), so the prebuilt blob wins over
 * conf resolution whenever it exists for the running kernel.
 *
 * The matching punch is selected with GL_PUNCH=sigret (64-bit rt_sigreturn
 * fpsimd bulk copy). The default MCAST_BLOCK_SOURCE setsockopt punch is
 * infeasible on this kernel, and an upstream prebuilt APK cannot be used.
 */
object Phy110Profiles {

    private const val PREBUILT_DIR = "prebuilt"

    /** Release string of the reference device this build was verified on. */
    const val VERIFIED_RELEASE: String = "6.1.141-android14-11-o-g984c12362a16"

    /** Device-verified GLK1 v2 blob for [release], or null when not bundled. */
    fun prebuiltBlob(context: Context, release: String): ByteArray? {
        if (release.isEmpty()) return null
        return runCatching {
            context.applicationContext.assets.open("$PREBUILT_DIR/$release.glk1").use { it.readBytes() }
        }.getOrNull()
    }

    /** True when [blob] is byte-identical to the bundled prebuilt profile. */
    fun isPrebuilt(context: Context, release: String, blob: ByteArray): Boolean =
        prebuiltBlob(context, release)?.contentEquals(blob) == true
}
