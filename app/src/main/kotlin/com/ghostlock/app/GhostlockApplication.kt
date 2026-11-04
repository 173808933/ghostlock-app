package com.ghostlock.app

import android.app.Application
import com.ghostlock.app.data.AndroidGhostlockRepository
import com.ghostlock.app.data.BootGuard
import com.ghostlock.app.data.NativeLogRecovery
import com.ghostlock.app.domain.repository.GhostlockRepository

/** Application composition root. It is the only place that binds data implementations to domain ports. */
class GhostlockApplication : Application() {

    override fun onCreate() {
        super.onCreate()
        instance = this
        BootGuard.init(this)
        /* A run that ended in a panic left its stdout in app-private storage,
         * the only copy that survives the kernel going down. Publish it before
         * anything else can truncate the file, and keep it off the main thread:
         * the write goes through MediaStore. */
        Thread {
            runCatching { NativeLogRecovery.recover(this) }
        }.apply {
            isDaemon = true
            name = "gl-native-log-recovery"
        }.start()
    }

    fun createRepository(): GhostlockRepository = AndroidGhostlockRepository(this)

    companion object {
        @JvmStatic
        lateinit var instance: GhostlockApplication
            private set
    }
}
