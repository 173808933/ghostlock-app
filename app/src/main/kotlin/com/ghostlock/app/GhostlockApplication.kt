package com.ghostlock.app

import android.app.Application
import com.ghostlock.app.data.AndroidGhostlockRepository
import com.ghostlock.app.data.BootGuard
import com.ghostlock.app.domain.repository.GhostlockRepository

/** Application composition root. It is the only place that binds data implementations to domain ports. */
class GhostlockApplication : Application() {

    override fun onCreate() {
        super.onCreate()
        instance = this
        BootGuard.init(this)
    }

    fun createRepository(): GhostlockRepository = AndroidGhostlockRepository(this)

    companion object {
        @JvmStatic
        lateinit var instance: GhostlockApplication
            private set
    }
}
