package com.ghostlock.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.os.IBinder

/**
 * Keeps the process alive while the exploit race is running.
 *
 * ColorOS freezes and kills background apps aggressively. A SIGKILL of the
 * armed exploit process wedges the futex subsystem (workers stuck in
 * `rt_mutex_adjust_prio_chain`), so the process must survive the whole run.
 * A foreground service raises the process priority above the LMK/OOM killer
 * without touching any device state.
 */
class KeepAliveService : Service() {

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(
            NotificationChannel(CHANNEL_ID, "运行状态", NotificationManager.IMPORTANCE_LOW),
        )
        val notification = Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("GhostLock 正在运行")
            .setContentText("提权进行中，请勿关闭应用、勿重启手机")
            .setSmallIcon(android.R.drawable.stat_notify_sync)
            .setOngoing(true)
            .build()
        startForeground(NOTIFICATION_ID, notification)
    }

    companion object {
        const val CHANNEL_ID = "ghostlock_run"
        const val NOTIFICATION_ID = 0x474C
        const val ACTION_START = "com.ghostlock.app.action.KEEP_ALIVE_START"
        const val ACTION_STOP = "com.ghostlock.app.action.KEEP_ALIVE_STOP"
    }
}
