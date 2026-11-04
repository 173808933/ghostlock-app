package com.ghostlock.app.data

import android.content.ContentValues
import android.content.Context
import android.provider.MediaStore
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Recovers the native run log of an attempt that never reached its epilogue.
 *
 * The native process writes its stdout to a file in app-private storage. That
 * is a plain f2fs file, so a kernel panic cannot take the data with it - unlike
 * the Download archive, which goes through FUSE and loses everything still
 * buffered in MediaProvider when the device goes down. The archive is what the
 * user reads; this file is what survives.
 *
 * A run that ends normally clears it. Anything left over therefore belongs to a
 * run that died, and it is the only copy of that run's log.
 */
internal object NativeLogRecovery {
    /** Matches AndroidGhostlockRepository.NativeLogFileName. */
    const val FileName = ".ghostlock_native.log"

    private const val PrefExportLocation = "debug_export_location"
    private const val DefaultLocation = "Download/ghostlock-debug-log"
    private const val PrefsName = "ghostlock_prefs"

    fun file(context: Context): File = File(context.filesDir, FileName)

    /**
     * Copies a leftover log into the visible archive, then clears it so the next
     * start does not republish the same crash. Returns true when it recovered
     * something. Cheap enough to call on every app start: an empty or missing
     * file returns immediately.
     */
    fun recover(context: Context): Boolean {
        val source = file(context)
        if (!source.isFile || source.length() == 0L) return false
        val bytes = runCatching { source.readBytes() }.getOrNull() ?: return false
        if (bytes.isEmpty()) return false

        val location = runCatching {
            context.getSharedPreferences(PrefsName, Context.MODE_PRIVATE)
                .getString(PrefExportLocation, null)
        }.getOrNull().orEmpty().trim().trim('/').ifEmpty { DefaultLocation }

        val stamp = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date())
        val values = ContentValues().apply {
            put(MediaStore.MediaColumns.DISPLAY_NAME, "ghostlock-native-crash.log")
            put(MediaStore.MediaColumns.MIME_TYPE, "text/plain")
            put(MediaStore.MediaColumns.RELATIVE_PATH, "$location/$stamp-recovered")
        }
        val resolver = context.contentResolver
        val written = runCatching {
            val uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                ?: error("cannot create the recovery entry")
            val output = resolver.openOutputStream(uri, "w")
                ?: error("cannot open the recovery entry")
            output.use { it.write(bytes) }
            true
        }.getOrDefault(false)
        if (written) clear(context)
        return written
    }

    /** Called at the end of a normal run: nothing is left to recover. */
    fun clear(context: Context) {
        runCatching { file(context).writeText("") }
    }
}
