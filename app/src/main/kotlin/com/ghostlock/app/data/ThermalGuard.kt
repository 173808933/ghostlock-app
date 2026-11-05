package com.ghostlock.app.data

import java.io.File

/**
 * Reads the SoC thermal zones so every run records the temperature it started at.
 *
 * The PI race depends on a fixed 20 ms window (`arm_hold`): the consumer thread
 * has to complete `sched_setattr` inside it for the priority chain to form. When
 * the CPU is thermally throttled that call arrives late, the chain never forms,
 * the punch lands away from the page it was aimed at, and a W1b/W2 miss is a
 * panic rather than a clean failure.
 *
 * That makes temperature a first-order input to the hit rate, but the log never
 * carried it - a field report of "some runs fail and some do not" could not be
 * told apart from a profile problem. Recording it costs one read per run.
 *
 * Everything here is best-effort: sysfs thermal nodes are not guaranteed to be
 * readable from the app domain, and a missing reading must never block a run.
 */
internal object ThermalGuard {
    /** At or above this the run is flagged, not blocked. */
    const val HOT_MILLI_C = 45_000

    private const val ZoneRoot = "/sys/class/thermal"

    /** Celsius per zone, keyed by the zone type ("cpuss-0", "cpu-2-0-1", ...). */
    fun readZones(): Map<String, Int> {
        val zones = runCatching {
            File(ZoneRoot).listFiles { file -> file.name.startsWith("thermal_zone") }
        }.getOrNull() ?: return emptyMap()
        val out = LinkedHashMap<String, Int>()
        for (zone in zones.sortedBy { it.name }) {
            val type = runCatching { File(zone, "type").readText().trim() }
                .getOrNull()?.takeIf { it.isNotEmpty() } ?: continue
            val raw = runCatching { File(zone, "temp").readText().trim().toLong() }
                .getOrNull() ?: continue
            /* sysfs reports milli-Celsius on this platform; a few older ones
             * report tenths. Anything under a hundred is clearly tenths. */
            val milli = if (raw in 1..9_999) raw * 100 else raw
            if (milli <= 0) continue
            out[type] = milli.toInt()
        }
        return out
    }

    /** Hottest CPU/SoC zone in milli-Celsius, or null when nothing is readable. */
    fun hottest(): Pair<String, Int>? =
        readZones()
            .filterKeys { key ->
                val k = key.lowercase()
                k.contains("cpu") || k.contains("soc") || k.contains("gpu") || k.contains("cpuss")
            }
            .maxByOrNull { it.value }
            ?.toPair()

    /** One log line: the three hottest zones plus a verdict. */
    fun describe(): String {
        val zones = readZones()
        if (zones.isEmpty()) return "thermal: unavailable (sysfs not readable)"
        val ranked = zones.entries.sortedByDescending { it.value }.take(3)
        val text = ranked.joinToString(" ") { "${it.key}=${it.value / 1000.0}C" }
        val peak = ranked.first().value
        val verdict = if (peak >= HOT_MILLI_C) {
            "HOT - the 20ms race window is tight at this clock, expect a lower hit rate"
        } else {
            "ok"
        }
        return "thermal: $text ($verdict)"
    }
}
