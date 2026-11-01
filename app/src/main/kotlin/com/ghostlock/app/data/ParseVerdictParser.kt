package com.ghostlock.app.data

import com.ghostlock.app.domain.model.ParseVerdict
import org.json.JSONObject

/**
 * Reads the `--analysis-json` document the extractor writes next to the
 * profile. Kept deliberately lenient: a missing or older document must never
 * break the import, it only hides the verdict card.
 */
object ParseVerdictParser {

    fun parse(text: String?): ParseVerdict? {
        if (text.isNullOrBlank()) return null
        val root = runCatching { JSONObject(text) }.getOrNull() ?: return null
        val verdict = root.optJSONObject("verdict") ?: return null
        val level = verdict.optString("level").takeIf { it.isNotEmpty() } ?: return null
        val reasons = verdict.optJSONArray("reasons")?.let { array ->
            buildList { for (i in 0 until array.length()) array.optString(i).takeIf { it.isNotEmpty() }?.let(::add) }
        }.orEmpty()
        val sigret = root.optJSONArray("routes")?.let { routes ->
            (0 until routes.length())
                .mapNotNull { routes.optJSONObject(it) }
                .firstOrNull { it.optString("route") == "sigret" && it.optBoolean("derived") }
        }
        return ParseVerdict(
            level = level,
            route = root.optString("punch").takeIf { it == "sigret" }?.let { "sigret" }
                ?: root.optJSONObject("suggestion")?.optString("route")?.takeIf { it.isNotEmpty() },
            punch = root.optString("punch").takeIf { it.isNotEmpty() },
            release = root.optString("release").takeIf { it.isNotEmpty() },
            waiterOff = sigret?.takeIf { it.optBoolean("feasible") }?.optLong("waiter_off"),
            depth = sigret?.optLong("depth"),
            d = sigret?.optLong("d"),
            buffer = sigret?.optLong("buffer"),
            reasons = reasons,
        )
    }
}
