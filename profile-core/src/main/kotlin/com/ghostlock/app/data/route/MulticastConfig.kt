package com.ghostlock.app.data.route

/**
 * Multicast waiter route: geometry plus the lottery knobs.
 *
 * Every setsockopt/sigret punch is one draw — the destination copy races skb
 * page recycling, so a single shot misses often. [attempts] is the number of
 * draws, [armSequence] how many draws share one arming round, [armHold] how
 * many scheduling yields separate two rounds. All three are optional: a
 * profile written before they existed keeps the historical single shot.
 */
data class MulticastConfig(
    val geometry: MulticastGeometry,
    val attempts: UInt? = null,
    val armSequence: UInt? = null,
    val armHold: UInt? = null,
) : RouteConfig {
    override fun entries(): List<Pair<String, ULong>> = buildList {
        geometry.waiterOff?.let { add("waiter_off" to it.toLong().toULong()) }
        geometry.bufferSize?.let { add("buffer_size" to it.toULong()) }
        geometry.taskOffset?.let { add("task_offset" to it.toULong()) }
        geometry.lockOffset?.let { add("lock_offset" to it.toULong()) }
        attempts?.let { add("attempts" to it.toULong()) }
        armSequence?.let { add("arm_sequence" to it.toULong()) }
        armHold?.let { add("arm_hold" to it.toULong()) }
    }

    override fun apply(key: String, value: ULong): RouteConfig = when (key) {
        "waiter_off" -> copy(geometry = geometry.copy(waiterOff = value.toLong().toInt()))
        "buffer_size" -> copy(geometry = geometry.copy(bufferSize = value.toUInt()))
        "task_offset" -> copy(geometry = geometry.copy(taskOffset = value.toUInt()))
        "lock_offset" -> copy(geometry = geometry.copy(lockOffset = value.toUInt()))
        "attempts" -> copy(attempts = value.toUInt())
        "arm_sequence" -> copy(armSequence = value.toUInt())
        "arm_hold" -> copy(armHold = value.toUInt())
        else -> this
    }

    companion object {
        val EMPTY = MulticastConfig(
            geometry = MulticastGeometry(null, null, null, null),
        )

        fun from(value: (String) -> Long?): MulticastConfig = MulticastConfig(
            geometry = MulticastGeometry(
                waiterOff = value("mcast.waiter_off")?.toInt(),
                bufferSize = value("mcast.buffer_size")?.toUInt(),
                taskOffset = value("mcast.task_offset")?.toUInt(),
                lockOffset = value("mcast.lock_offset")?.toUInt(),
            ),
            attempts = value("mcast.attempts")?.toUInt(),
            armSequence = value("mcast.arm_sequence")?.toUInt(),
            armHold = value("mcast.arm_hold")?.toUInt(),
        )
    }
}

/** Mirrors native `RouteGeometry`'s multicast members (all `std::optional`). */
data class MulticastGeometry(
    val waiterOff: Int?,
    val bufferSize: UInt?,
    val taskOffset: UInt?,
    val lockOffset: UInt?,
)
