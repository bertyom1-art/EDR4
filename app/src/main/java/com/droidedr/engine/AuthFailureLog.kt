package com.droidedr.engine

import android.content.Context

/**
 * A tiny rolling record of failed device-unlock attempts, shared between the
 * device-admin receiver (which writes) and SignalCollector (which reads). Backed
 * by SharedPreferences so it survives process death; stored as a CSV of epoch-ms
 * timestamps and pruned to [WINDOW_MS] on every read and write.
 *
 * Observe-only: this just counts. Nothing here locks, wipes, or resets the
 * device — the auth_bruteforce rule decides whether the count is interesting.
 */
object AuthFailureLog {
    private const val PREFS = "droidedr_auth"
    private const val KEY = "fail_ts"
    const val WINDOW_MS = 15L * 60 * 1000  // 15-minute rolling window

    /** Record one failed unlock attempt. */
    fun record(context: Context) {
        val now = System.currentTimeMillis()
        val kept = load(context, now) + now
        save(context, kept)
    }

    /** A successful unlock clears the window — the brute-force streak is broken. */
    fun clear(context: Context) {
        prefs(context).edit().remove(KEY).apply()
    }

    /** Failed attempts within the rolling window (prunes as a side effect). */
    fun countInWindow(context: Context): Int {
        val now = System.currentTimeMillis()
        val kept = load(context, now)
        save(context, kept)   // persist the pruned set
        return kept.size
    }

    private fun load(context: Context, now: Long): List<Long> =
        prefs(context).getString(KEY, "")
            .orEmpty()
            .split(",")
            .mapNotNull { it.trim().toLongOrNull() }
            .filter { now - it <= WINDOW_MS }

    private fun save(context: Context, stamps: List<Long>) {
        prefs(context).edit()
            .putString(KEY, stamps.joinToString(","))
            .apply()
    }

    private fun prefs(context: Context) =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
}
