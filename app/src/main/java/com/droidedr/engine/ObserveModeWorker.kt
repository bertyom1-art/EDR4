package com.droidedr.engine

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters

/**
 * Drives observe-mode evaluation on a schedule via WorkManager (already a project
 * dependency). Production posture is a foreground service for continuous sampling;
 * this worker is the low-friction runner to start collecting telemetry today.
 *
 * The one thing you must wire: [collectSignals]. Point it at your existing v2.6
 * sensors/collectors so the engine reads real device state. Until then it runs
 * against an empty snapshot (no matches) — safe, just not useful.
 */
class ObserveModeWorker(
    appContext: Context,
    params: WorkerParameters
) : CoroutineWorker(appContext, params) {

    override suspend fun doWork(): Result {
        val dao = ObserveDatabase.get(applicationContext).detectionDao()
        val engine = RuleEngine(applicationContext, dao)
        engine.loadCatalog()

        val signals = collectSignals()
        engine.runCycle(signals)

        // Housekeeping: keep the observe window bounded (default 30 days).
        val cutoff = System.currentTimeMillis() - RETENTION_MS
        dao.pruneOlderThan(cutoff)
        return Result.success()
    }

    /**
     * TODO(port): replace with reads from the existing DroidEDR v2.6 collectors
     * (package manager scan, netlink/DNS taps, DHCP watcher, auth-failure counter).
     * Returning an empty-but-timestamped snapshot keeps the engine safe by default.
     */
    private fun collectSignals(): Signals =
        Signals(timestamp = System.currentTimeMillis())

    companion object {
        const val WORK_NAME = "droidedr-observe-cycle"
        private const val RETENTION_MS = 30L * 24 * 60 * 60 * 1000
    }
}
