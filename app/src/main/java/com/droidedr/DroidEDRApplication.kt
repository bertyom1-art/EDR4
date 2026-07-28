package com.droidedr

import android.app.Application
import android.content.Intent
import android.os.Build
import androidx.work.*
import com.droidedr.detection.EDRCoreService
import com.droidedr.engine.ObserveModeWorker
import com.droidedr.healing.WatchdogWorker
import java.util.concurrent.TimeUnit

class DroidEDRApplication : Application() {

    override fun onCreate() {
        super.onCreate()

        // Initialize WorkManager with custom config
        val config = Configuration.Builder()
            .setMinimumLoggingLevel(android.util.Log.INFO)
            .build()

        WorkManager.initialize(this, config)

        // Start EDR Core Service immediately (existing v2.6 enforcing engine)
        val serviceIntent = Intent(this, EDRCoreService::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(serviceIntent)
        } else {
            startService(serviceIntent)
        }

        // Schedule persistent watchdog
        scheduleWatchdog()

        // Schedule v2.9 observe-mode engine (log-only, runs alongside — never enforces)
        scheduleObserveEngine()
    }

    private fun scheduleWatchdog() {
        val request = PeriodicWorkRequestBuilder<WatchdogWorker>(15, TimeUnit.MINUTES)
            .setConstraints(Constraints.Builder().build())
            .setBackoffCriteria(BackoffPolicy.LINEAR, 1, TimeUnit.MINUTES)
            .build()

        WorkManager.getInstance(this).enqueueUniquePeriodicWork(
            "edr_watchdog_app",
            ExistingPeriodicWorkPolicy.KEEP,
            request
        )
    }

    private fun scheduleObserveEngine() {
        val request = PeriodicWorkRequestBuilder<ObserveModeWorker>(15, TimeUnit.MINUTES)
            .setConstraints(Constraints.Builder().build())
            .build()

        WorkManager.getInstance(this).enqueueUniquePeriodicWork(
            ObserveModeWorker.WORK_NAME,
            ExistingPeriodicWorkPolicy.KEEP,
            request
        )
    }
}
