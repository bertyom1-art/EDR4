package com.droidedr

import android.app.Application
import android.content.Intent
import android.os.Build
import androidx.work.*
import com.droidedr.detection.EDRCoreService
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

        // Start EDR Core Service immediately
        val serviceIntent = Intent(this, EDRCoreService::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(serviceIntent)
        } else {
            startService(serviceIntent)
        }

        // Schedule persistent watchdog
        scheduleWatchdog()
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
}
