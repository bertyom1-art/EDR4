package com.droidedr.detection

import android.app.*
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import com.droidedr.baseline.BaselineEngine
import com.droidedr.baseline.BaselineSnapshot
import com.droidedr.healing.SelfHealingEngine
import com.droidedr.network.DnsVpnService
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow

// ============================================================
// ALERT BUS — singleton event stream for threat alerts
// ============================================================
object AlertBus {
    private val _flow = MutableSharedFlow<ThreatAlert>(extraBufferCapacity = 100)
    val flow = _flow.asSharedFlow()

    fun emit(alert: ThreatAlert) {
        _flow.tryEmit(alert)
    }
}

// ============================================================
// EDR CORE SERVICE
// Orchestrates: baseline, detection, healing, alerting
// ============================================================
class EDRCoreService : Service() {

    private val scope = CoroutineScope(Dispatchers.Default + SupervisorJob())
    private lateinit var baselineEngine: BaselineEngine
    private lateinit var healingEngine: SelfHealingEngine
    private lateinit var detectionEngine: DetectionEngine

    companion object {
        const val NOTIFICATION_ID = 1001
        const val CHANNEL_ID = "droidedr_core"
        const val DETECTION_INTERVAL_MS = 30_000L   // 30 sec scan cycle
        const val BASELINE_INTERVAL_MS  = 5 * 60 * 1000L  // 5 min snapshot

        var instance: EDRCoreService? = null
        val alertHistory = mutableListOf<ThreatAlert>()
    }

    override fun onCreate() {
        super.onCreate()
        instance = this

        baselineEngine = BaselineEngine(this)
        healingEngine = SelfHealingEngine(this)
        detectionEngine = DetectionEngine(this, baselineEngine)

        createNotificationChannel()
        startForeground(NOTIFICATION_ID, buildNotification("EDR Active — Monitoring"))

        startBaselineCapture()
        startDetectionLoop()
        startAlertConsumer()
        healingEngine.startWatchdog()

        // Start DNS VPN
        startDnsVpn()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int = START_STICKY

    override fun onBind(intent: Intent?) = null

    // ─── BASELINE ─────────────────────────────────────────────────────────────
    private fun startBaselineCapture() {
        scope.launch {
            while (isActive) {
                val snapshot = baselineEngine.captureSnapshot()
                updateNotification(buildStatusText())
                delay(BASELINE_INTERVAL_MS)
            }
        }
    }

    // ─── DETECTION LOOP ───────────────────────────────────────────────────────
    private fun startDetectionLoop() {
        scope.launch {
            while (isActive) {
                try {
                    detectionEngine.runFullScan()
                } catch (e: Exception) {
                    // log error
                }
                delay(DETECTION_INTERVAL_MS)
            }
        }
    }

    // ─── ALERT CONSUMER ───────────────────────────────────────────────────────
    private fun startAlertConsumer() {
        scope.launch {
            AlertBus.flow.collect { alert ->
                alertHistory.add(alert)
                if (alertHistory.size > 500) alertHistory.removeAt(0)

                // Auto-respond if enabled
                if (alert.technique.autoRespond) {
                    val actions = healingEngine.respondToThreat(alert)
                    val responded = alert.copy(
                        responded = true,
                        responseActions = actions.map { it.name }
                    )
                    alertHistory[alertHistory.lastIndex] = responded
                }

                // Update notification
                updateNotification("⚠ ${alert.technique.severity}: ${alert.technique.name}")
            }
        }
    }

    // ─── DNS VPN ──────────────────────────────────────────────────────────────
    private fun startDnsVpn() {
        val vpnIntent = android.net.VpnService.prepare(this)
        if (vpnIntent == null) {
            // Permission already granted
            val intent = Intent(this, DnsVpnService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                startForegroundService(intent)
            } else {
                startService(intent)
            }
        }
        // If not granted, UI will prompt user
    }

    // ─── NOTIFICATION ─────────────────────────────────────────────────────────
    private fun buildStatusText(): String {
        val baseline = baselineEngine.getBaseline()
        return if (baseline.established) {
            "EDR Active — Baseline ${baseline.coveragePercent}% · ${alertHistory.size} alerts"
        } else {
            "EDR Active — Building baseline (${baseline.coveragePercent}%)"
        }
    }

    private fun buildNotification(text: String): Notification {
        val intent = Intent(this, com.droidedr.ui.MainActivity::class.java)
        val pi = PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_IMMUTABLE)

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("DroidEDR v2")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentIntent(pi)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    private fun updateNotification(text: String) {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        nm.notify(NOTIFICATION_ID, buildNotification(text))
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID, "EDR Core Service",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "DroidEDR monitoring service"
                setShowBadge(false)
            }
            (getSystemService(NOTIFICATION_SERVICE) as NotificationManager)
                .createNotificationChannel(channel)
        }
    }

    override fun onDestroy() {
        scope.cancel()
        instance = null
        super.onDestroy()

        // Self-heal: reschedule restart via WorkManager
        val request = androidx.work.OneTimeWorkRequest.Builder(com.droidedr.healing.WatchdogWorker::class.java)
            .setInitialDelay(5, java.util.concurrent.TimeUnit.SECONDS)
            .build()
        androidx.work.WorkManager.getInstance(this).enqueue(request as androidx.work.WorkRequest)
    }
}

// ============================================================
// DETECTION ENGINE — runs all MITRE rules against device state
// ============================================================
class DetectionEngine(
    private val context: Context,
    private val baseline: BaselineEngine
) {
    private val am = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager

    suspend fun runFullScan() = withContext(Dispatchers.IO) {
        checkLotLActivity()
        checkRemoteAccess()
        checkPrivilegeEscalation()
        checkPersistence()
        checkBruteForce()
        checkNetworkAnomalies()
        checkCVEPatterns()
    }

    private fun checkLotLActivity() {
        val processes = getRunningProcesses()

        // Detect shell spawned from non-shell app
        val shellProcs = processes.filter { it.contains(":shell") || it == "sh" || it == "bash" }
        shellProcs.forEach { proc ->
            AlertBus.emit(ThreatAlert(
                technique = MitreRulesEngine.T1623,
                evidence = mapOf("process" to proc, "source" to "process_scan"),
                deviceState = "RUNNING",
                baselineDeviation = 0.8
            ))
        }

        // Detect su / magisk
        val rootProcs = processes.filter { p ->
            SelfHealingEngine.LOTL_BINARIES.any { p.contains(it) }
        }
        rootProcs.forEach { proc ->
            AlertBus.emit(ThreatAlert(
                technique = MitreRulesEngine.T1626,
                evidence = mapOf("process" to proc),
                deviceState = "ELEVATED"
            ))
        }
    }

    private fun checkRemoteAccess() {
        val pm = context.packageManager
        val installedPackages = pm.getInstalledApplications(0).map { it.packageName }

        val ratPackages = installedPackages.filter { pkg ->
            SelfHealingEngine.KNOWN_RAT_PACKAGES.contains(pkg)
        }

        ratPackages.forEach { pkg ->
            AlertBus.emit(ThreatAlert(
                technique = MitreRulesEngine.T1219,
                evidence = mapOf("packageName" to pkg, "source" to "package_scan"),
                deviceState = "COMPROMISED"
            ))
        }

        // Check ADB TCP
        if (isAdbTcpListening()) {
            AlertBus.emit(ThreatAlert(
                technique = MitreRulesEngine.ADB_REMOTE,
                evidence = mapOf("port" to "5555", "status" to "OPEN"),
                deviceState = "EXPOSED"
            ))
        }
    }

    private fun checkPrivilegeEscalation() {
        if (isSuBinaryPresent()) {
            AlertBus.emit(ThreatAlert(
                technique = MitreRulesEngine.T1626,
                evidence = mapOf("binary" to "su", "location" to "/system/bin/su"),
                deviceState = "ROOTED"
            ))
        }
    }

    private fun checkPersistence() {
        val processes = getRunningProcesses()
        val suspiciousForeground = processes.filter { proc ->
            !proc.startsWith("com.android") &&
            !proc.startsWith("com.google") &&
            !proc.startsWith("com.droidedr") &&
            proc.contains(":") &&
            proc.contains("service")
        }

        if (suspiciousForeground.isNotEmpty()) {
            AlertBus.emit(ThreatAlert(
                technique = MitreRulesEngine.T1541,
                evidence = mapOf("services" to suspiciousForeground.take(5).joinToString()),
                deviceState = "MONITORING"
            ))
        }
    }

    private fun checkBruteForce() {
        // In production: monitor KeyguardManager failed attempts, system logs
        // placeholder — integrate with AccessibilityService for real impl
    }

    private fun checkNetworkAnomalies() {
        val dnsStats = DnsVpnService.instance?.getStats() ?: return
        val b = baseline.getBaseline()

        if (!b.established) return

        val deviations = baseline.getDnsDeviation(
            dnsStats.totalQueries,
            dnsStats.nxdomainCount,
            dnsStats.avgEntropy
        )

        deviations.forEach { dev ->
            val technique = when {
                dev.category == "DNS_NXDOMAIN_STORM" -> MitreRulesEngine.T1637
                dev.category == "DNS_ENTROPY_HIGH" -> MitreRulesEngine.T1437_001
                else -> return@forEach
            }
            AlertBus.emit(ThreatAlert(
                technique = technique,
                evidence = mapOf("detail" to dev.detail, "sigma" to dev.sigmaValue.toString()),
                deviceState = "MONITORING",
                baselineDeviation = dev.score
            ))
        }
    }

    private fun checkCVEPatterns() {
        // CVE-2024-3661: Check for DHCP option 121 route injection via network info
        // CVE-2024-0044: Monitor PackageInstaller API calls
        // CVE-2023-4863: Monitor WebView/Chrome crash patterns
        // These are populated via AccessibilityService and system log monitoring
    }

    private fun getRunningProcesses(): List<String> {
        return try {
            am.runningAppProcesses?.map { it.processName } ?: emptyList()
        } catch (e: Exception) { emptyList() }
    }

    private fun isAdbTcpListening(): Boolean {
        return try {
            java.io.File("/proc/net/tcp").readLines()
                .any { it.contains("15B3") }  // 5555 in little-endian hex
        } catch (e: Exception) { false }
    }

    private fun isSuBinaryPresent(): Boolean {
        val suPaths = listOf("/system/bin/su", "/system/xbin/su", "/sbin/su", "/data/local/su")
        return suPaths.any { java.io.File(it).exists() }
    }
}

// ─── ACCESSIBILITY SERVICE ────────────────────────────────────────────────────
class EDRAccessibilityService : android.accessibilityservice.AccessibilityService() {
    override fun onAccessibilityEvent(event: android.view.accessibility.AccessibilityEvent?) {
        event ?: return
        // Monitor for overlay attacks, IME abuse, suspicious UI interactions
        val pkgName = event.packageName?.toString() ?: return
        if (event.eventType == android.view.accessibility.AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED) {
            // Check for overlay over banking/sensitive apps
        }
    }

    override fun onInterrupt() {}
}
