package com.droidedr.healing

import android.app.ActivityManager
import android.app.admin.DeviceAdminReceiver
import android.app.admin.DevicePolicyManager
import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.wifi.WifiManager
import android.os.Build
import androidx.work.*
import com.droidedr.detection.MitreTechnique
import com.droidedr.detection.ThreatAlert
import com.droidedr.detection.ThreatCategory
import com.droidedr.detection.ThreatSeverity
import kotlinx.coroutines.*
import java.util.concurrent.TimeUnit

// ============================================================
// SELF-HEALING ENGINE
// - Watchdog that detects if EDR is killed and restarts it
// - Auto-response actions per MITRE technique
// - Boot persistence
// - Network isolation for critical threats
// - DNS restoration
// ============================================================

enum class ResponseAction {
    BLOCK_NETWORK,
    RESTORE_DNS,
    KILL_PROCESS,
    REVOKE_PERMISSIONS,
    QUARANTINE_APP,
    RESTART_EDR,
    ESCALATE_ALERT,
    LOCK_DEVICE,
    WIPE_SENSITIVE,
    ENABLE_STRICT_MODE,
    DISABLE_ADB,
    RESTORE_FIREWALL,
    CAPTURE_FORENSICS,
    NOTIFY_USER,
    DISABLE_WIFI,
    ENABLE_VPN
}

data class HealingAction(
    val timestamp: Long = System.currentTimeMillis(),
    val trigger: String,
    val actions: List<ResponseAction>,
    val success: Boolean,
    val details: String
)

data class HealingState(
    val isHealthy: Boolean = true,
    val edrServiceAlive: Boolean = true,
    val dnsVpnActive: Boolean = false,
    val networkIsolated: Boolean = false,
    val strictModeEnabled: Boolean = false,
    val lastHealTimestamp: Long = 0L,
    val healingHistory: List<HealingAction> = emptyList()
)

class SelfHealingEngine(private val context: Context) {

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var healingState = HealingState()
    private val healingHistory = mutableListOf<HealingAction>()

    companion object {
        const val WATCHDOG_INTERVAL_MS = 30_000L   // 30 seconds
        const val DNS_PRIMARY = "1.1.1.1"
        const val DNS_SECONDARY = "8.8.8.8"
        const val DNS_DOH_URL = "https://cloudflare-dns.com/dns-query"
        val TRUSTED_DNS = setOf("1.1.1.1", "8.8.8.8", "9.9.9.9", "208.67.222.222")

        // Known RAT/remote access packages
        val KNOWN_RAT_PACKAGES = setOf(
            "com.teamviewer.host", "com.anydesk.anydeskandroid",
            "com.logmein.ignitionandroid", "com.splashtop.remote.pad.consumer",
            "com.citrix.receiver", "com.rdp.rdpclient",
            "net.christianbeier.droidvnc_ng", "org.vnc.viewer",
            "com.rvncviewer", "com.google.android.apps.remotedesktopclient"
        )

        // LotL / dangerous shell tools
        val LOTL_BINARIES = setOf("su", "busybox", "nc", "netcat", "nmap", "tcpdump",
            "strace", "ltrace", "frida-server", "magisk")
    }

    // ─── WATCHDOG ─────────────────────────────────────────────────────────────
    fun startWatchdog() {
        scope.launch {
            while (isActive) {
                delay(WATCHDOG_INTERVAL_MS)
                performHealthCheck()
            }
        }

        // Schedule WorkManager watchdog as backup
        val watchdogRequest = PeriodicWorkRequestBuilder<WatchdogWorker>(
            15, TimeUnit.MINUTES
        ).setConstraints(
            Constraints.Builder()
                .setRequiresBatteryNotLow(false)
                .build()
        ).build()

        WorkManager.getInstance(context).enqueueUniquePeriodicWork(
            "edr_watchdog",
            ExistingPeriodicWorkPolicy.KEEP,
            watchdogRequest
        )
    }

    private suspend fun performHealthCheck() {
        val serviceAlive = isEDRServiceAlive()

        if (!serviceAlive) {
            heal(
                trigger = "EDR_SERVICE_KILLED",
                actions = listOf(ResponseAction.RESTART_EDR, ResponseAction.NOTIFY_USER),
                details = "EDR core service was killed — restarting"
            )
            restartEDRService()
        }

        // Check DNS hasn't been hijacked
        val currentDns = getCurrentDnsServer()
        if (currentDns != null && currentDns !in TRUSTED_DNS) {
            heal(
                trigger = "DNS_HIJACK_DETECTED",
                actions = listOf(ResponseAction.RESTORE_DNS, ResponseAction.NOTIFY_USER),
                details = "DNS server changed to $currentDns — restoring to trusted resolver"
            )
        }

        // Check for unauthorized ADB TCP
        if (isAdbTcpOpen()) {
            heal(
                trigger = "ADB_TCP_OPEN",
                actions = listOf(ResponseAction.DISABLE_ADB, ResponseAction.NOTIFY_USER),
                details = "ADB TCP (port 5555) detected open — disabling"
            )
        }
    }

    // ─── AUTO-RESPONSE ────────────────────────────────────────────────────────
    suspend fun respondToThreat(alert: ThreatAlert): List<ResponseAction> {
        val actionsToTake = mutableListOf<ResponseAction>()

        // Map MITRE technique to response actions
        when (alert.technique.category) {
            ThreatCategory.REMOTE_ACCESS -> {
                actionsToTake.addAll(listOf(
                    ResponseAction.KILL_PROCESS,
                    ResponseAction.BLOCK_NETWORK,
                    ResponseAction.REVOKE_PERMISSIONS,
                    ResponseAction.NOTIFY_USER,
                    ResponseAction.CAPTURE_FORENSICS
                ))
                if (alert.technique.severity == ThreatSeverity.CRITICAL) {
                    actionsToTake.add(ResponseAction.ENABLE_STRICT_MODE)
                }
            }
            ThreatCategory.DNS_ATTACK -> {
                actionsToTake.addAll(listOf(
                    ResponseAction.RESTORE_DNS,
                    ResponseAction.ENABLE_VPN,
                    ResponseAction.NOTIFY_USER
                ))
                if (alert.technique.id == "T1437.001") {  // DNS Tunneling
                    actionsToTake.add(ResponseAction.CAPTURE_FORENSICS)
                }
            }
            ThreatCategory.DHCP_ATTACK -> {
                actionsToTake.addAll(listOf(
                    ResponseAction.RESTORE_DNS,
                    ResponseAction.NOTIFY_USER,
                    ResponseAction.ESCALATE_ALERT
                ))
            }
            ThreatCategory.BRUTE_FORCE -> {
                actionsToTake.addAll(listOf(
                    ResponseAction.NOTIFY_USER,
                    ResponseAction.ESCALATE_ALERT
                ))
                if (alert.technique.id == "T1110.001") {
                    actionsToTake.add(ResponseAction.LOCK_DEVICE)
                }
            }
            ThreatCategory.EXPLOIT_CVE -> {
                actionsToTake.addAll(listOf(
                    ResponseAction.ENABLE_STRICT_MODE,
                    ResponseAction.CAPTURE_FORENSICS,
                    ResponseAction.NOTIFY_USER,
                    ResponseAction.ESCALATE_ALERT
                ))
                if (alert.technique.severity == ThreatSeverity.CRITICAL) {
                    actionsToTake.add(ResponseAction.BLOCK_NETWORK)
                }
            }
            ThreatCategory.LOTL -> {
                actionsToTake.addAll(listOf(
                    ResponseAction.KILL_PROCESS,
                    ResponseAction.NOTIFY_USER,
                    ResponseAction.CAPTURE_FORENSICS
                ))
            }
            ThreatCategory.CREDENTIAL_ACCESS -> {
                actionsToTake.addAll(listOf(
                    ResponseAction.REVOKE_PERMISSIONS,
                    ResponseAction.NOTIFY_USER,
                    ResponseAction.WIPE_SENSITIVE
                ))
            }
            ThreatCategory.EXFILTRATION -> {
                actionsToTake.addAll(listOf(
                    ResponseAction.BLOCK_NETWORK,
                    ResponseAction.CAPTURE_FORENSICS,
                    ResponseAction.NOTIFY_USER,
                    ResponseAction.ESCALATE_ALERT
                ))
            }
            ThreatCategory.DEFENSE_EVASION -> {
                actionsToTake.addAll(listOf(
                    ResponseAction.RESTART_EDR,
                    ResponseAction.ENABLE_STRICT_MODE,
                    ResponseAction.NOTIFY_USER
                ))
            }
            else -> {
                actionsToTake.addAll(listOf(
                    ResponseAction.NOTIFY_USER,
                    ResponseAction.CAPTURE_FORENSICS
                ))
            }
        }

        // Execute actions
        executeActions(actionsToTake, alert)
        heal(
            trigger = alert.technique.id,
            actions = actionsToTake,
            details = "Auto-responded to ${alert.technique.name}"
        )

        return actionsToTake
    }

    private suspend fun executeActions(actions: List<ResponseAction>, alert: ThreatAlert) {
        for (action in actions) {
            when (action) {
                ResponseAction.RESTORE_DNS -> restoreDns()
                ResponseAction.RESTART_EDR -> restartEDRService()
                ResponseAction.DISABLE_ADB -> disableAdbTcp()
                ResponseAction.ENABLE_STRICT_MODE -> enableStrictMode()
                ResponseAction.CAPTURE_FORENSICS -> captureForensics(alert)
                ResponseAction.NOTIFY_USER -> sendThreatNotification(alert)
                ResponseAction.BLOCK_NETWORK -> blockNetworkForThreat(alert)
                ResponseAction.REVOKE_PERMISSIONS -> revokePermissionsForThreat(alert)
                ResponseAction.KILL_PROCESS -> killThreatProcess(alert)
                else -> { /* log action */ }
            }
            delay(100) // stagger actions
        }
    }

    // ─── HEALING ACTIONS ──────────────────────────────────────────────────────
    private fun restoreDns() {
        // In production: write to VPN interface or system DNS
        // For non-rooted: enforce via local VPN tunnel to trusted DoH
        // This is handled by DnsVpnService in the full implementation
    }

    private fun restartEDRService() {
        val intent = Intent(context, com.droidedr.detection.EDRCoreService::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            context.startForegroundService(intent)
        } else {
            context.startService(intent)
        }
    }

    private fun disableAdbTcp() {
        // Execute via root shell if available: adb disconnect && setprop service.adb.tcp.port -1
        // For non-rooted: alert user, revoke developer permissions
    }

    private fun enableStrictMode() {
        healingState = healingState.copy(strictModeEnabled = true, networkIsolated = true)
    }

    private fun captureForensics(alert: ThreatAlert) {
        val logDir = context.getExternalFilesDir(null)
        val logFile = java.io.File(logDir, "forensics_${alert.id}_${alert.timestamp}.json")
        logFile.writeText("""
            {
              "alertId": "${alert.id}",
              "timestamp": ${alert.timestamp},
              "technique": "${alert.technique.id}",
              "techniqueName": "${alert.technique.name}",
              "severity": "${alert.technique.severity}",
              "evidence": ${com.google.gson.Gson().toJson(alert.evidence)},
              "deviceState": "${alert.deviceState}",
              "baselineDeviation": ${alert.baselineDeviation}
            }
        """.trimIndent())
    }

    private fun sendThreatNotification(alert: ThreatAlert) {
        // NotificationManager call — implemented in NotificationHelper
    }

    private fun blockNetworkForThreat(alert: ThreatAlert) {
        healingState = healingState.copy(networkIsolated = true)
        // In production: use VPN to drop all traffic except to trusted EDR endpoint
    }

    private fun revokePermissionsForThreat(alert: ThreatAlert) {
        val packageName = alert.evidence["packageName"] ?: return
        try {
            val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
            val admin = ComponentName(context, EDRDeviceAdminReceiver::class.java)
            if (dpm.isAdminActive(admin)) {
                dpm.clearPackagePersistentPreferredActivities(admin, packageName)
            }
        } catch (e: Exception) { /* log */ }
    }

    private fun killThreatProcess(alert: ThreatAlert) {
        val am = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
        val packageName = alert.evidence["packageName"] ?: return
        try {
            am.killBackgroundProcesses(packageName)
        } catch (e: Exception) { /* log */ }
    }

    // ─── DIAGNOSTICS ──────────────────────────────────────────────────────────
    private fun isEDRServiceAlive(): Boolean {
        val am = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
        return am.getRunningServices(Int.MAX_VALUE)?.any {
            it.service.className == "com.droidedr.detection.EDRCoreService"
        } ?: false
    }

    private fun getCurrentDnsServer(): String? {
        // In production: read /proc/net/udp or system DNS settings
        return null
    }

    private fun isAdbTcpOpen(): Boolean {
        // Check if port 5555 is listening via /proc/net/tcp
        return try {
            val file = java.io.File("/proc/net/tcp")
            if (file.canRead()) {
                file.readLines().any { line ->
                    line.contains("15B3") // 5555 in hex
                }
            } else false
        } catch (e: Exception) { false }
    }

    private fun heal(trigger: String, actions: List<ResponseAction>, details: String) {
        val action = HealingAction(
            trigger = trigger,
            actions = actions,
            success = true,
            details = details
        )
        healingHistory.add(action)
        healingState = healingState.copy(
            lastHealTimestamp = System.currentTimeMillis(),
            healingHistory = healingHistory.toList()
        )
    }

    fun getHealingState(): HealingState = healingState
    fun getHealingHistory(): List<HealingAction> = healingHistory.toList()
}

// ─── BOOT RECEIVER ────────────────────────────────────────────────────────────
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action in listOf(
                Intent.ACTION_BOOT_COMPLETED,
                Intent.ACTION_MY_PACKAGE_REPLACED,
                "com.htc.intent.action.QUICKBOOT_POWERON"
            )) {
            // Restart EDR service on boot
            val serviceIntent = Intent(context, com.droidedr.detection.EDRCoreService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(serviceIntent)
            } else {
                context.startService(serviceIntent)
            }
        }
    }
}

// ─── DEVICE ADMIN RECEIVER ────────────────────────────────────────────────────
class EDRDeviceAdminReceiver : DeviceAdminReceiver() {
    override fun onEnabled(context: Context, intent: Intent) {
        // Device admin activated — enable additional protections
    }
    override fun onDisabled(context: Context, intent: Intent) {
        // Admin revoked — restart service to re-request admin
        val serviceIntent = Intent(context, com.droidedr.detection.EDRCoreService::class.java)
        context.startService(serviceIntent)
    }
}

// ─── WATCHDOG WORKER ──────────────────────────────────────────────────────────
class WatchdogWorker(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {
    override suspend fun doWork(): Result {
        val engine = SelfHealingEngine(applicationContext)
        // Health check via coroutine
        val serviceAlive = (applicationContext.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager)
            .getRunningServices(Int.MAX_VALUE)?.any {
                it.service.className == "com.droidedr.detection.EDRCoreService"
            } ?: false

        if (!serviceAlive) {
            val intent = Intent(applicationContext, com.droidedr.detection.EDRCoreService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                applicationContext.startForegroundService(intent)
            } else {
                applicationContext.startService(intent)
            }
        }
        return Result.success()
    }
}

// ─── WATCHDOG SERVICE ─────────────────────────────────────────────────────────
class WatchdogService : android.app.Service() {
    private val engine by lazy { SelfHealingEngine(this) }

    override fun onCreate() {
        super.onCreate()
        engine.startWatchdog()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        return START_STICKY  // Restart if killed
    }

    override fun onBind(intent: Intent?) = null
}
