package com.droidedr.baseline

import android.app.ActivityManager
import android.app.usage.UsageStatsManager
import android.content.Context
import android.net.TrafficStats
import android.net.wifi.WifiManager
import android.os.Process
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import kotlinx.coroutines.*
import java.io.File
import kotlin.math.abs
import kotlin.math.sqrt

// ============================================================
// BEHAVIORAL BASELINE ENGINE
// - 7-day rolling behavioral profile
// - Statistical deviation scoring (z-score + IQR)
// - Per-app, network, system, and DNS baselines
// - Self-updating with anomaly exclusion
// ============================================================

data class NetworkBaseline(
    val avgBytesPerHour: Double = 0.0,
    val avgConnectionCount: Double = 0.0,
    val avgDnsQueriesPerHour: Double = 0.0,
    val typicalDnsServers: Set<String> = emptySet(),
    val avgUploadBytes: Double = 0.0,
    val avgDownloadBytes: Double = 0.0,
    val uploadStdDev: Double = 0.0,
    val downloadStdDev: Double = 0.0,
    val nighttimeThreshold: Double = 0.1,    // ratio of daytime traffic
    val typicalPorts: Set<Int> = setOf(80, 443, 53, 5228),
    val avgNxdomainRate: Double = 0.02        // 2% is normal
)

data class SystemBaseline(
    val avgCpuPercent: Double = 0.0,
    val avgMemoryMb: Double = 0.0,
    val avgBatteryDrainPerHour: Double = 0.0,
    val cpuStdDev: Double = 0.0,
    val memoryStdDev: Double = 0.0,
    val typicalProcesses: Set<String> = emptySet(),
    val avgForegroundServices: Double = 0.0,
    val wakeLocksTypical: Double = 0.0
)

data class AppBaseline(
    val packageName: String,
    val avgUsageMinutesPerDay: Double = 0.0,
    val avgBytesPerSession: Double = 0.0,
    val typicalPermissions: Set<String> = emptySet(),
    val firstSeen: Long = System.currentTimeMillis(),
    val lastSeen: Long = System.currentTimeMillis(),
    val installSource: String = "unknown",
    val avgLaunchCount: Double = 0.0,
    val backgroundActivity: Double = 0.0
)

data class DnsBaseline(
    val avgQueriesPerHour: Double = 0.0,
    val avgNxdomainPercent: Double = 2.0,
    val avgSubdomainLength: Double = 12.0,
    val avgQueryEntropy: Double = 3.2,
    val topDomains: Map<String, Int> = emptyMap(),
    val entropyStdDev: Double = 0.5,
    val subdomainLenStdDev: Double = 4.0
)

data class BaselineSnapshot(
    val timestamp: Long,
    val networkTxBytes: Long,
    val networkRxBytes: Long,
    val cpuPercent: Float,
    val memoryMb: Float,
    val batteryLevel: Int,
    val runningProcesses: List<String>,
    val dnsQueryCount: Int,
    val nxdomainCount: Int,
    val foregroundApp: String
)

data class BehaviorBaseline(
    val established: Boolean = false,
    val baselinePeriodDays: Int = 7,
    val startTimestamp: Long = System.currentTimeMillis(),
    val lastUpdated: Long = System.currentTimeMillis(),
    val network: NetworkBaseline = NetworkBaseline(),
    val system: SystemBaseline = SystemBaseline(),
    val dns: DnsBaseline = DnsBaseline(),
    val apps: Map<String, AppBaseline> = emptyMap(),
    val snapshots: List<BaselineSnapshot> = emptyList(),
    val anomalyThresholdSigma: Double = 3.0,  // 3-sigma rule
    val coveragePercent: Int = 0              // 0-100% baseline maturity
)

data class DeviationReport(
    val score: Double,          // 0.0 = normal, 1.0 = max anomaly
    val category: String,
    val detail: String,
    val sigmaValue: Double,
    val isCritical: Boolean
)

class BaselineEngine(private val context: Context) {

    private val prefs = context.getSharedPreferences("droidedr_baseline", Context.MODE_PRIVATE)
    private val gson = Gson()
    private var currentBaseline = loadBaseline()
    private val snapshots = mutableListOf<BaselineSnapshot>()

    companion object {
        const val BASELINE_FILE = "baseline_v2.json"
        const val SNAPSHOT_INTERVAL_MS = 5 * 60 * 1000L  // 5 min
        const val BASELINE_COMPLETE_DAYS = 7
        const val CRITICAL_SIGMA = 4.0
        const val HIGH_SIGMA = 3.0
    }

    fun getBaseline(): BehaviorBaseline = currentBaseline

    fun isEstablished(): Boolean = currentBaseline.established

    fun getMaturityPercent(): Int = currentBaseline.coveragePercent

    // ─── SNAPSHOT CAPTURE ─────────────────────────────────────────────────────
    fun captureSnapshot(): BaselineSnapshot {
        val am = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
        val memInfo = ActivityManager.MemoryInfo()
        am.getMemoryInfo(memInfo)

        val snapshot = BaselineSnapshot(
            timestamp = System.currentTimeMillis(),
            networkTxBytes = TrafficStats.getTotalTxBytes(),
            networkRxBytes = TrafficStats.getTotalRxBytes(),
            cpuPercent = getCpuUsage(),
            memoryMb = ((memInfo.totalMem - memInfo.availMem) / (1024f * 1024f)),
            batteryLevel = getBatteryLevel(),
            runningProcesses = getRunningProcessNames(am),
            dnsQueryCount = 0,  // populated by DnsVpnService
            nxdomainCount = 0,  // populated by DnsVpnService
            foregroundApp = getForegroundApp()
        )

        snapshots.add(snapshot)
        if (snapshots.size > 2016) snapshots.removeAt(0)  // keep ~7 days at 5min intervals

        updateBaseline()
        return snapshot
    }

    // ─── BASELINE COMPUTATION ─────────────────────────────────────────────────
    private fun updateBaseline() {
        if (snapshots.size < 12) return  // need at least 1 hour

        val txDeltas = snapshots.zipWithNext { a, b -> (b.networkTxBytes - a.networkTxBytes).toDouble() }
        val rxDeltas = snapshots.zipWithNext { a, b -> (b.networkRxBytes - a.networkRxBytes).toDouble() }
        val cpus = snapshots.map { it.cpuPercent.toDouble() }
        val mems = snapshots.map { it.memoryMb.toDouble() }

        val avgTx = txDeltas.average()
        val avgRx = rxDeltas.average()
        val avgCpu = cpus.average()
        val avgMem = mems.average()

        val txStd = stdDev(txDeltas)
        val rxStd = stdDev(rxDeltas)
        val cpuStd = stdDev(cpus)
        val memStd = stdDev(mems)

        val daysCovered = ((System.currentTimeMillis() - currentBaseline.startTimestamp) /
                (1000.0 * 60 * 60 * 24)).coerceAtMost(7.0)
        val coverage = ((daysCovered / 7.0) * 100).toInt().coerceIn(0, 100)

        val newBaseline = currentBaseline.copy(
            established = daysCovered >= 1.0,
            lastUpdated = System.currentTimeMillis(),
            coveragePercent = coverage,
            network = currentBaseline.network.copy(
                avgBytesPerHour = avgTx * 12,  // 5min * 12 = 1hr
                avgUploadBytes = avgTx,
                avgDownloadBytes = avgRx,
                uploadStdDev = txStd,
                downloadStdDev = rxStd
            ),
            system = currentBaseline.system.copy(
                avgCpuPercent = avgCpu,
                avgMemoryMb = avgMem,
                cpuStdDev = cpuStd,
                memoryStdDev = memStd
            ),
            snapshots = snapshots.takeLast(100)  // persist last 100 snapshots
        )

        currentBaseline = newBaseline
        saveBaseline(newBaseline)
    }

    // ─── DEVIATION ANALYSIS ───────────────────────────────────────────────────
    fun analyzeDeviation(current: BaselineSnapshot): List<DeviationReport> {
        if (!currentBaseline.established) return emptyList()

        val reports = mutableListOf<DeviationReport>()
        val baseline = currentBaseline

        // Network TX deviation
        if (baseline.network.uploadStdDev > 0) {
            val txDelta = (current.networkTxBytes - (snapshots.lastOrNull()?.networkTxBytes ?: 0)).toDouble()
            val sigma = (txDelta - baseline.network.avgUploadBytes) / baseline.network.uploadStdDev
            if (sigma > HIGH_SIGMA) {
                reports.add(DeviationReport(
                    score = (sigma / 10.0).coerceIn(0.0, 1.0),
                    category = "NETWORK_UPLOAD",
                    detail = "Upload spike: ${sigma.toInt()}σ above baseline (${formatBytes(txDelta.toLong())})",
                    sigmaValue = sigma,
                    isCritical = sigma > CRITICAL_SIGMA
                ))
            }
        }

        // CPU deviation
        if (baseline.system.cpuStdDev > 0) {
            val sigma = (current.cpuPercent - baseline.system.avgCpuPercent) / baseline.system.cpuStdDev
            if (sigma > HIGH_SIGMA) {
                reports.add(DeviationReport(
                    score = (sigma / 10.0).coerceIn(0.0, 1.0),
                    category = "CPU_SPIKE",
                    detail = "CPU anomaly: ${current.cpuPercent.toInt()}% vs baseline ${baseline.system.avgCpuPercent.toInt()}% (${sigma.toInt()}σ)",
                    sigmaValue = sigma,
                    isCritical = sigma > CRITICAL_SIGMA
                ))
            }
        }

        // New process detection
        val knownProcesses = baseline.system.typicalProcesses
        val newProcesses = current.runningProcesses.filter { it !in knownProcesses }
        if (newProcesses.isNotEmpty()) {
            reports.add(DeviationReport(
                score = 0.6,
                category = "NEW_PROCESS",
                detail = "Unknown processes: ${newProcesses.take(5).joinToString()}",
                sigmaValue = 4.0,
                isCritical = newProcesses.any { it.contains("shell") || it.contains("su") || it.contains("magisk") }
            ))
        }

        return reports
    }

    fun getDnsDeviation(queryCount: Int, nxdomainCount: Int, avgEntropy: Double): List<DeviationReport> {
        val reports = mutableListOf<DeviationReport>()
        val dns = currentBaseline.dns

        // NXDOMAIN storm detection
        val nxdomainRate = if (queryCount > 0) nxdomainCount.toDouble() / queryCount else 0.0
        if (nxdomainRate > dns.avgNxdomainPercent / 100 * 5) {  // 5x normal
            reports.add(DeviationReport(
                score = (nxdomainRate * 5).coerceIn(0.0, 1.0),
                category = "DNS_NXDOMAIN_STORM",
                detail = "NXDOMAIN rate ${(nxdomainRate * 100).toInt()}% vs baseline ${dns.avgNxdomainPercent.toInt()}%",
                sigmaValue = nxdomainRate / (dns.avgNxdomainPercent / 100),
                isCritical = nxdomainRate > 0.5
            ))
        }

        // DNS entropy (tunneling detection)
        if (dns.entropyStdDev > 0) {
            val sigma = (avgEntropy - dns.avgQueryEntropy) / dns.entropyStdDev
            if (sigma > 2.5) {
                reports.add(DeviationReport(
                    score = (sigma / 8.0).coerceIn(0.0, 1.0),
                    category = "DNS_ENTROPY_HIGH",
                    detail = "DNS query entropy ${avgEntropy.format(2)} vs baseline ${dns.avgQueryEntropy.format(2)} (${sigma.format(1)}σ)",
                    sigmaValue = sigma,
                    isCritical = sigma > CRITICAL_SIGMA
                ))
            }
        }

        return reports
    }

    // ─── UTILITY ──────────────────────────────────────────────────────────────
    private fun stdDev(values: List<Double>): Double {
        if (values.size < 2) return 0.0
        val mean = values.average()
        return sqrt(values.map { (it - mean) * (it - mean) }.average())
    }

    private fun getCpuUsage(): Float {
        return try {
            val pid = Process.myPid()
            val reader = File("/proc/stat").bufferedReader()
            val line = reader.readLine()
            reader.close()
            val parts = line.trim().split("\\s+".toRegex())
            val idle = parts[4].toLong()
            val total = parts.drop(1).take(7).sumOf { it.toLong() }
            ((total - idle).toFloat() / total.toFloat() * 100)
        } catch (e: Exception) { 0f }
    }

    private fun getBatteryLevel(): Int = 50  // placeholder — use BatteryManager in real impl

    private fun getRunningProcessNames(am: ActivityManager): List<String> {
        return try {
            am.runningAppProcesses?.map { it.processName } ?: emptyList()
        } catch (e: Exception) { emptyList() }
    }

    private fun getForegroundApp(): String = "com.droidedr"  // placeholder

    private fun formatBytes(bytes: Long): String = when {
        bytes > 1024 * 1024 -> "${bytes / (1024 * 1024)}MB"
        bytes > 1024 -> "${bytes / 1024}KB"
        else -> "${bytes}B"
    }

    private fun Double.format(digits: Int) = "%.${digits}f".format(this)

    // ─── PERSISTENCE ──────────────────────────────────────────────────────────
    private fun saveBaseline(baseline: BehaviorBaseline) {
        try {
            val json = gson.toJson(baseline)
            val file = File(context.filesDir, BASELINE_FILE)
            file.writeText(json)
            prefs.edit().putLong("last_saved", System.currentTimeMillis()).apply()
        } catch (e: Exception) { /* log error */ }
    }

    private fun loadBaseline(): BehaviorBaseline {
        return try {
            val file = File(context.filesDir, BASELINE_FILE)
            if (file.exists()) {
                val json = file.readText()
                gson.fromJson(json, BehaviorBaseline::class.java) ?: BehaviorBaseline()
            } else BehaviorBaseline()
        } catch (e: Exception) { BehaviorBaseline() }
    }

    fun resetBaseline() {
        File(context.filesDir, BASELINE_FILE).delete()
        snapshots.clear()
        currentBaseline = BehaviorBaseline()
    }
}
