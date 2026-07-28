package com.droidedr.engine

import android.content.Context
import android.content.pm.PackageManager
import android.provider.Settings
import java.io.File

/**
 * Populates a [Signals] snapshot from real device state using standard Android
 * APIs. Every read is wrapped so a missing permission or OEM quirk degrades that
 * one field to a safe default instead of failing the whole cycle — the engine
 * would rather under-report than crash.
 *
 * Fields sourced from the DNS VPN / keyguard subsystems (recentDnsQueries,
 * dhcpOffers, authFailuresLastWindow) are left empty here and marked TODO; wire
 * them from DnsVpnService and a keyguard-failure receiver when you're ready.
 */
class SignalCollector(private val context: Context) {

    fun collect(): Signals = Signals(
        timestamp = System.currentTimeMillis(),
        installedPackages = safe(emptyList()) { installed() },
        suBinariesPresent = safe(emptyList()) { suBinaries() },
        magiskPresent = safe(false) { magiskPresent() },
        adbTcpEnabled = safe(false) { adbTcpEnabled() },
        tcpListeners = safe(emptyList()) { listeningPorts() },
        developerOptionsOn = safe(false) { devOptionsOn() },
        unknownSourcesAllowed = safe(false) { unknownSourcesOn() }
        // TODO(port): recentDnsQueries  <- DnsVpnService query log
        // TODO(port): dhcpOffers        <- DHCP watcher
        // TODO(port): authFailuresLastWindow <- keyguard failure receiver
        // TODO(port): runningPackages   <- UsageStatsManager (needs PACKAGE_USAGE_STATS grant)
    )

    private fun installed(): List<PackageInfoLite> {
        val pm = context.packageManager
        val flags = PackageManager.GET_PERMISSIONS
        return pm.getInstalledPackages(flags).map { pi ->
            val requested = pi.requestedPermissions?.toSet() ?: emptySet()
            PackageInfoLite(
                packageName = pi.packageName,
                installerPackage = installerOf(pi.packageName),
                requestsAccessibility =
                    "android.permission.BIND_ACCESSIBILITY_SERVICE" in requested,
                requestsDeviceAdmin =
                    "android.permission.BIND_DEVICE_ADMIN" in requested
            )
        }
    }

    private fun installerOf(pkg: String): String? = try {
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.R)
            context.packageManager.getInstallSourceInfo(pkg).installingPackageName
        else
            @Suppress("DEPRECATION")
            context.packageManager.getInstallerPackageName(pkg)
    } catch (_: Exception) { null }

    private fun suBinaries(): List<String> = listOf(
        "/system/bin/su", "/system/xbin/su", "/sbin/su",
        "/su/bin/su", "/system/sd/xbin/su", "/vendor/bin/su"
    ).filter { File(it).exists() }

    private fun magiskPresent(): Boolean =
        listOf("/sbin/.magisk", "/cache/.disable_magisk", "/data/adb/magisk")
            .any { File(it).exists() } ||
            isInstalled("com.topjohnwu.magisk")

    private fun isInstalled(pkg: String): Boolean = try {
        context.packageManager.getPackageInfo(pkg, 0); true
    } catch (_: PackageManager.NameNotFoundException) { false }

    /** adb enabled AND a tcp port is set (service.adb.tcp.port) => ADB-over-TCP. */
    private fun adbTcpEnabled(): Boolean {
        val adbOn = Settings.Global.getInt(
            context.contentResolver, Settings.Global.ADB_ENABLED, 0
        ) == 1
        if (!adbOn) return false
        val port = systemProperty("service.adb.tcp.port")
        return port.isNotBlank() && port != "0" && port != "-1"
    }

    private fun devOptionsOn(): Boolean = Settings.Global.getInt(
        context.contentResolver,
        Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0
    ) == 1

    @Suppress("DEPRECATION")
    private fun unknownSourcesOn(): Boolean = try {
        Settings.Secure.getInt(
            context.contentResolver, "install_non_market_apps", 0
        ) == 1
    } catch (_: Exception) { false }

    /** Best-effort read of listening TCP ports from /proc/net/tcp (state 0A). */
    private fun listeningPorts(): List<Int> {
        val ports = mutableSetOf<Int>()
        listOf("/proc/net/tcp", "/proc/net/tcp6").forEach { path ->
            runCatching {
                File(path).useLines { lines ->
                    lines.drop(1).forEach { line ->
                        val cols = line.trim().split(Regex("\\s+"))
                        if (cols.size > 3 && cols[3] == "0A") {
                            val hexPort = cols[1].substringAfter(':')
                            hexPort.toIntOrNull(16)?.let { ports.add(it) }
                        }
                    }
                }
            }
        }
        return ports.toList()
    }

    private fun systemProperty(key: String): String = try {
        val c = Class.forName("android.os.SystemProperties")
        val m = c.getMethod("get", String::class.java)
        (m.invoke(null, key) as? String).orEmpty()
    } catch (_: Exception) { "" }

    private inline fun <T> safe(default: T, block: () -> T): T =
        try { block() } catch (_: Throwable) { default }
}
