package com.droidedr.engine.detectors

import com.droidedr.engine.Detector
import com.droidedr.engine.Match
import com.droidedr.engine.RuleContext
import org.json.JSONObject

/** T1633 — su / Magisk presence (privilege escalation / defense evasion). */
class SuBinaryDetector : Detector {
    override val key = "su_binary"
    override fun evaluate(ctx: RuleContext): Match? {
        val s = ctx.signals
        val found = s.suBinariesPresent
        if (found.isEmpty() && !s.magiskPresent) return null
        val evidence = JSONObject()
            .put("suBinaries", found.joinToString(","))
            .put("magisk", s.magiskPresent)
            .toString()
        return Match(
            summary = "Root artifacts present (${found.size} su binaries, magisk=${s.magiskPresent})",
            evidenceJson = evidence,
            observedValue = (found.size + if (s.magiskPresent) 1 else 0).toDouble()
        )
    }
}

/** T1430 / remote access — ADB over TCP exposed. */
class AdbTcpDetector : Detector {
    override val key = "adb_tcp"
    override fun evaluate(ctx: RuleContext): Match? {
        if (!ctx.signals.adbTcpEnabled) return null
        val listening = ctx.signals.tcpListeners.filter { it == 5555 }
        val evidence = JSONObject()
            .put("adbTcp", true)
            .put("port5555Listening", listening.isNotEmpty())
            .toString()
        return Match(
            summary = "ADB over TCP is enabled${if (listening.isNotEmpty()) " (5555 listening)" else ""}",
            evidenceJson = evidence,
            observedValue = 1.0
        )
    }
}

/** CVE-2024-3661 — rogue DHCP pushing Option 121 routes (VPN bypass). */
class DhcpOption121Detector : Detector {
    override val key = "dhcp_option121"
    override fun evaluate(ctx: RuleContext): Match? {
        val rogue = ctx.signals.dhcpOffers.filter { it.hasOption121 }
        if (rogue.isEmpty()) return null
        val evidence = JSONObject()
            .put("offers", rogue.joinToString(",") { it.serverMac })
            .put("count", rogue.size)
            .toString()
        return Match(
            summary = "DHCP Option 121 route injection observed from ${rogue.size} server(s)",
            evidenceJson = evidence,
            observedValue = rogue.size.toDouble()
        )
    }
}

/**
 * T1071.004 — DNS tunneling heuristic. Fires when a host shows an unusually long
 * label or high subdomain entropy above the spec threshold. Threshold comes from
 * the rule spec so it is tunable and recorded on every hit.
 */
class DnsTunnelingDetector : Detector {
    override val key = "dns_tunneling"
    override fun evaluate(ctx: RuleContext): Match? {
        val suspicious = ctx.signals.recentDnsQueries
            .map { it.host to labelEntropy(it.host) }
            .filter { it.second >= ctx.threshold }
        if (suspicious.isEmpty()) return null
        val worst = suspicious.maxByOrNull { it.second }!!
        val evidence = JSONObject()
            .put("host", worst.first)
            .put("entropy", worst.second)
            .put("suspiciousCount", suspicious.size)
            .toString()
        return Match(
            summary = "High-entropy DNS labels (possible tunneling): ${worst.first}",
            evidenceJson = evidence,
            observedValue = worst.second
        )
    }

    private fun labelEntropy(host: String): Double {
        val label = host.substringBefore('.').ifEmpty { host }
        if (label.isEmpty()) return 0.0
        val freq = label.groupingBy { it }.eachCount()
        val len = label.length.toDouble()
        return -freq.values.sumOf { c -> (c / len) * (Math.log(c / len) / Math.log(2.0)) }
    }
}

/** Remote access trojan / stalkerware package heuristic. */
class RatPackageDetector : Detector {
    override val key = "rat_package"
    private val watch = setOf(
        "com.teamviewer.quicksupport.market",
        "com.anydesk.anydeskandroid",
        "net.androidtvbox.rat"
    )
    override fun evaluate(ctx: RuleContext): Match? {
        val hits = ctx.signals.installedPackages.filter {
            it.packageName in watch ||
                (it.requestsAccessibility && it.requestsDeviceAdmin && it.installerPackage == null)
        }
        if (hits.isEmpty()) return null
        val evidence = JSONObject()
            .put("packages", hits.joinToString(",") { it.packageName })
            .toString()
        return Match(
            summary = "Remote-access / high-privilege sideloaded package(s): ${hits.size}",
            evidenceJson = evidence,
            observedValue = hits.size.toDouble()
        )
    }
}

/** T1110 — auth brute force / MFA fatigue: failure count over spec threshold. */
class AuthBruteForceDetector : Detector {
    override val key = "auth_bruteforce"
    override fun evaluate(ctx: RuleContext): Match? {
        val failures = ctx.signals.authFailuresLastWindow
        if (failures < ctx.threshold) return null
        val evidence = JSONObject().put("failures", failures).toString()
        return Match(
            summary = "Auth failures ($failures) exceeded threshold in window",
            evidenceJson = evidence,
            observedValue = failures.toDouble()
        )
    }
}
