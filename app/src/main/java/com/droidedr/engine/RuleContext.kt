package com.droidedr.engine

/**
 * An immutable snapshot of device state for one evaluation cycle. Collectors
 * populate this; detectors only read it. Keeping it read-only is what makes the
 * engine observe-only by construction — a detector has no handle it could use to
 * change device state even if it tried.
 *
 * Fields are intentionally coarse and cheap to sample. Add signals here as you
 * port rules over; a detector that needs a signal not present should be skipped,
 * not fail the cycle.
 */
data class Signals(
    val timestamp: Long,
    val runningPackages: List<String> = emptyList(),
    val installedPackages: List<PackageInfoLite> = emptyList(),
    val tcpListeners: List<Int> = emptyList(),          // listening local ports
    val adbTcpEnabled: Boolean = false,
    val suBinariesPresent: List<String> = emptyList(),  // e.g. /system/xbin/su
    val magiskPresent: Boolean = false,
    val recentDnsQueries: List<DnsQuery> = emptyList(),
    val authFailuresLastWindow: Int = 0,
    val dhcpOffers: List<DhcpOffer> = emptyList(),
    val developerOptionsOn: Boolean = false,
    val unknownSourcesAllowed: Boolean = false,
    val extras: Map<String, String> = emptyMap()        // escape hatch for ported rules
)

data class PackageInfoLite(
    val packageName: String,
    val installerPackage: String?,
    val requestsAccessibility: Boolean,
    val requestsDeviceAdmin: Boolean
)

data class DnsQuery(val host: String, val timestamp: Long, val responseIp: String?)

data class DhcpOffer(val serverMac: String, val hasOption121: Boolean, val gateway: String?)

/** What a detector reads. Threshold comes from the rule spec, not hardcoded. */
class RuleContext(
    val signals: Signals,
    val threshold: Double
)
