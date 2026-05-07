package com.droidedr.detection

import android.content.Context
import com.droidedr.baseline.BehaviorBaseline
import java.util.Date

// ============================================================
// MITRE ATT&CK MOBILE FRAMEWORK - COMPLETE RULE SET v2.0
// Covers: Identify, Protect, Respond
// Domains: LotL, DNS/DHCP, Brute Force, Remote Access, CVEs
// ============================================================

enum class MitrePhase { IDENTIFY, PROTECT, RESPOND }
enum class ThreatSeverity { CRITICAL, HIGH, MEDIUM, LOW, INFO }
enum class ThreatCategory {
    LOTL, DNS_ATTACK, DHCP_ATTACK, BRUTE_FORCE,
    REMOTE_ACCESS, EXPLOIT_CVE, PERSISTENCE,
    PRIVILEGE_ESCALATION, DEFENSE_EVASION, CREDENTIAL_ACCESS,
    DISCOVERY, LATERAL_MOVEMENT, COLLECTION, EXFILTRATION, COMMAND_AND_CONTROL
}

data class MitreTechnique(
    val id: String,          // e.g. T1422
    val name: String,
    val tactic: String,
    val category: ThreatCategory,
    val phase: MitrePhase,
    val severity: ThreatSeverity,
    val description: String,
    val indicators: List<String>,
    val mitigations: List<String>,
    val autoRespond: Boolean = true
)

data class ThreatAlert(
    val id: String = java.util.UUID.randomUUID().toString(),
    val timestamp: Long = System.currentTimeMillis(),
    val technique: MitreTechnique,
    val evidence: Map<String, String>,
    val deviceState: String,
    val responded: Boolean = false,
    val responseActions: List<String> = emptyList(),
    val baselineDeviation: Double = 0.0
)

object MitreRulesEngine {

    // ─── LIVING OFF THE LAND (LotL) ──────────────────────────────────────────
    val T1623 = MitreTechnique(
        id = "T1623", name = "Command and Scripting Interpreter",
        tactic = "Execution", category = ThreatCategory.LOTL, phase = MitrePhase.IDENTIFY,
        severity = ThreatSeverity.HIGH,
        description = "Adversary uses device shell (sh/bash/toybox) to execute malicious commands via legitimate interpreter",
        indicators = listOf("shell_exec_anomaly", "toybox_abuse", "sh_child_of_browser", "adb_shell_active"),
        mitigations = listOf("Block ADB remote", "Disable developer mode", "Terminate shell process", "Alert SOC"),
        autoRespond = true
    )

    val T1624 = MitreTechnique(
        id = "T1624", name = "Event Triggered Execution",
        tactic = "Persistence", category = ThreatCategory.PERSISTENCE, phase = MitrePhase.IDENTIFY,
        severity = ThreatSeverity.HIGH,
        description = "Malware registers broadcast receivers for system events (BOOT, SMS, SCREEN_ON) to persist",
        indicators = listOf("suspicious_broadcast_receiver", "boot_persist_app", "undeclared_receiver"),
        mitigations = listOf("Revoke permissions", "Quarantine package", "Remove from autostart"),
        autoRespond = true
    )

    val T1631 = MitreTechnique(
        id = "T1631", name = "Process Injection via Shared Libraries",
        tactic = "Defense Evasion", category = ThreatCategory.LOTL, phase = MitrePhase.IDENTIFY,
        severity = ThreatSeverity.CRITICAL,
        description = "Malicious code injected into legitimate process memory via .so library loading",
        indicators = listOf("unexpected_so_load", "dlopen_from_tmp", "library_from_external_storage"),
        mitigations = listOf("Block process", "Memory scan trigger", "Isolate app", "Reboot recovery"),
        autoRespond = true
    )

    val T1655 = MitreTechnique(
        id = "T1655", name = "Masquerading - Match Legitimate Name",
        tactic = "Defense Evasion", category = ThreatCategory.LOTL, phase = MitrePhase.IDENTIFY,
        severity = ThreatSeverity.HIGH,
        description = "App mimics system package name (com.android.*, com.google.*) to evade detection",
        indicators = listOf("fake_system_package", "spoofed_certificate", "icon_clone", "name_collision"),
        mitigations = listOf("Certificate validation", "Package quarantine", "User alert"),
        autoRespond = true
    )

    val T1629 = MitreTechnique(
        id = "T1629", name = "Impair Defenses - Disable or Modify Tools",
        tactic = "Defense Evasion", category = ThreatCategory.DEFENSE_EVASION, phase = MitrePhase.PROTECT,
        severity = ThreatSeverity.CRITICAL,
        description = "Adversary attempts to disable EDR, antivirus, or security services",
        indicators = listOf("edr_kill_attempt", "security_app_uninstall", "accessibility_revoke_attempt"),
        mitigations = listOf("SELF-HEAL: restart service", "Lock settings", "Elevate alert", "Notify admin"),
        autoRespond = true
    )

    // ─── DNS ATTACKS ──────────────────────────────────────────────────────────
    val T1437_001 = MitreTechnique(
        id = "T1437.001", name = "DNS Tunneling",
        tactic = "Command and Control", category = ThreatCategory.DNS_ATTACK, phase = MitrePhase.IDENTIFY,
        severity = ThreatSeverity.CRITICAL,
        description = "Malware exfiltrates data or receives C2 commands encoded in DNS query/response payloads",
        indicators = listOf("dns_query_entropy_high", "abnormal_subdomain_length", "txt_record_abuse",
            "nxdomain_storm", "dns_beacon_pattern", "covert_channel_dns"),
        mitigations = listOf("Block DNS to non-trusted resolvers", "Redirect to DNS sinkehole",
            "Alert + capture PCAP", "Quarantine offending app"),
        autoRespond = true
    )

    val T1637 = MitreTechnique(
        id = "T1637", name = "Dynamic Resolution - DGA",
        tactic = "Command and Control", category = ThreatCategory.DNS_ATTACK, phase = MitrePhase.IDENTIFY,
        severity = ThreatSeverity.CRITICAL,
        description = "Malware uses Domain Generation Algorithm to rotate C2 domains, evading static blocklists",
        indicators = listOf("dga_pattern_detected", "high_nxdomain_rate", "random_domain_entropy",
            "subdomain_rotation", "consonant_cluster_anomaly"),
        mitigations = listOf("DGA domain blocking", "Enforce DoH with trusted provider",
            "Isolate device from network", "Forensic capture"),
        autoRespond = true
    )

    val DNS_HIJACK = MitreTechnique(
        id = "T1599.DNS", name = "DNS Hijacking / Rogue Server",
        tactic = "Defense Evasion", category = ThreatCategory.DNS_ATTACK, phase = MitrePhase.PROTECT,
        severity = ThreatSeverity.CRITICAL,
        description = "DNS settings modified to route queries through attacker-controlled resolver for MITM",
        indicators = listOf("dns_server_changed", "private_ip_dns_server", "dns_response_mismatch",
            "dnssec_validation_failure"),
        mitigations = listOf("Restore trusted DNS (1.1.1.1 / 8.8.8.8)", "Lock DNS via VPN",
            "Invalidate DNS cache", "Alert user"),
        autoRespond = true
    )

    val DNS_REBINDING = MitreTechnique(
        id = "T1599.REB", name = "DNS Rebinding Attack",
        tactic = "Lateral Movement", category = ThreatCategory.DNS_ATTACK, phase = MitrePhase.IDENTIFY,
        severity = ThreatSeverity.HIGH,
        description = "Short TTL DNS responses rebind external domain to internal IP, bypassing SOP",
        indicators = listOf("dns_ttl_below_30s", "external_domain_internal_ip", "rebind_pattern"),
        mitigations = listOf("Block rebinding IPs", "Enforce minimum TTL", "NAT firewall rules"),
        autoRespond = true
    )

    // ─── DHCP ATTACKS ─────────────────────────────────────────────────────────
    val DHCP_STARVATION = MitreTechnique(
        id = "T1557.DHCP", name = "DHCP Starvation / Rogue Server",
        tactic = "Credential Access", category = ThreatCategory.DHCP_ATTACK, phase = MitrePhase.IDENTIFY,
        severity = ThreatSeverity.HIGH,
        description = "Attacker floods DHCP pool or stands up rogue DHCP server to redirect traffic",
        indicators = listOf("dhcp_server_ip_changed", "multiple_dhcp_offers", "gateway_changed",
            "arp_gateway_mismatch", "unexpected_dhcp_options"),
        mitigations = listOf("Static IP assignment", "Network isolation", "Alert + log DHCP offer MACs"),
        autoRespond = true
    )

    val DHCP_OPTION_INJECT = MitreTechnique(
        id = "T1557.DHCP2", name = "DHCP Option 121 Route Injection",
        tactic = "Credential Access", category = ThreatCategory.DHCP_ATTACK, phase = MitrePhase.IDENTIFY,
        severity = ThreatSeverity.CRITICAL,
        description = "CVE-2024-3661: DHCP Option 121 used to inject host routes bypassing VPN tunnel",
        indicators = listOf("dhcp_opt121_present", "route_injection_detected", "vpn_split_tunnel_anomaly"),
        mitigations = listOf("Block DHCP option 121 processing", "Re-route all traffic through VPN",
            "Alert security team", "Patch VPN client"),
        autoRespond = true
    )

    // ─── BRUTE FORCE ──────────────────────────────────────────────────────────
    val T1110_001 = MitreTechnique(
        id = "T1110.001", name = "Brute Force - Password Guessing",
        tactic = "Credential Access", category = ThreatCategory.BRUTE_FORCE, phase = MitrePhase.IDENTIFY,
        severity = ThreatSeverity.HIGH,
        description = "Repeated authentication failures against device lock screen, SSH, or app login",
        indicators = listOf("auth_failures_gt5", "lockscreen_attempts_rapid", "ssh_brute_force",
            "api_auth_flooding", "pin_spray_pattern"),
        mitigations = listOf("Temporary lockout", "Increase delay", "Alert user", "Enable biometric lock"),
        autoRespond = true
    )

    val T1110_003 = MitreTechnique(
        id = "T1110.003", name = "Password Spraying",
        tactic = "Credential Access", category = ThreatCategory.BRUTE_FORCE, phase = MitrePhase.IDENTIFY,
        severity = ThreatSeverity.HIGH,
        description = "Low-and-slow credential stuffing across multiple accounts to evade lockout policies",
        indicators = listOf("distributed_auth_failures", "multi_account_low_rate_fail", "credential_stuffing_pattern"),
        mitigations = listOf("Rate limit auth endpoints", "MFA enforcement", "Block source IP"),
        autoRespond = false
    )

    val T1621 = MitreTechnique(
        id = "T1621", name = "MFA Request Generation (MFA Fatigue)",
        tactic = "Credential Access", category = ThreatCategory.BRUTE_FORCE, phase = MitrePhase.IDENTIFY,
        severity = ThreatSeverity.HIGH,
        description = "Attacker floods user with MFA push notifications hoping for accidental approval",
        indicators = listOf("mfa_push_flood", "repeated_auth_prompts", "auth_request_storm"),
        mitigations = listOf("Block push notifications from auth app", "Alert user", "Require number matching"),
        autoRespond = true
    )

    // ─── REMOTE ACCESS ────────────────────────────────────────────────────────
    val T1219 = MitreTechnique(
        id = "T1219", name = "Remote Access Software (RAT)",
        tactic = "Command and Control", category = ThreatCategory.REMOTE_ACCESS, phase = MitrePhase.IDENTIFY,
        severity = ThreatSeverity.CRITICAL,
        description = "Unauthorized RAT/RDP/TeamViewer/AnyDesk-type software providing attacker device control",
        indicators = listOf("rat_package_detected", "screen_capture_background", "input_injection_active",
            "remote_control_api_usage", "adb_tcp_open", "scrcpy_connection"),
        mitigations = listOf("Kill process immediately", "Block network socket", "Quarantine app",
            "Revoke accessibility permissions", "Wipe sensitive data"),
        autoRespond = true
    )

    val T1481 = MitreTechnique(
        id = "T1481", name = "Web Service C2 (Legitimate Service Abuse)",
        tactic = "Command and Control", category = ThreatCategory.REMOTE_ACCESS, phase = MitrePhase.IDENTIFY,
        severity = ThreatSeverity.HIGH,
        description = "C2 traffic tunneled through Telegram, Discord, Pastebin, GitHub to evade detection",
        indicators = listOf("c2_via_telegram", "pastebin_exfil", "discord_webhook_c2",
            "github_raw_payload", "legitimate_service_beacon"),
        mitigations = listOf("Deep packet inspection", "Behavioral analysis", "Alert analyst", "Block endpoint"),
        autoRespond = false
    )

    val ADB_REMOTE = MitreTechnique(
        id = "T1219.ADB", name = "ADB over TCP/IP Remote Access",
        tactic = "Command and Control", category = ThreatCategory.REMOTE_ACCESS, phase = MitrePhase.PROTECT,
        severity = ThreatSeverity.CRITICAL,
        description = "Android Debug Bridge running in TCP mode (port 5555) enabling unauthorized root shell",
        indicators = listOf("adb_tcp_port_5555_open", "adb_authorized_keys_modified", "usb_debugging_enabled"),
        mitigations = listOf("Kill ADB TCP listener", "Disable USB debugging", "Close port 5555",
            "Remove unauthorized ADB keys"),
        autoRespond = true
    )

    val T1563 = MitreTechnique(
        id = "T1563", name = "Remote Service Session Hijacking",
        tactic = "Lateral Movement", category = ThreatCategory.REMOTE_ACCESS, phase = MitrePhase.RESPOND,
        severity = ThreatSeverity.CRITICAL,
        description = "Attacker hijacks authenticated session tokens (OAuth, cookies, JWT) for lateral movement",
        indicators = listOf("token_replay_detected", "session_from_new_location", "jwt_manipulation",
            "oauth_token_theft"),
        mitigations = listOf("Invalidate all tokens", "Force re-auth", "Alert user", "Log forensic data"),
        autoRespond = true
    )

    // ─── CVE-BASED EXPLOITS (2021–2026) ──────────────────────────────────────
    val CVE_2024_3661 = MitreTechnique(
        id = "CVE-2024-3661", name = "TunnelVision - DHCP Route Bypass",
        tactic = "Defense Evasion", category = ThreatCategory.EXPLOIT_CVE, phase = MitrePhase.PROTECT,
        severity = ThreatSeverity.CRITICAL,
        description = "VPN bypass via DHCP Option 121 route injection, leaking traffic outside encrypted tunnel",
        indicators = listOf("dhcp_opt121_present", "vpn_traffic_leak", "tunnel_bypass"),
        mitigations = listOf("Detect and block DHCP option 121", "Enforce strict tunnel routing"),
        autoRespond = true
    )

    val CVE_2024_0044 = MitreTechnique(
        id = "CVE-2024-0044", name = "Android createSession Privilege Escalation",
        tactic = "Privilege Escalation", category = ThreatCategory.EXPLOIT_CVE, phase = MitrePhase.PROTECT,
        severity = ThreatSeverity.CRITICAL,
        description = "PackageInstaller createSession allows run-as arbitrary app, enabling sandbox escape",
        indicators = listOf("pkg_installer_anomaly", "sandbox_escape_attempt", "run_as_abuse"),
        mitigations = listOf("Block PackageInstaller API misuse", "Patch Android to March 2024+"),
        autoRespond = true
    )

    val CVE_2023_4863 = MitreTechnique(
        id = "CVE-2023-4863", name = "libwebp Heap Buffer Overflow (0-day)",
        tactic = "Execution", category = ThreatCategory.EXPLOIT_CVE, phase = MitrePhase.IDENTIFY,
        severity = ThreatSeverity.CRITICAL,
        description = "Critical WebP image parsing heap overflow enabling RCE via malicious image in Chrome/apps",
        indicators = listOf("webp_heap_overflow_pattern", "renderer_crash_repeated", "memory_corruption_sig"),
        mitigations = listOf("Block WebP from untrusted sources", "Kill browser renderer", "Update Chrome/libwebp"),
        autoRespond = true
    )

    val CVE_2023_20963 = MitreTechnique(
        id = "CVE-2023-20963", name = "Android WorkSource Parcel Privilege Escalation",
        tactic = "Privilege Escalation", category = ThreatCategory.EXPLOIT_CVE, phase = MitrePhase.PROTECT,
        severity = ThreatSeverity.HIGH,
        description = "WorkSource deserialization flaw allows privilege escalation without user interaction",
        indicators = listOf("worksource_parcel_anomaly", "system_service_exploit_attempt"),
        mitigations = listOf("Monitor Binder transactions", "Apply March 2023 patch"),
        autoRespond = true
    )

    val CVE_2022_20465 = MitreTechnique(
        id = "CVE-2022-20465", name = "Android Lock Screen Bypass",
        tactic = "Defense Evasion", category = ThreatCategory.EXPLOIT_CVE, phase = MitrePhase.PROTECT,
        severity = ThreatSeverity.CRITICAL,
        description = "SIM card replacement bypasses Android lock screen on Pixel/Samsung (patched Nov 2022)",
        indicators = listOf("sim_swap_detected", "lockscreen_bypass_pattern", "invalid_sim_insertion"),
        mitigations = listOf("Carrier lock enforcement", "Anti-SIM-swap alert", "Device lock escalation"),
        autoRespond = true
    )

    val CVE_2021_39793 = MitreTechnique(
        id = "CVE-2021-39793", name = "Android GPU Driver OOB Write (Pixel)",
        tactic = "Privilege Escalation", category = ThreatCategory.EXPLOIT_CVE, phase = MitrePhase.PROTECT,
        severity = ThreatSeverity.HIGH,
        description = "Mali/Adreno GPU driver out-of-bounds write enabling kernel code execution",
        indicators = listOf("gpu_driver_anomaly", "kernel_exploit_signature", "mali_crash_pattern"),
        mitigations = listOf("Kernel integrity monitoring", "Apply GPU firmware patch"),
        autoRespond = false
    )

    val CVE_2025_0282 = MitreTechnique(
        id = "CVE-2025-0282", name = "Ivanti Connect Secure Stack Overflow (RCE)",
        tactic = "Initial Access", category = ThreatCategory.EXPLOIT_CVE, phase = MitrePhase.IDENTIFY,
        severity = ThreatSeverity.CRITICAL,
        description = "Pre-auth stack overflow in Ivanti Connect Secure VPN client enabling device RCE",
        indicators = listOf("ivanti_client_anomaly", "vpn_stack_overflow_sig", "pre_auth_rce_pattern"),
        mitigations = listOf("Block Ivanti VPN connections", "Apply Ivanti patch immediately"),
        autoRespond = true
    )

    val CVE_2026_PLACEHOLDER = MitreTechnique(
        id = "CVE-2026-HEUR", name = "Zero-Day Heuristic Detection (2026)",
        tactic = "Initial Access", category = ThreatCategory.EXPLOIT_CVE, phase = MitrePhase.IDENTIFY,
        severity = ThreatSeverity.CRITICAL,
        description = "Behavioral heuristics detecting unknown/zero-day exploit patterns via baseline deviation",
        indicators = listOf("baseline_deviation_critical", "unknown_syscall_pattern", "memory_anomaly",
            "privilege_spike", "new_root_process"),
        mitigations = listOf("Isolate process", "Capture memory dump", "Alert SOC", "Enable strict mode"),
        autoRespond = true
    )

    // ─── PERSISTENCE / PRIVILEGE ESCALATION ──────────────────────────────────
    val T1398 = MitreTechnique(
        id = "T1398", name = "Boot or Logon Initialization Scripts",
        tactic = "Persistence", category = ThreatCategory.PERSISTENCE, phase = MitrePhase.IDENTIFY,
        severity = ThreatSeverity.HIGH,
        description = "Malware installs init.d scripts or modifies boot sequence for persistence",
        indicators = listOf("initd_modification", "boot_script_added", "rc_local_modification"),
        mitigations = listOf("Remove malicious init scripts", "Monitor /etc/init.d", "Integrity check boot"),
        autoRespond = true
    )

    val T1626 = MitreTechnique(
        id = "T1626", name = "Abuse Elevation Control (su/sudo)",
        tactic = "Privilege Escalation", category = ThreatCategory.PRIVILEGE_ESCALATION, phase = MitrePhase.IDENTIFY,
        severity = ThreatSeverity.CRITICAL,
        description = "App abuses su binary or rooted device to gain elevated privileges",
        indicators = listOf("su_binary_present", "root_shell_spawned", "selinux_disabled",
            "magisk_detected", "supersu_active"),
        mitigations = listOf("Alert user of root abuse", "Block su access", "Integrity check"),
        autoRespond = true
    )

    val T1541 = MitreTechnique(
        id = "T1541", name = "Foreground Persistence",
        tactic = "Persistence", category = ThreatCategory.PERSISTENCE, phase = MitrePhase.IDENTIFY,
        severity = ThreatSeverity.MEDIUM,
        description = "Malware runs as foreground service to prevent kill by system's low-memory killer",
        indicators = listOf("suspicious_foreground_service", "permanent_notification_abuse",
            "wakelock_excessive"),
        mitigations = listOf("Kill foreground service", "Revoke FOREGROUND_SERVICE permission"),
        autoRespond = true
    )

    // ─── CREDENTIAL ACCESS ────────────────────────────────────────────────────
    val T1417 = MitreTechnique(
        id = "T1417", name = "Input Capture - Keylogging",
        tactic = "Credential Access", category = ThreatCategory.CREDENTIAL_ACCESS, phase = MitrePhase.IDENTIFY,
        severity = ThreatSeverity.CRITICAL,
        description = "Malicious accessibility service or IME captures keystrokes including passwords",
        indicators = listOf("suspicious_accessibility_service", "ime_keystroke_capture",
            "overlay_attack", "input_method_abuse"),
        mitigations = listOf("Revoke accessibility permission", "Remove malicious IME",
            "Block overlay", "Reset credentials"),
        autoRespond = true
    )

    val T1416 = MitreTechnique(
        id = "T1416", name = "URI Hijacking (Intent Hijacking)",
        tactic = "Credential Access", category = ThreatCategory.CREDENTIAL_ACCESS, phase = MitrePhase.IDENTIFY,
        severity = ThreatSeverity.HIGH,
        description = "Malicious app intercepts custom URI scheme intents (OAuth callbacks) to steal tokens",
        indicators = listOf("uri_scheme_collision", "oauth_callback_intercept", "deep_link_hijack"),
        mitigations = listOf("Validate intent origin", "Block hijacking app", "Re-issue tokens"),
        autoRespond = true
    )

    // ─── EXFILTRATION ─────────────────────────────────────────────────────────
    val T1646 = MitreTechnique(
        id = "T1646", name = "Exfiltration over C2 Channel",
        tactic = "Exfiltration", category = ThreatCategory.EXFILTRATION, phase = MitrePhase.RESPOND,
        severity = ThreatSeverity.CRITICAL,
        description = "Data exfiltrated via same channel used for C2 communication, often encrypted",
        indicators = listOf("large_upload_anomaly", "encrypted_outbound_burst", "nighttime_exfil",
            "beacon_with_data", "high_entropy_upload"),
        mitigations = listOf("Block outbound connection", "Capture evidence", "Alert SOC", "Data loss prevention"),
        autoRespond = true
    )

    val T1532 = MitreTechnique(
        id = "T1532", name = "Archive Collected Data",
        tactic = "Collection", category = ThreatCategory.COLLECTION, phase = MitrePhase.IDENTIFY,
        severity = ThreatSeverity.MEDIUM,
        description = "Malware stages stolen files into compressed archives before exfiltration",
        indicators = listOf("bulk_file_archive", "zip_of_sensitive_dirs", "staging_directory_created"),
        mitigations = listOf("Block archive creation", "Monitor file system changes"),
        autoRespond = false
    )

    // ─── FULL RULE CATALOGUE ─────────────────────────────────────────────────
    val ALL_RULES: List<MitreTechnique> = listOf(
        // LotL
        T1623, T1624, T1631, T1655, T1629,
        // DNS
        T1437_001, T1637, DNS_HIJACK, DNS_REBINDING,
        // DHCP
        DHCP_STARVATION, DHCP_OPTION_INJECT,
        // Brute Force
        T1110_001, T1110_003, T1621,
        // Remote Access
        T1219, T1481, ADB_REMOTE, T1563,
        // CVEs
        CVE_2024_3661, CVE_2024_0044, CVE_2023_4863,
        CVE_2023_20963, CVE_2022_20465, CVE_2021_39793,
        CVE_2025_0282, CVE_2026_PLACEHOLDER,
        // Persistence / Privilege
        T1398, T1626, T1541,
        // Credential
        T1417, T1416,
        // Exfil
        T1646, T1532
    )

    fun getRulesByPhase(phase: MitrePhase) = ALL_RULES.filter { it.phase == phase }
    fun getRulesByCategory(cat: ThreatCategory) = ALL_RULES.filter { it.category == cat }
    fun getRulesBySeverity(sev: ThreatSeverity) = ALL_RULES.filter { it.severity == sev }
    fun getRuleById(id: String) = ALL_RULES.find { it.id == id }
}
