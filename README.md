# DroidEDR v2 — Android Endpoint Detection & Response

**MITRE ATT&CK Mobile | Self-Healing | Identify · Protect · Respond**

---

## Overview

DroidEDR v2 is a full Android EDR application that maps every detection to the MITRE ATT&CK Mobile framework. It provides real-time threat detection, a 7-day behavioral baseline, DNS-level interception via local VPN, and a self-healing watchdog that restores the EDR if killed.

---

## Feature Matrix

| Capability | Detail |
|---|---|
| **MITRE Rules** | 35 rules across all ATT&CK Mobile tactics |
| **Detect Phases** | Identify, Protect, Respond |
| **LotL Detection** | Shell abuse, su/magisk, masquerading, process injection |
| **DNS Security** | DoH via Cloudflare, tunneling detection, DGA, hijack, rebinding, NXDOMAIN storm |
| **DHCP Security** | Rogue server, starvation, Option 121 route injection (CVE-2024-3661) |
| **Brute Force** | Auth failure tracking, password spray, MFA fatigue |
| **Remote Access** | RAT package detection, ADB TCP monitoring, session hijacking |
| **CVEs** | 8 CVEs from 2021–2026 including 0-day heuristics |
| **Baseline** | 7-day rolling profile, 3σ/4σ deviation thresholds, z-score + IQR |
| **Self-Healing** | 30s watchdog, WorkManager backup, boot receiver, START_STICKY |
| **Auto-Response** | 16 response actions per threat category |
| **UI** | 10-tab Jetpack Compose dashboard |
| **Min Android** | 8.0 (API 26) |

---

## MITRE ATT&CK Coverage

### IDENTIFY
| ID | Technique | Category |
|---|---|---|
| T1623 | Command & Scripting Interpreter | LotL |
| T1624 | Event Triggered Execution | Persistence |
| T1631 | Process Injection via Shared Libraries | LotL |
| T1655 | Masquerading | LotL |
| T1437.001 | DNS Tunneling | C2 |
| T1637 | DGA — Dynamic Resolution | C2 |
| T1110.001 | Brute Force — Password Guessing | Credential |
| T1110.003 | Password Spraying | Credential |
| T1621 | MFA Request Generation | Credential |
| T1219 | Remote Access Software (RAT) | C2 |
| T1481 | Web Service C2 Abuse | C2 |
| T1219.ADB | ADB over TCP/IP | C2 |
| T1417 | Input Capture — Keylogging | Credential |
| T1416 | URI/Intent Hijacking | Credential |
| T1646 | Exfiltration over C2 | Exfil |
| T1532 | Archive Collected Data | Collection |
| T1626 | Abuse su/sudo | Privilege Escalation |
| T1541 | Foreground Persistence | Persistence |
| T1398 | Boot/Logon Init Scripts | Persistence |
| CVE-2023-4863 | libwebp Heap Overflow | Exploit |
| CVE-2026-HEUR | Zero-Day Heuristic | Exploit |

### PROTECT
| ID | Technique | Category |
|---|---|---|
| T1629 | Impair Defenses | Defense Evasion |
| T1599.DNS | DNS Hijacking | DNS |
| T1557.DHCP | DHCP Starvation/Rogue Server | DHCP |
| T1557.DHCP2 | DHCP Option 121 Injection | DHCP |
| T1219.ADB | ADB TCP | Remote Access |
| CVE-2024-3661 | TunnelVision VPN Bypass | Exploit |
| CVE-2024-0044 | Android Privilege Escalation | Exploit |
| CVE-2023-20963 | WorkSource Parcel PE | Exploit |
| CVE-2022-20465 | Lockscreen Bypass | Exploit |
| CVE-2021-39793 | GPU Driver OOB Write | Exploit |
| CVE-2025-0282 | Ivanti Stack Overflow RCE | Exploit |

### RESPOND
| ID | Technique | Category |
|---|---|---|
| T1563 | Remote Service Session Hijacking | Remote Access |
| T1599.REB | DNS Rebinding | DNS |
| T1646 | Exfiltration over C2 | Exfil |

---

## Self-Healing Architecture

```
┌─────────────────────────────────────────────────┐
│                 DroidEDR v2                     │
│                                                 │
│  ┌──────────────┐    ┌───────────────────────┐  │
│  │ EDRCoreService│    │    WatchdogWorker      │  │
│  │ (Foreground) │◄───│  (WorkManager 15min)  │  │
│  │ START_STICKY │    └───────────────────────┘  │
│  └──────┬───────┘                               │
│         │                ┌───────────────────┐  │
│  ┌──────▼───────┐        │   BootReceiver    │  │
│  │BaselineEngine│        │ (BOOT_COMPLETED)  │  │
│  │ 7-day profile│        └───────────────────┘  │
│  └──────────────┘                               │
│         │                ┌───────────────────┐  │
│  ┌──────▼───────┐        │  DeviceAdminRcvr  │  │
│  │DetectionEngine│       │  (Policy Control) │  │
│  │  35 MITRE    │        └───────────────────┘  │
│  │    rules     │                               │
│  └──────┬───────┘    ┌──────────────────────┐   │
│         │            │   DnsVpnService       │   │
│  ┌──────▼───────┐    │ DNS interception+DoH  │   │
│  │SelfHealingEng│    │ Tunneling/DGA detect  │   │
│  │ 16 responses │    └──────────────────────┘   │
│  └──────────────┘                               │
└─────────────────────────────────────────────────┘
```

---

## Quick Start

### Prerequisites
- Android Studio Hedgehog (2023.1+) or just JDK 17 + Android SDK
- Android device: API 26+ (Android 8.0+)
- Python 3.8+ for the build script

### Build & Install (One Command)

```bash
# Install via USB
python3 build_droidedr_v2.py --install

# Install via WiFi ADB
python3 build_droidedr_v2.py --install --ip 192.168.1.100

# Build only (produces APK in app/build/outputs/)
python3 build_droidedr_v2.py

# Build release APK
python3 build_droidedr_v2.py --release
```

### Manual Build (Android Studio)
1. Open `DroidEDRv2/` in Android Studio
2. Wait for Gradle sync
3. Build → Build APK(s) → Debug
4. Install: `adb install app/build/outputs/apk/debug/app-debug.apk`

---

## Post-Install Setup (One-Time)

1. **Accessibility Service**: Settings → Accessibility → DroidEDR → Enable
2. **VPN Permission**: Allow when prompted on first launch (DNS Shield)
3. **Device Admin**: Settings → Device Admin Apps → DroidEDR → Activate
4. **Battery Optimization**: Settings → Battery → DroidEDR → Don't Optimize
5. **Usage Stats**: Settings → Privacy → Usage Access → DroidEDR → Allow

---

## Architecture

```
com.droidedr/
├── DroidEDRApplication.kt       # App init, WorkManager setup
├── detection/
│   ├── MitreRulesEngine.kt      # 35 MITRE rules + alert data classes
│   ├── EDRCoreService.kt        # Foreground service + detection loop
│   └── EDRAccessibilityService  # Overlay/keylog monitoring
├── baseline/
│   └── BaselineEngine.kt        # 7-day profile, z-score deviation
├── healing/
│   └── SelfHealingEngine.kt     # Watchdog, response actions, boot persist
├── network/
│   └── DnsVpnService.kt         # DNS interception, DoH, DGA/tunnel detect
└── ui/
    └── MainActivity.kt          # 10-tab Jetpack Compose dashboard
```

---

## Response Actions

When a threat is detected, DroidEDR automatically executes appropriate responses:

| Action | Trigger |
|---|---|
| `BLOCK_NETWORK` | RAT detected, critical exfiltration |
| `RESTORE_DNS` | DNS hijack, DHCP attack |
| `KILL_PROCESS` | RAT, LotL shell abuse |
| `REVOKE_PERMISSIONS` | Keylogger, overlay attack |
| `QUARANTINE_APP` | RAT package |
| `RESTART_EDR` | Service killed (defense evasion) |
| `LOCK_DEVICE` | Brute force on lockscreen |
| `DISABLE_ADB` | ADB TCP port detected open |
| `ENABLE_STRICT_MODE` | Critical CVE, zero-day |
| `CAPTURE_FORENSICS` | All critical alerts |
| `NOTIFY_USER` | All alerts |
| `ENABLE_VPN` | DNS attack |
| `ESCALATE_ALERT` | High/Critical severity |

---

## Legal & Ethics

DroidEDR is designed for **defensive security** on devices you own or have explicit permission to monitor. Deploying on devices without authorization may violate applicable law. Always obtain proper consent before installation in enterprise environments.

---

*DroidEDR v2 — Built for Android 8.0+ · Kotlin + Jetpack Compose · MITRE ATT&CK Mobile*
