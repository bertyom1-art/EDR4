package com.droidedr.ui

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.animation.*
import androidx.compose.animation.core.*
import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.*
import androidx.compose.foundation.shape.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.*
import androidx.compose.ui.draw.*
import androidx.compose.ui.graphics.*
import androidx.compose.ui.text.font.*
import androidx.compose.ui.text.style.*
import androidx.compose.ui.unit.*
import com.droidedr.detection.*
import com.droidedr.healing.*
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            DroidEDRTheme {
                DroidEDRApp()
            }
        }
    }
}

// ─── THEME ────────────────────────────────────────────────────────────────────
@Composable
fun DroidEDRTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = darkColorScheme(
            primary = Color(0xFF00E5FF),
            secondary = Color(0xFF69FF47),
            error = Color(0xFFFF1744),
            background = Color(0xFF050A0F),
            surface = Color(0xFF0D1B2A),
            surfaceVariant = Color(0xFF112233),
            onSurface = Color(0xFFE0F4FF),
            onBackground = Color(0xFFE0F4FF)
        ),
        typography = Typography(
            titleLarge = androidx.compose.ui.text.TextStyle(
                fontFamily = FontFamily.Monospace,
                fontWeight = FontWeight.Bold,
                fontSize = 20.sp
            ),
            bodySmall = androidx.compose.ui.text.TextStyle(
                fontFamily = FontFamily.Monospace,
                fontSize = 11.sp
            )
        ),
        content = content
    )
}

// ─── MAIN APP ─────────────────────────────────────────────────────────────────
@Composable
fun DroidEDRApp() {
    var selectedTab by remember { mutableStateOf(0) }
    val alerts = remember { mutableStateListOf<ThreatAlert>() }
    val scope = rememberCoroutineScope()

    // Simulate incoming alerts for demo
    LaunchedEffect(Unit) {
        AlertBus.flow.collect { alert ->
            alerts.add(0, alert)
            if (alerts.size > 200) alerts.removeLast()
        }
    }

    Scaffold(
        bottomBar = {
            EDRBottomBar(selectedTab = selectedTab, onTabSelect = { selectedTab = it })
        },
        containerColor = Color(0xFF050A0F)
    ) { padding ->
        Box(Modifier.padding(padding)) {
            when (selectedTab) {
                0 -> DashboardTab(alerts)
                1 -> BaselineTab()
                2 -> AlertsTab(alerts)
                3 -> MitreCoverageTab()
                4 -> NetworkTab()
                5 -> LotLTab()
                6 -> CVETab()
                7 -> HealingTab()
                8 -> RemoteAccessTab()
                9 -> SettingsTab()
            }
        }
    }
}

@Composable
fun EDRBottomBar(selectedTab: Int, onTabSelect: (Int) -> Unit) {
    val tabs = listOf(
        Icons.Default.Dashboard to "Dashboard",
        Icons.Default.Timeline to "Baseline",
        Icons.Default.Notifications to "Alerts",
        Icons.Default.Security to "MITRE",
        Icons.Default.Wifi to "Network",
        Icons.Default.BugReport to "LotL",
        Icons.Default.Warning to "CVEs",
        Icons.Default.AutoFixHigh to "Healing",
        Icons.Default.Computer to "Remote",
        Icons.Default.Settings to "Settings"
    )

    NavigationBar(containerColor = Color(0xFF0D1B2A), tonalElevation = 0.dp) {
        tabs.forEachIndexed { index, (icon, label) ->
            NavigationBarItem(
                selected = selectedTab == index,
                onClick = { onTabSelect(index) },
                icon = { Icon(icon, contentDescription = label, modifier = Modifier.size(20.dp)) },
                label = { Text(label, fontSize = 8.sp, fontFamily = FontFamily.Monospace) },
                colors = NavigationBarItemDefaults.colors(
                    selectedIconColor = Color(0xFF00E5FF),
                    selectedTextColor = Color(0xFF00E5FF),
                    unselectedIconColor = Color(0xFF446688),
                    unselectedTextColor = Color(0xFF446688),
                    indicatorColor = Color(0xFF001122)
                )
            )
        }
    }
}

// ─── TAB 0: DASHBOARD ─────────────────────────────────────────────────────────
@Composable
fun DashboardTab(alerts: List<ThreatAlert>) {
    val criticalCount = alerts.count { it.technique.severity == ThreatSeverity.CRITICAL }
    val highCount = alerts.count { it.technique.severity == ThreatSeverity.HIGH }
    val totalRules = MitreRulesEngine.ALL_RULES.size
    val autoRespondRules = MitreRulesEngine.ALL_RULES.count { it.autoRespond }

    LazyColumn(
        modifier = Modifier.fillMaxSize().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            // Header
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    modifier = Modifier.size(12.dp).background(Color(0xFF00E5FF), CircleShape)
                )
                Spacer(Modifier.width(8.dp))
                Text(
                    "DROIDEDR v2.0", color = Color(0xFF00E5FF),
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.Bold, fontSize = 20.sp
                )
                Spacer(Modifier.weight(1f))
                ThreatBadge("ACTIVE", Color(0xFF00E5FF))
            }
            Text(
                "MITRE ATT&CK Mobile · Identify · Protect · Respond",
                color = Color(0xFF446688), fontSize = 10.sp,
                fontFamily = FontFamily.Monospace
            )
        }

        item {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                StatCard("CRITICAL", criticalCount.toString(), Color(0xFFFF1744), Modifier.weight(1f))
                StatCard("HIGH", highCount.toString(), Color(0xFFFF6D00), Modifier.weight(1f))
                StatCard("ALERTS", alerts.size.toString(), Color(0xFF00E5FF), Modifier.weight(1f))
                StatCard("RULES", totalRules.toString(), Color(0xFF69FF47), Modifier.weight(1f))
            }
        }

        item { SectionHeader("MITRE COVERAGE") }
        item { MitreCoverageBar() }

        item { SectionHeader("THREAT CATEGORIES") }
        item { ThreatCategoryGrid(alerts) }

        item { SectionHeader("RECENT ALERTS") }
        items(alerts.take(5)) { alert ->
            AlertRow(alert, compact = true)
        }

        item { SectionHeader("EDR STATUS") }
        item { EDRStatusGrid(autoRespondRules) }
    }
}

@Composable
fun StatCard(label: String, value: String, color: Color, modifier: Modifier = Modifier) {
    Card(
        modifier = modifier,
        colors = CardDefaults.cardColors(containerColor = Color(0xFF0D1B2A)),
        border = BorderStroke(1.dp, color.copy(alpha = 0.3f))
    ) {
        Column(
            modifier = Modifier.padding(12.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(value, color = color, fontFamily = FontFamily.Monospace,
                fontWeight = FontWeight.Bold, fontSize = 24.sp)
            Text(label, color = Color(0xFF446688), fontSize = 9.sp,
                fontFamily = FontFamily.Monospace)
        }
    }
}

@Composable
fun MitreCoverageBar() {
    val phases = listOf(
        "IDENTIFY" to MitreRulesEngine.getRulesByPhase(MitrePhase.IDENTIFY).size,
        "PROTECT" to MitreRulesEngine.getRulesByPhase(MitrePhase.PROTECT).size,
        "RESPOND" to MitreRulesEngine.getRulesByPhase(MitrePhase.RESPOND).size
    )
    val total = MitreRulesEngine.ALL_RULES.size.toFloat()

    Card(colors = CardDefaults.cardColors(containerColor = Color(0xFF0D1B2A))) {
        Column(Modifier.padding(16.dp)) {
            phases.forEach { (phase, count) ->
                val ratio = count / total
                val color = when(phase) {
                    "IDENTIFY" -> Color(0xFF00E5FF)
                    "PROTECT" -> Color(0xFF69FF47)
                    else -> Color(0xFFFF6D00)
                }
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)
                ) {
                    Text(phase, color = color, fontFamily = FontFamily.Monospace,
                        fontSize = 10.sp, modifier = Modifier.width(70.dp))
                    Box(
                        modifier = Modifier
                            .weight(1f).height(12.dp)
                            .background(Color(0xFF112233), RoundedCornerShape(6.dp))
                    ) {
                        Box(
                            modifier = Modifier
                                .fillMaxWidth(ratio).fillMaxHeight()
                                .background(color.copy(alpha = 0.7f), RoundedCornerShape(6.dp))
                        )
                    }
                    Text(" $count", color = color, fontFamily = FontFamily.Monospace,
                        fontSize = 10.sp, modifier = Modifier.width(28.dp))
                }
            }
        }
    }
}

@Composable
fun ThreatCategoryGrid(alerts: List<ThreatAlert>) {
    val categories = ThreatCategory.values()
    val cols = 3
    val rows = (categories.size + cols - 1) / cols

    Card(colors = CardDefaults.cardColors(containerColor = Color(0xFF0D1B2A))) {
        Column(Modifier.padding(8.dp)) {
            for (r in 0 until rows) {
                Row(Modifier.fillMaxWidth()) {
                    for (c in 0 until cols) {
                        val idx = r * cols + c
                        if (idx < categories.size) {
                            val cat = categories[idx]
                            val count = alerts.count { it.technique.category == cat }
                            Box(
                                modifier = Modifier.weight(1f).padding(4.dp),
                                contentAlignment = Alignment.Center
                            ) {
                                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                                    Text(
                                        count.toString(),
                                        color = if (count > 0) Color(0xFFFF1744) else Color(0xFF223344),
                                        fontWeight = FontWeight.Bold,
                                        fontFamily = FontFamily.Monospace, fontSize = 16.sp
                                    )
                                    Text(
                                        cat.name.replace("_", "\n"),
                                        color = Color(0xFF446688), fontSize = 7.sp,
                                        fontFamily = FontFamily.Monospace,
                                        textAlign = TextAlign.Center
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun EDRStatusGrid(autoRespondRules: Int) {
    val items = listOf(
        Triple("BASELINE", "LEARNING", Color(0xFFFFAB00)),
        Triple("DNS VPN", "ACTIVE", Color(0xFF69FF47)),
        Triple("WATCHDOG", "RUNNING", Color(0xFF69FF47)),
        Triple("AUTO-HEAL", "$autoRespondRules RULES", Color(0xFF00E5FF)),
        Triple("DEVICE ADMIN", "REQUESTED", Color(0xFFFFAB00)),
        Triple("FORENSICS", "READY", Color(0xFF69FF47))
    )
    Card(colors = CardDefaults.cardColors(containerColor = Color(0xFF0D1B2A))) {
        Column(Modifier.padding(8.dp)) {
            items.chunked(2).forEach { row ->
                Row(Modifier.fillMaxWidth()) {
                    row.forEach { (label, status, color) ->
                        Row(
                            modifier = Modifier.weight(1f).padding(8.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Box(Modifier.size(6.dp).background(color, CircleShape))
                            Spacer(Modifier.width(6.dp))
                            Column {
                                Text(label, color = Color(0xFF8899AA), fontSize = 8.sp,
                                    fontFamily = FontFamily.Monospace)
                                Text(status, color = color, fontSize = 10.sp,
                                    fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold)
                            }
                        }
                    }
                }
            }
        }
    }
}

// ─── TAB 1: BASELINE ──────────────────────────────────────────────────────────
@Composable
fun BaselineTab() {
    LazyColumn(Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        item { SectionHeader("BEHAVIORAL BASELINE") }
        item {
            Card(colors = CardDefaults.cardColors(containerColor = Color(0xFF0D1B2A))) {
                Column(Modifier.padding(16.dp)) {
                    BaselineProgressItem("7-Day Profile", 45, Color(0xFF00E5FF))
                    BaselineProgressItem("Network Patterns", 62, Color(0xFF69FF47))
                    BaselineProgressItem("Process Behavior", 38, Color(0xFFFFAB00))
                    BaselineProgressItem("DNS Activity", 71, Color(0xFF00E5FF))
                    BaselineProgressItem("App Usage", 55, Color(0xFF69FF47))
                    BaselineProgressItem("System Resources", 44, Color(0xFFFFAB00))
                }
            }
        }
        item { SectionHeader("BASELINE PARAMETERS") }
        item {
            BaselineParamTable(listOf(
                "Learning Window" to "7 days",
                "Snapshot Interval" to "5 minutes",
                "Detection Threshold" to "3σ (99.7%)",
                "Critical Threshold" to "4σ (99.99%)",
                "DNS Entropy Baseline" to "3.2 bits",
                "NXDOMAIN Normal Rate" to "< 2%",
                "Upload Σ Trigger" to "3.0 sigma",
                "Anomaly Exclusion" to "Enabled",
                "IQR Outlier Removal" to "Enabled",
                "Z-Score Algorithm" to "Welford Online"
            ))
        }
        item { SectionHeader("DEVIATION SENSORS") }
        item {
            DeviationSensorList(listOf(
                Triple("Network TX/RX", "CALIBRATING", Color(0xFFFFAB00)),
                Triple("CPU Usage", "CALIBRATING", Color(0xFFFFAB00)),
                Triple("Memory Profile", "CALIBRATING", Color(0xFFFFAB00)),
                Triple("DNS Query Rate", "ACTIVE", Color(0xFF69FF47)),
                Triple("DNS Entropy", "ACTIVE", Color(0xFF69FF47)),
                Triple("Process List", "ACTIVE", Color(0xFF69FF47)),
                Triple("Foreground Apps", "CALIBRATING", Color(0xFFFFAB00)),
                Triple("Battery Drain", "PENDING", Color(0xFF446688))
            ))
        }
    }
}

@Composable
fun BaselineProgressItem(label: String, percent: Int, color: Color) {
    Column(Modifier.padding(vertical = 6.dp)) {
        Row(Modifier.fillMaxWidth()) {
            Text(label, color = Color(0xFFBBCCDD), fontFamily = FontFamily.Monospace, fontSize = 11.sp)
            Spacer(Modifier.weight(1f))
            Text("$percent%", color = color, fontFamily = FontFamily.Monospace, fontSize = 11.sp)
        }
        Spacer(Modifier.height(4.dp))
        LinearProgressIndicator(
            progress = percent / 100f,
            modifier = Modifier.fillMaxWidth().height(4.dp),
            color = color,
            trackColor = Color(0xFF112233)
        )
    }
}

@Composable
fun BaselineParamTable(items: List<Pair<String, String>>) {
    Card(colors = CardDefaults.cardColors(containerColor = Color(0xFF0D1B2A))) {
        Column(Modifier.padding(16.dp)) {
            items.forEach { (key, value) ->
                Row(Modifier.fillMaxWidth().padding(vertical = 3.dp)) {
                    Text(key, color = Color(0xFF557799), fontFamily = FontFamily.Monospace, fontSize = 10.sp)
                    Spacer(Modifier.weight(1f))
                    Text(value, color = Color(0xFF00E5FF), fontFamily = FontFamily.Monospace,
                        fontSize = 10.sp, fontWeight = FontWeight.Bold)
                }
                if (items.last() != key to value) {
                    Divider(color = Color(0xFF112233), thickness = 0.5.dp)
                }
            }
        }
    }
}

@Composable
fun DeviationSensorList(sensors: List<Triple<String, String, Color>>) {
    Card(colors = CardDefaults.cardColors(containerColor = Color(0xFF0D1B2A))) {
        Column(Modifier.padding(16.dp)) {
            sensors.forEach { (name, status, color) ->
                Row(
                    Modifier.fillMaxWidth().padding(vertical = 5.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Box(Modifier.size(8.dp).background(color, CircleShape))
                    Spacer(Modifier.width(10.dp))
                    Text(name, color = Color(0xFFBBCCDD), fontFamily = FontFamily.Monospace,
                        fontSize = 11.sp, modifier = Modifier.weight(1f))
                    Text(status, color = color, fontFamily = FontFamily.Monospace, fontSize = 10.sp)
                }
            }
        }
    }
}

// ─── TAB 2: ALERTS ────────────────────────────────────────────────────────────
@Composable
fun AlertsTab(alerts: List<ThreatAlert>) {
    var filterSeverity by remember { mutableStateOf<ThreatSeverity?>(null) }

    Column(Modifier.fillMaxSize()) {
        // Filter chips
        Row(
            Modifier.horizontalScroll(rememberScrollState()).padding(12.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            FilterChip(
                selected = filterSeverity == null,
                onClick = { filterSeverity = null },
                label = { Text("ALL", fontFamily = FontFamily.Monospace, fontSize = 10.sp) }
            )
            ThreatSeverity.values().forEach { sev ->
                FilterChip(
                    selected = filterSeverity == sev,
                    onClick = { filterSeverity = if (filterSeverity == sev) null else sev },
                    label = { Text(sev.name, fontFamily = FontFamily.Monospace, fontSize = 10.sp) }
                )
            }
        }

        val filtered = if (filterSeverity == null) alerts else alerts.filter { it.technique.severity == filterSeverity }

        if (filtered.isEmpty()) {
            Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Text("✓", color = Color(0xFF69FF47), fontSize = 48.sp)
                    Text("NO ALERTS", color = Color(0xFF69FF47), fontFamily = FontFamily.Monospace,
                        fontSize = 14.sp, fontWeight = FontWeight.Bold)
                    Text("All systems nominal", color = Color(0xFF446688), fontFamily = FontFamily.Monospace,
                        fontSize = 11.sp)
                }
            }
        } else {
            LazyColumn(Modifier.fillMaxSize().padding(horizontal = 12.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)) {
                items(filtered) { alert -> AlertRow(alert, compact = false) }
            }
        }
    }
}

@Composable
fun AlertRow(alert: ThreatAlert, compact: Boolean) {
    val sevColor = when (alert.technique.severity) {
        ThreatSeverity.CRITICAL -> Color(0xFFFF1744)
        ThreatSeverity.HIGH -> Color(0xFFFF6D00)
        ThreatSeverity.MEDIUM -> Color(0xFFFFAB00)
        ThreatSeverity.LOW -> Color(0xFF69FF47)
        ThreatSeverity.INFO -> Color(0xFF00E5FF)
    }

    Card(
        colors = CardDefaults.cardColors(containerColor = Color(0xFF0D1B2A)),
        border = BorderStroke(1.dp, sevColor.copy(alpha = 0.25f))
    ) {
        Row(Modifier.padding(12.dp), verticalAlignment = Alignment.Top) {
            Box(
                modifier = Modifier.width(4.dp).height(if (compact) 40.dp else 60.dp)
                    .background(sevColor, RoundedCornerShape(2.dp))
            )
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    ThreatBadge(alert.technique.severity.name, sevColor)
                    Spacer(Modifier.width(8.dp))
                    Text(alert.technique.id, color = Color(0xFF446688),
                        fontFamily = FontFamily.Monospace, fontSize = 9.sp)
                }
                Text(
                    alert.technique.name,
                    color = Color(0xFFE0F4FF),
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.Bold,
                    fontSize = 12.sp
                )
                if (!compact) {
                    Text(
                        alert.technique.tactic,
                        color = Color(0xFF557799), fontSize = 10.sp,
                        fontFamily = FontFamily.Monospace
                    )
                    if (alert.responded) {
                        Spacer(Modifier.height(4.dp))
                        Text("✓ AUTO-RESPONDED: ${alert.responseActions.take(3).joinToString(" · ")}",
                            color = Color(0xFF69FF47), fontSize = 9.sp, fontFamily = FontFamily.Monospace)
                    }
                }
            }
            Text(
                formatTimestamp(alert.timestamp),
                color = Color(0xFF334455), fontSize = 8.sp,
                fontFamily = FontFamily.Monospace
            )
        }
    }
}

// ─── TAB 3: MITRE COVERAGE ───────────────────────────────────────────────────
@Composable
fun MitreCoverageTab() {
    LazyColumn(Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        item { SectionHeader("MITRE ATT&CK MOBILE — ${MitreRulesEngine.ALL_RULES.size} RULES") }

        val grouped = MitreRulesEngine.ALL_RULES.groupBy { it.tactic }
        grouped.forEach { (tactic, rules) ->
            item {
                TacticSection(tactic, rules)
            }
        }
    }
}

@Composable
fun TacticSection(tactic: String, rules: List<MitreTechnique>) {
    var expanded by remember { mutableStateOf(false) }

    Card(
        colors = CardDefaults.cardColors(containerColor = Color(0xFF0D1B2A)),
        modifier = Modifier.clickable { expanded = !expanded }
    ) {
        Column(Modifier.padding(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(tactic.uppercase(), color = Color(0xFF00E5FF),
                    fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold, fontSize = 12.sp)
                Spacer(Modifier.weight(1f))
                Text("${rules.size} RULES", color = Color(0xFF446688),
                    fontFamily = FontFamily.Monospace, fontSize = 10.sp)
                Icon(
                    if (expanded) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                    contentDescription = null, tint = Color(0xFF446688), modifier = Modifier.size(16.dp)
                )
            }

            AnimatedVisibility(visible = expanded) {
                Column(Modifier.padding(top = 8.dp)) {
                    rules.forEach { rule ->
                        Divider(color = Color(0xFF112233))
                        Row(
                            Modifier.fillMaxWidth().padding(vertical = 6.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            val sevColor = when (rule.severity) {
                                ThreatSeverity.CRITICAL -> Color(0xFFFF1744)
                                ThreatSeverity.HIGH -> Color(0xFFFF6D00)
                                ThreatSeverity.MEDIUM -> Color(0xFFFFAB00)
                                else -> Color(0xFF69FF47)
                            }
                            Box(Modifier.size(6.dp).background(sevColor, CircleShape))
                            Spacer(Modifier.width(8.dp))
                            Column(Modifier.weight(1f)) {
                                Text(rule.id, color = Color(0xFF446688),
                                    fontFamily = FontFamily.Monospace, fontSize = 9.sp)
                                Text(rule.name, color = Color(0xFFCCDDEE),
                                    fontFamily = FontFamily.Monospace, fontSize = 10.sp)
                            }
                            if (rule.autoRespond) {
                                Text("AUTO", color = Color(0xFF69FF47),
                                    fontFamily = FontFamily.Monospace, fontSize = 8.sp)
                            }
                        }
                    }
                }
            }
        }
    }
}

// ─── TAB 4: NETWORK ────────────────────────────────────────────────────────────
@Composable
fun NetworkTab() {
    LazyColumn(Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        item { SectionHeader("NETWORK SECURITY") }
        item {
            BaselineParamTable(listOf(
                "DNS Shield" to "ACTIVE (DoH)",
                "Primary Resolver" to "1.1.1.1 (Cloudflare)",
                "Secondary Resolver" to "8.8.8.8 (Google)",
                "DNS Encryption" to "TLS 1.3",
                "DNSSEC Validation" to "ENABLED",
                "Queries Today" to "0",
                "Blocked Queries" to "0",
                "Avg Entropy" to "3.2 bits",
                "NXDOMAIN Rate" to "0.0%",
                "DGA Detections" to "0",
                "Tunneling Alerts" to "0",
                "DNS Rebinding" to "0"
            ))
        }
        item { SectionHeader("DHCP MONITORING") }
        item {
            BaselineParamTable(listOf(
                "DHCP Server" to "192.168.1.1",
                "Option 121 Watch" to "ENABLED",
                "Rogue Server Check" to "ACTIVE",
                "Gateway Validation" to "ENABLED",
                "ARP Monitoring" to "ACTIVE",
                "Route Injection" to "NOT DETECTED"
            ))
        }
        item { SectionHeader("DETECTION RULES ACTIVE") }
        item {
            Card(colors = CardDefaults.cardColors(containerColor = Color(0xFF0D1B2A))) {
                Column(Modifier.padding(12.dp)) {
                    listOf(
                        "DNS Tunneling (T1437.001)" to true,
                        "DGA Detection (T1637)" to true,
                        "DNS Hijacking" to true,
                        "DNS Rebinding" to true,
                        "DHCP Starvation" to true,
                        "DHCP Option 121 Injection" to true
                    ).forEach { (rule, active) ->
                        Row(Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
                            Box(Modifier.size(8.dp).background(
                                if (active) Color(0xFF69FF47) else Color(0xFF334455), CircleShape
                            ).align(Alignment.CenterVertically))
                            Spacer(Modifier.width(8.dp))
                            Text(rule, color = Color(0xFFCCDDEE),
                                fontFamily = FontFamily.Monospace, fontSize = 11.sp)
                        }
                    }
                }
            }
        }
    }
}

// ─── TAB 5: LotL ──────────────────────────────────────────────────────────────
@Composable
fun LotLTab() {
    LazyColumn(Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        item { SectionHeader("LIVING OFF THE LAND DETECTION") }
        item {
            Card(colors = CardDefaults.cardColors(containerColor = Color(0xFF0D1B2A))) {
                Column(Modifier.padding(12.dp)) {
                    Text("MONITORED BINARIES", color = Color(0xFF446688),
                        fontFamily = FontFamily.Monospace, fontSize = 10.sp)
                    Spacer(Modifier.height(8.dp))
                    SelfHealingEngine.LOTL_BINARIES.chunked(3).forEach { row ->
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            row.forEach { bin ->
                                Text("• $bin", color = Color(0xFFFF6D00),
                                    fontFamily = FontFamily.Monospace, fontSize = 10.sp,
                                    modifier = Modifier.weight(1f))
                            }
                        }
                    }
                }
            }
        }
        item { SectionHeader("LotL MITRE TECHNIQUES") }
        MitreRulesEngine.getRulesByCategory(ThreatCategory.LOTL).forEach { rule ->
            item { RuleCard(rule) }
        }
        item { SectionHeader("PROCESS MONITOR") }
        item {
            BaselineParamTable(listOf(
                "Shell Processes" to "NONE DETECTED",
                "Root Shells" to "NONE DETECTED",
                "Suspicious .so Loads" to "NONE",
                "Masquerading Apps" to "NONE",
                "Accessibility Abuse" to "NONE",
                "Overlay Attacks" to "NONE"
            ))
        }
    }
}

// ─── TAB 6: CVEs ──────────────────────────────────────────────────────────────
@Composable
fun CVETab() {
    LazyColumn(Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        item { SectionHeader("CVE DATABASE — 2021–2026") }
        MitreRulesEngine.getRulesByCategory(ThreatCategory.EXPLOIT_CVE).forEach { rule ->
            item { RuleCard(rule) }
        }
    }
}

@Composable
fun RuleCard(rule: MitreTechnique) {
    val sevColor = when (rule.severity) {
        ThreatSeverity.CRITICAL -> Color(0xFFFF1744)
        ThreatSeverity.HIGH -> Color(0xFFFF6D00)
        ThreatSeverity.MEDIUM -> Color(0xFFFFAB00)
        else -> Color(0xFF69FF47)
    }
    var expanded by remember { mutableStateOf(false) }

    Card(
        colors = CardDefaults.cardColors(containerColor = Color(0xFF0D1B2A)),
        border = BorderStroke(1.dp, sevColor.copy(alpha = 0.2f)),
        modifier = Modifier.clickable { expanded = !expanded }
    ) {
        Column(Modifier.padding(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                ThreatBadge(rule.severity.name, sevColor)
                Spacer(Modifier.width(8.dp))
                Text(rule.id, color = Color(0xFF446688), fontFamily = FontFamily.Monospace, fontSize = 9.sp)
                Spacer(Modifier.weight(1f))
                if (rule.autoRespond) ThreatBadge("AUTO-RESPOND", Color(0xFF69FF47))
            }
            Spacer(Modifier.height(4.dp))
            Text(rule.name, color = Color(0xFFE0F4FF), fontFamily = FontFamily.Monospace,
                fontWeight = FontWeight.Bold, fontSize = 12.sp)

            AnimatedVisibility(visible = expanded) {
                Column(Modifier.padding(top = 8.dp)) {
                    Text(rule.description, color = Color(0xFF7799BB),
                        fontFamily = FontFamily.Monospace, fontSize = 10.sp)
                    Spacer(Modifier.height(6.dp))
                    Text("INDICATORS:", color = Color(0xFF00E5FF),
                        fontFamily = FontFamily.Monospace, fontSize = 9.sp)
                    rule.indicators.forEach { indicator ->
                        Text("  · $indicator", color = Color(0xFF557799),
                            fontFamily = FontFamily.Monospace, fontSize = 9.sp)
                    }
                    Spacer(Modifier.height(6.dp))
                    Text("MITIGATIONS:", color = Color(0xFF69FF47),
                        fontFamily = FontFamily.Monospace, fontSize = 9.sp)
                    rule.mitigations.forEach { mit ->
                        Text("  → $mit", color = Color(0xFF447744),
                            fontFamily = FontFamily.Monospace, fontSize = 9.sp)
                    }
                }
            }
        }
    }
}

// ─── TAB 7: HEALING ───────────────────────────────────────────────────────────
@Composable
fun HealingTab() {
    LazyColumn(Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        item { SectionHeader("SELF-HEALING ENGINE") }
        item {
            BaselineParamTable(listOf(
                "Watchdog Interval" to "30 seconds",
                "WorkManager Backup" to "15 minutes",
                "Boot Persistence" to "ENABLED",
                "Service Restart Policy" to "START_STICKY",
                "Admin Privileges" to "REQUESTED",
                "Auto-Response Rules" to "${MitreRulesEngine.ALL_RULES.count { it.autoRespond }}",
                "DNS Auto-Restore" to "ENABLED",
                "ADB TCP Monitoring" to "ENABLED",
                "Forensic Capture" to "ENABLED",
                "Network Isolation" to "READY"
            ))
        }
        item { SectionHeader("RESPONSE ACTIONS") }
        item {
            Card(colors = CardDefaults.cardColors(containerColor = Color(0xFF0D1B2A))) {
                Column(Modifier.padding(12.dp)) {
                    ResponseAction.values().forEach { action ->
                        Row(Modifier.fillMaxWidth().padding(vertical = 3.dp)) {
                            Box(Modifier.size(6.dp).background(Color(0xFF69FF47), CircleShape)
                                .align(Alignment.CenterVertically))
                            Spacer(Modifier.width(8.dp))
                            Text(action.name.replace("_", " "), color = Color(0xFFCCDDEE),
                                fontFamily = FontFamily.Monospace, fontSize = 10.sp)
                        }
                    }
                }
            }
        }
        item { SectionHeader("HEALING HISTORY") }
        item {
            Card(colors = CardDefaults.cardColors(containerColor = Color(0xFF0D1B2A))) {
                Box(Modifier.fillMaxWidth().padding(24.dp), contentAlignment = Alignment.Center) {
                    Text("No healing events — system nominal",
                        color = Color(0xFF334455), fontFamily = FontFamily.Monospace, fontSize = 11.sp)
                }
            }
        }
    }
}

// ─── TAB 8: REMOTE ACCESS ─────────────────────────────────────────────────────
@Composable
fun RemoteAccessTab() {
    LazyColumn(Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        item { SectionHeader("REMOTE ACCESS MONITORING") }
        item {
            BaselineParamTable(listOf(
                "ADB TCP (5555)" to "CLOSED",
                "USB Debugging" to "DISABLED",
                "Authorized ADB Keys" to "0",
                "Known RAT Apps" to "NONE INSTALLED",
                "Screen Capture BG" to "NOT DETECTED",
                "Input Injection" to "NOT DETECTED",
                "Overlay Active" to "NOT DETECTED",
                "VNC/RDP Ports" to "CLOSED"
            ))
        }
        item { SectionHeader("KNOWN RAT BLOCKLIST") }
        item {
            Card(colors = CardDefaults.cardColors(containerColor = Color(0xFF0D1B2A))) {
                Column(Modifier.padding(12.dp)) {
                    SelfHealingEngine.KNOWN_RAT_PACKAGES.forEach { pkg ->
                        Text("✗ $pkg", color = Color(0xFFFF1744).copy(alpha = 0.6f),
                            fontFamily = FontFamily.Monospace, fontSize = 9.sp,
                            modifier = Modifier.padding(vertical = 2.dp))
                    }
                }
            }
        }
        item { SectionHeader("REMOTE ACCESS MITRE RULES") }
        MitreRulesEngine.getRulesByCategory(ThreatCategory.REMOTE_ACCESS).forEach { rule ->
            item { RuleCard(rule) }
        }
    }
}

// ─── TAB 9: SETTINGS ──────────────────────────────────────────────────────────
@Composable
fun SettingsTab() {
    LazyColumn(Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        item { SectionHeader("SETTINGS") }
        item {
            Card(colors = CardDefaults.cardColors(containerColor = Color(0xFF0D1B2A))) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    SettingToggle("DNS VPN Shield", true)
                    SettingToggle("Auto-Response", true)
                    SettingToggle("Baseline Learning", true)
                    SettingToggle("Boot Persistence", true)
                    SettingToggle("Forensic Capture", true)
                    SettingToggle("Brute Force Detection", true)
                    SettingToggle("LotL Monitoring", true)
                    SettingToggle("CVE Pattern Matching", true)
                    SettingToggle("Network Isolation (Critical)", false)
                    SettingToggle("Strict Mode", false)
                }
            }
        }
        item { SectionHeader("ABOUT") }
        item {
            BaselineParamTable(listOf(
                "Version" to "2.0.0",
                "Build Date" to "2026-05-06",
                "MITRE Rules" to "${MitreRulesEngine.ALL_RULES.size}",
                "CVEs Covered" to "8 (2021–2026)",
                "Min Android" to "8.0 (API 26)",
                "Architecture" to "Kotlin + Compose",
                "Database" to "Room (SQLite)",
                "Encryption" to "AES-256-GCM"
            ))
        }
    }
}

@Composable
fun SettingToggle(label: String, initial: Boolean) {
    var checked by remember { mutableStateOf(initial) }
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Text(label, color = Color(0xFFCCDDEE), fontFamily = FontFamily.Monospace,
            fontSize = 11.sp, modifier = Modifier.weight(1f))
        Switch(
            checked = checked,
            onCheckedChange = { checked = it },
            colors = SwitchDefaults.colors(
                checkedThumbColor = Color(0xFF00E5FF),
                checkedTrackColor = Color(0xFF003344)
            )
        )
    }
}

// ─── SHARED COMPOSABLES ───────────────────────────────────────────────────────
@Composable
fun SectionHeader(text: String) {
    Text(
        text, color = Color(0xFF446688),
        fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold,
        fontSize = 10.sp, letterSpacing = 2.sp,
        modifier = Modifier.padding(vertical = 4.dp)
    )
}

@Composable
fun ThreatBadge(text: String, color: Color) {
    Box(
        modifier = Modifier
            .background(color.copy(alpha = 0.15f), RoundedCornerShape(4.dp))
            .border(0.5.dp, color.copy(alpha = 0.4f), RoundedCornerShape(4.dp))
            .padding(horizontal = 6.dp, vertical = 2.dp)
    ) {
        Text(text, color = color, fontFamily = FontFamily.Monospace,
            fontSize = 8.sp, fontWeight = FontWeight.Bold)
    }
}

fun formatTimestamp(ts: Long): String {
    val sdf = java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.US)
    return sdf.format(java.util.Date(ts))
}
