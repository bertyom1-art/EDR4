package com.droidedr.engine

/**
 * A rule as data. The v2.9 catalog (200 specs) lives in assets/rules_v2.9.json,
 * so growing 35 → 200 is editing config, not writing 200 classes. Each spec
 * names a [detector] whose logic is implemented once and reused across specs.
 */
data class RuleSpec(
    val id: String,               // e.g. "EX-104b"
    val detector: String,         // key into DetectorRegistry, e.g. "su_binary"
    val mitreTechnique: String,   // e.g. "T1633"
    val tactic: Tactic,
    val severity: Severity,
    val threshold: Double,        // recorded into every Detection this spec produces
    val plannedAction: String,    // what enforce mode WOULD do — recorded, never run here
    val enabled: Boolean = true,
    val description: String = ""
)

/**
 * A match. Detectors return this (or null for no-match). Note there is no
 * "execute" here — a detector describes what it saw and how far over the line it
 * was; the engine decides only whether to *log* it. Nothing enforces.
 */
data class Match(
    val summary: String,
    val evidenceJson: String,
    val observedValue: Double
)

/**
 * The single piece of detection logic behind one or more rule specs.
 * Implementations must be pure reads over [RuleContext]. Throwing is contained
 * by the engine and logged as a rule error, never a crash.
 */
interface Detector {
    val key: String
    fun evaluate(ctx: RuleContext): Match?
}

/** Central registry. Register built-in detectors at startup; ported ones plug in here. */
object DetectorRegistry {
    private val detectors = mutableMapOf<String, Detector>()

    fun register(detector: Detector) { detectors[detector.key] = detector }

    fun get(key: String): Detector? = detectors[key]

    fun registeredKeys(): Set<String> = detectors.keys.toSet()

    fun registerDefaults() {
        listOf(
            com.droidedr.engine.detectors.SuBinaryDetector(),
            com.droidedr.engine.detectors.AdbTcpDetector(),
            com.droidedr.engine.detectors.DhcpOption121Detector(),
            com.droidedr.engine.detectors.DnsTunnelingDetector(),
            com.droidedr.engine.detectors.RatPackageDetector(),
            com.droidedr.engine.detectors.AuthBruteForceDetector()
        ).forEach(::register)
    }
}
