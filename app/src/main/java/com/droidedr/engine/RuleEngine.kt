package com.droidedr.engine

import android.content.Context
import android.util.Log
import org.json.JSONArray
import java.io.InputStream

/**
 * DroidEDR v2.9 rule engine — OBSERVE build.
 *
 * Contract, enforced here and relied on everywhere else:
 *   1. Load rule specs (data).
 *   2. Each cycle, run every enabled spec's detector over an immutable [Signals]
 *      snapshot.
 *   3. Persist every match as a [Detection]. Record what enforce mode WOULD do.
 *   4. Never execute an enforcement action. The guard below is the only place an
 *      action could ever dispatch, and in this build it is unreachable.
 */
class RuleEngine(
    private val context: Context,
    private val dao: DetectionDao
) {
    private val specs = mutableListOf<RuleSpec>()

    fun loadCatalog(assetName: String = "rules_v2.9.json") {
        DetectorRegistry.registerDefaults()
        val parsed = context.assets.open(assetName).use(::parseSpecs)
        val known = DetectorRegistry.registeredKeys()
        specs.clear()
        parsed.forEach { spec ->
            if (spec.detector !in known) {
                // A ported spec with no detector yet: skip loudly, don't crash.
                Log.w(TAG, "Rule ${spec.id} references unimplemented detector '${spec.detector}' — skipped")
            } else {
                specs.add(spec)
            }
        }
        Log.i(TAG, "Loaded ${specs.count { it.enabled }} enabled rules (mode=${EnforcementMode.ACTIVE})")
    }

    /** Run one evaluation cycle. Returns how many matches were logged. */
    suspend fun runCycle(signals: Signals): Int {
        var logged = 0
        for (spec in specs) {
            if (!spec.enabled) continue
            val detector = DetectorRegistry.get(spec.detector) ?: continue
            val match = try {
                detector.evaluate(RuleContext(signals, spec.threshold))
            } catch (t: Throwable) {
                Log.e(TAG, "Rule ${spec.id} detector threw — treated as no-match", t)
                null
            } ?: continue

            val wouldEnforce = spec.plannedAction.isNotBlank() &&
                spec.plannedAction != "none"

            dao.insert(
                Detection(
                    ruleId = spec.id,
                    mitreTechnique = spec.mitreTechnique,
                    tactic = spec.tactic,
                    severity = spec.severity,
                    timestamp = signals.timestamp,
                    summary = match.summary,
                    evidenceJson = match.evidenceJson,
                    thresholdSnapshot = spec.threshold,
                    observedValue = match.observedValue,
                    wouldEnforce = wouldEnforce,
                    plannedAction = spec.plannedAction
                )
            )
            logged++

            // The single dispatch point. Unreachable in this build by design.
            if (wouldEnforce && EnforcementMode.enforcementAllowed()) {
                dispatchEnforcement(spec, match)
            }
        }
        return logged
    }

    private fun dispatchEnforcement(spec: RuleSpec, match: Match) {
        // Intentionally not implemented in the observe build. Graduating a rule to
        // enforce is a reviewed change per OBSERVE_MODE.md, not a runtime path.
        throw IllegalStateException(
            "Enforcement dispatch reached in an OBSERVE build for ${spec.id}. " +
                "This should be impossible — investigate EnforcementMode.ACTIVE."
        )
    }

    private fun parseSpecs(stream: InputStream): List<RuleSpec> {
        val json = stream.bufferedReader().readText()
        val arr = JSONArray(json)
        return (0 until arr.length()).map { i ->
            val o = arr.getJSONObject(i)
            RuleSpec(
                id = o.getString("id"),
                detector = o.getString("detector"),
                mitreTechnique = o.optString("mitre", "T0000"),
                tactic = runCatching { Tactic.valueOf(o.optString("tactic", "UNKNOWN")) }
                    .getOrDefault(Tactic.UNKNOWN),
                severity = runCatching { Severity.valueOf(o.optString("severity", "LOW")) }
                    .getOrDefault(Severity.LOW),
                threshold = o.optDouble("threshold", 1.0),
                plannedAction = o.optString("plannedAction", "none"),
                enabled = o.optBoolean("enabled", true),
                description = o.optString("description", "")
            )
        }
    }

    companion object { private const val TAG = "DroidEDR/Engine" }
}
