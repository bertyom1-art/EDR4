package com.droidedr.engine

import androidx.room.Entity
import androidx.room.PrimaryKey

/** MITRE ATT&CK Mobile tactic buckets used for grouping in the dashboard. */
enum class Tactic {
    INITIAL_ACCESS, EXECUTION, PERSISTENCE, PRIVILEGE_ESCALATION,
    DEFENSE_EVASION, CREDENTIAL_ACCESS, DISCOVERY, LATERAL_MOVEMENT,
    COLLECTION, COMMAND_AND_CONTROL, EXFILTRATION, IMPACT, UNKNOWN
}

enum class Severity { INFO, LOW, MEDIUM, HIGH, CRITICAL }

/**
 * A single observation. One row per rule match.
 *
 * Everything the engine knows about why a rule fired lives here so a match can
 * be validated after the fact without re-running anything:
 *  - [evidenceJson]        what the detector saw
 *  - [thresholdSnapshot]   the threshold in force at match time (recorded, not hidden)
 *  - [observedValue]       the value that crossed it
 *  - [wouldEnforce]        true if this match WOULD have triggered an action in enforce mode
 *  - [plannedAction]       the action that was recorded-but-not-executed
 */
@Entity(tableName = "detections")
data class Detection(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val ruleId: String,
    val mitreTechnique: String,
    val tactic: Tactic,
    val severity: Severity,
    val timestamp: Long,
    val summary: String,
    val evidenceJson: String,
    val thresholdSnapshot: Double,
    val observedValue: Double,
    val wouldEnforce: Boolean,
    val plannedAction: String,
    val mode: EnforcementMode = EnforcementMode.ACTIVE
)
