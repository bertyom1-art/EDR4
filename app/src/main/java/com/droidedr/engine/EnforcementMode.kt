package com.droidedr.engine

/**
 * DroidEDR v2.9 — enforcement posture.
 *
 * This build ships locked to [OBSERVE]. Rules evaluate and every match is
 * persisted as a [Detection], but no enforcement action is ever executed —
 * the engine records the action it *would* have taken and stops there.
 *
 * ENFORCE is intentionally not reachable at runtime in this build. Flipping it
 * on is a deliberate, reviewed change (see OBSERVE_MODE.md → "Graduating a rule
 * to enforce"), not a config toggle, precisely so a bad rule can never brick a
 * device before its telemetry has been looked at.
 */
enum class EnforcementMode {
    OBSERVE,
    ENFORCE;

    companion object {
        /** The only mode this build will run in. */
        val ACTIVE: EnforcementMode = OBSERVE

        /** Guard used by the engine before any action dispatch. */
        fun enforcementAllowed(): Boolean = ACTIVE == ENFORCE
    }
}
