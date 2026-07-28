# DroidEDR v2.9 — Observe Mode

This drop adds the v2.9 rule engine in **observe / log-only** mode. All rules
evaluate and every match is persisted with full evidence and the threshold that
was in force. **Nothing enforces.** The engine records the action it *would*
have taken (`plannedAction`, `wouldEnforce`) and stops.

The point: get real telemetry off the device first, tune against it, and
graduate rules to enforce one at a time — instead of shipping 200 immediate-
enforcement rules whose only failure recovery is a wipe.

## Why observe-only is enforced structurally, not by a flag

- `EnforcementMode.ACTIVE` is hardcoded to `OBSERVE`. `enforcementAllowed()`
  returns false, and the engine's single dispatch point throws if ever reached.
- Detectors receive a read-only `Signals` snapshot. They have no handle to
  device state, so a rule *cannot* act even if written to — observe-only is a
  property of the types, not a runtime toggle someone can fat-finger.
- Thresholds are recorded on every `Detection` (`thresholdSnapshot`). Nothing is
  hidden or unlogged, which is what makes a match reviewable after the fact.

## Files

```
app/src/main/java/com/droidedr/engine/
  EnforcementMode.kt      OBSERVE lock + guard
  Detection.kt            Room entity (evidence, threshold, would-enforce)
  DetectionStore.kt       DAO + Room DB + tuning queries
  RuleContext.kt          immutable Signals snapshot + context
  Detector.kt             RuleSpec (rule-as-data) + Detector registry
  RuleEngine.kt           load specs → evaluate → log; hard no-enforce guard
  ObserveModeWorker.kt    WorkManager runner (wire collectSignals to your sensors)
  detectors/BuiltInDetectors.kt   6 real detectors across MITRE tactics
app/src/main/assets/
  rules_v2.9.json         starter catalog (spec format for all 200)
```

## Scaling 35 → 200

Rules are data. Each `RuleSpec` names a `detector`; detector logic is written
once and reused. Point your `scripts/gen_rules.py` output at this schema
(`id, detector, mitre, tactic, severity, threshold, plannedAction, enabled`) and
the 200 specs load from `rules_v2.9.json`. A spec whose `detector` isn't
implemented yet is **skipped with a warning**, never a crash — so you can commit
the full 200 and fill in detectors incrementally.

## Wiring (the one required step)

`ObserveModeWorker.collectSignals()` currently returns an empty snapshot (safe,
but finds nothing). Point it at your existing v2.6 collectors — package scan,
DNS/netlink taps, DHCP watcher, auth-failure counter — mapping into `Signals`.

Schedule it from your `Application`/boot receiver:

```kotlin
val work = PeriodicWorkRequestBuilder<ObserveModeWorker>(15, TimeUnit.MINUTES).build()
WorkManager.getInstance(context).enqueueUniquePeriodicWork(
    ObserveModeWorker.WORK_NAME, ExistingPeriodicWorkPolicy.KEEP, work
)
```

## Reading the telemetry

- `DetectionDao.recent()` — event feed for the dashboard.
- `DetectionDao.ruleFrequency()` — noisiest rules first = your tuning worklist.
- `DetectionDao.wouldEnforceCount()` — how many actions enforce mode *would* have
  fired. This is the number to stare at before turning anything on.

## Graduating a rule to enforce (later, deliberately)

Do **not** flip `EnforcementMode.ACTIVE`. Per-rule, after its observe data is
clean: implement the specific action behind a reviewed `dispatchEnforcement`
branch keyed on `ruleId`, keep suspend-not-kill, keep phone-services hands-off,
and ship a rollback. One rule at a time, each backed by its own telemetry.

## Build

Standard debug build (see repo notes: JDK 17, Gradle 8.6, AGP 8.2.2):

```bash
./gradlew assembleDebug --no-daemon --stacktrace
```

## Push to GitHub (run from your Codespace — you're authenticated there)

Copy this `app/` tree over your repo's `app/`, then:

```bash
git checkout -b v2.9-observe
git add app/src/main/java/com/droidedr/engine app/src/main/assets/rules_v2.9.json OBSERVE_MODE.md
git commit -m "v2.9 rule engine — observe/log-only mode (no enforcement)"
git push -u origin v2.9-observe
```

Open a PR from `v2.9-observe` so the diff is reviewable before it touches `main`.
