# Changelog

All notable changes to the EASM_RED design are recorded here.

## Unreleased

### Added
- `docs/PLAN.md` — single consolidated design document (operating model,
  architecture, capability-state graph, reachability, Path Risk Score, autonomy
  ladder, decisions, production-ready prompt) with flow diagrams.
- `docs/BUILD_PLAN.md` — build-execution plan (milestones M0–M4, work-packages,
  acceptance/verification, safety gates) for a coding session to work through.
- `operating-model.html` — self-contained mock console: a synthetic dashboard
  (choke points, top paths, safe-to-ignore, coverage), an autonomy-tier switcher
  stating what each of L0–L3 enables and locks, and a step-through walkthrough.

### Changed
- Consolidated the five earlier design docs (`BLUEPRINT`, `PATH_RISK_SCORE`,
  `AUTONOMY_AND_ROADMAP`, `PRODUCTION_PROMPT`, `DECISIONS`) into the single
  `docs/PLAN.md`, per the author's request for one plan document. The operating
  model is now `PLAN.md` §1.

### Removed
- The five separate design docs, superseded by `docs/PLAN.md`.
