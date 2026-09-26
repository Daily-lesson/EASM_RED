# Changelog

All notable changes to the EASM_RED design are recorded here.

## Unreleased

### Revision 2.1 — author's rulings (2026-09-26)

- **Build vs buy is neutral** (D25, supersedes D19's buy-and-extend default):
  `PLAN.md` §1.4 now compares build / buy / buy-and-extend with one rubric.
- **SOC stance confirmed** (D26): validation stays deconflicted, not covert.
- **README one-page brief** — the value in one screen; its numbers are pinned
  to the engine by a test.
- **Executive view** leads with the share of findings needing action (13%);
  the unproven half is framed as a visibility decision to fund, tied to
  decision 3.

### Revision 2 — adversarial review (2026-09-26)

A five-role panel (adversary emulation, risk quantification, AI/platform
security, SOC/delivery, CISO/governance) attacked revision 1. Every finding and
its evidence is tabled in `docs/PLAN.md` §0; superseding decisions are D12–D24.

#### Changed
- **Scoring** — likelihood × impact replaces the additive Path Risk Score:
  step likelihood from a single threat term (KEV / PoC / EPSS percentile),
  effort and compensating controls; route likelihood is the product of steps
  (hardest step governs); order-of-magnitude impact weights. Revision 1's
  worked example could not be produced by its own formulas; the new one is
  computed and tested.
- **Reasoning** — entity-bound facts and a monotonic fixpoint replace the
  global capability set; assumed-breach sources; config/trust/network edges;
  a fifth feed family (network and segmentation policy).
- **Choke points** — remediation *actions* ranked by risk removed per unit
  effort, greedily on the residual graph, replace node leverage (which
  credited a patch with paths it does not cut).
- **Unknowns** — widen a pessimistic/optimistic band and drive a validate-next
  queue; confidence no longer discounts a score.
- **Findings** — "safe to ignore" is gone: on-route / floor /
  deferred-covered / deferred-unproven, with a residual floor for KEV,
  control-plane and compliance-scope findings.
- **Autonomy** — two axes (target interaction T0–T4, workflow write W0–W3),
  enforced by an external default-deny policy point, per-rung credentials and
  egress locks; numeric default gates; automatic demotion; kill switch at
  every level. T4 never uses a gained foothold.
- **Value tiers** renamed V0–V3; control-plane assets critical by policy;
  tier ratchet.
- `docs/BUILD_PLAN.md` — platform-security milestone before any real data,
  MVP slice, evaluation harness (gold set, shadow mode, injection corpus),
  estimates, pilot and a build-vs-buy checkpoint.
- `operating-model.html` — new **Executive** view (posture sentence, critical
  systems reachable, trend vs target, what the next fixes buy, deadlines,
  exposure by service, decisions needed); analyst view shows the action plan,
  route likelihoods and bands; autonomy view shows both axes, gates and
  demotion. All data generated from the reference engine.

#### Added
- `docs/PLAN.md` §0 (review table), §1.2 RACI, §1.4 build vs buy, §10
  deadlines/exceptions/closure, §13 leadership KPIs and baseline, §14.2
  platform security.
- `reference/` — dependency-free engine, synthetic estate, console data
  builder. `tests/` — 24 tests incl. negative cases, each seen to fail under a mutation of the rule it guards. `package.json`,
  `.github/workflows/check.yml`.

### Revision 1

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
