# BUILD PLAN — implementing the Attack Path Management agent

This is the **execution plan**, separate from the design (`PLAN.md`). It is
written to be worked through by an engineer or an AI coding session (e.g. a
Claude Code session), one work-package at a time, each ending in a reviewed,
tested pull request. It builds a **defensive** exposure-management platform; it
does not build offensive tooling. Every work-package inherits the Rules of
Engagement in `PLAN.md` §14 and the autonomy ceiling: the software never applies
a remediation on its own and never performs a destructive action.

Read `PLAN.md` first. This document says *how to build it and in what order*;
`PLAN.md` says *what it is and why*.

---

## 0. How to run this as a build loop

Each work-package (WP) below is sized for one focused session. Run every WP the
same way:

1. **Scope** — restate the WP goal and acceptance criteria; list the files it
   will touch. Do not widen beyond the WP.
2. **Design test-first** — write the tests/fixtures for the behaviour before the
   implementation. For this system, prefer synthetic graph fixtures with a known
   ground-truth answer (a hand-built topology whose dead-ends, gateways, and
   choke points you already know).
3. **Implement** the smallest change that meets the acceptance criteria.
4. **Verify** — run the WP's checks; for any "X is correct/complete/safe" claim,
   prove it by a negative case (make X fail and watch the test catch it).
5. **Review** — an independent adversarial pass (fresh context) that tries to
   refute the change, with the safety lens: could this WP let the system act
   outside its current autonomy phase? Fix or record findings.
6. **PR** — open a draft PR whose body carries the WP goal, the acceptance
   results, and the safety-lens result. Merge is a human decision.

**Guardrails that bind every WP:**
- The autonomy phase is enforced in code (the orchestrator), not left to
  convention. A WP that would let the system reach a live target ships behind a
  phase flag that defaults to the lowest phase.
- No secrets, no real-target data, and no organization-specific detail in the
  repo. Test fixtures are synthetic.
- The validation module (Phases C/E) is built strictly to the "authorized,
  non-destructive, allow-listed, rate-limited, SOC-coordinated" contract; it
  contains no exploit code and no capability to cause impact.

---

## 1. Milestone M0 — Foundations (Design → L0-ready)

Goal: a running L0 pipeline that ingests one feed, resolves entities, builds the
graph, scores paths, and reports — read-only, no target contact.

| WP | Objective | Key deliverables | Acceptance / verification |
|---|---|---|---|
| **WP-A1** | Common data model + connector contract | `Finding`/`Entity`/`CapabilityEdge`/`CrownJewel`/`Path` schema (`PLAN.md` §11); a connector interface; one reference connector reading from a static sample file | Schema validates; a golden sample file parses into typed records; contract documented |
| **WP-A2** | Entity resolution | Deterministic matcher (strong keys), probabilistic matcher (soft signals) with a review band, reversible `sameAs` graph | On a labelled synthetic set: precision/recall reported; a wrong-merge case is reversible without data loss (test proves it) |
| **WP-A3** | Graph store + capability-edge model | Graph schema; loader that turns findings into ATT&CK-labelled capability edges with preconditions | A fixture topology loads; edges carry capability, technique, enabling findings, preconditions |
| **WP-A4** | Reachability engine | Guarded capability-propagation search; dead-end vs gateway classification; least-effort predecessors | On a known topology, dead-end/gateway output matches ground truth; a mutation (add one edge) flips a dead-end to a gateway and the test catches it |
| **WP-A5** | Crown-jewel policy | Declarative, version-controlled policy mapping tags → value tiers; allow/deny overlay; coverage/blind-spot report | Policy assigns tiers on a fixture; unclassified assets appear in the blind-spot report |
| **WP-A6** | Path Risk Score + choke ranking | PRS with configurable weights and full decomposition; greedy set-cover choke ranking (`PLAN.md` §7) | Worked example reproduces (PRS ≈ 78/76/59, leverage 213); every score decomposes to inputs on demand |
| **WP-A7** | Reporting surface | Read-only views: "break the most paths," "top paths," "what you can ignore" | Report renders from a fixture; the ignore-count equals the dead-end count |

**Milestone gate (L0→L1 readiness):** the `PLAN.md` §12 L0→L1 criteria —
resolution accuracy, reachability correctness, signal-to-noise on the top-10,
100% score decomposition, coverage measured. This is a **human sign-off**, not a
code merge.

---

## 2. Milestone M1 — Fusion & scale (still L0, enterprise-ready)

Goal: all four feeds fused, incremental ingest at scale, the continuous loop.

| WP | Objective | Acceptance / verification |
|---|---|---|
| **WP-B1** | Remaining connectors (EASM, vuln scanners, CSPM, identity) | Each normalizes to the `Finding` schema against a recorded sample; no write-back path exists (test asserts read-only) |
| **WP-B2** | Incremental/streaming ingest + columnar finding store | Replaying a feed does not double-count (idempotency test); graph size tracks topology, not scan-row count |
| **WP-B3** | LLM translation service (scan text → schema + candidate technique) | Every LLM output passes the schema + controlled-vocabulary validator or is rejected; the LLM cannot emit an identifier or a merge (test asserts) |
| **WP-B4** | Continuous loop on the orchestrator with L0 checkpoints | The loop runs Scoping→Discovery→Prioritization→report on a schedule; L0 checkpoint blocks any step that would contact a target |

**Milestone gate:** scale + stability evidence; L0 criteria still hold on the
larger graph.

---

## 3. Milestone M2 — Non-intrusive validation (targets L1)

Goal: confirm which proposed paths are real, using only authorized,
non-destructive checks — behind the phase flag and the SOC contract.

| WP | Objective | Acceptance / verification |
|---|---|---|
| **WP-C1** | Read-only validation checks (service-responds, version banner, static IAM-policy evaluation, bucket-listable) behind an allow-list + rate-limiter | Every check is read-only (test asserts no state change); an out-of-allow-list target is refused; rate limit enforced |
| **WP-C2** | SOC coordination (registered identity, declared window, shared audit trail) | All validation traffic is attributable to the registered identity; activity outside the declared window is refused; audit trail complete |
| **WP-C3** | Broken-path re-planning + block-as-control reporting | A blocked edge is marked with expiring evidence; reachability re-plans over *known* edges only (no new probing); block choke-value reported |
| **WP-C4** | Confidence (`κ`) uplift from validation into PRS | A validated path's `κ` rises; ranking shifts accordingly; unvalidated paths never outrank confirmed equals |

**Milestone gate (L1→L2 readiness):** clean validation safety record (zero
out-of-scope actions / state changes / SOC-confirmed false incidents),
false-path reduction target met, 100% SOC attribution — human sign-off.

---

## 4. Milestone M3 — Mobilization (targets L2)

Goal: route the short list to owners and verify closure.

| WP | Objective | Acceptance / verification |
|---|---|---|
| **WP-D1** | Ownership routing from tags/CMDB | Each choke point resolves to an owner; unowned assets flagged |
| **WP-D2** | Ticketing integration (open/assign with path context) | Ticket opens with the path chain + severing fix; no fix is applied; a dry-run mode exists |
| **WP-D3** | Closure verification | After a simulated fix, reachability re-runs and confirms (or denies) the path is broken |

**Milestone gate (L2→L3 readiness):** ticket-acceptance quality,
closure-verification accuracy, and a **signed, scoped, time-boxed Rule of
Engagement with named approvers** for any active validation — human sign-off.

---

## 5. Milestone M4 — Assisted response (targets L3, ROE-gated)

Goal: highest-fidelity validation and drafted fixes — never applied.

| WP | Objective | Acceptance / verification |
|---|---|---|
| **WP-E1** | Chained safe active validation under the signed ROE | Each chain step is non-destructive and rate-limited; the chain halts at the ROE boundary; a kill-switch stops it immediately |
| **WP-E2** | Proposed-fix drafting for human review | A draft fix (e.g. a tighter IAM policy) is produced as a *proposal artifact*; the system has no code path that applies it |

**Ceiling (permanent):** there is no WP, and never will be, that applies a
remediation autonomously or performs a destructive action. Any such request is
out of scope for this build.

---

## 6. Suggested repository shape for the implementation

The implementation lives in its own repo (or a subdirectory), separate from this
design repo. A shape that mirrors the design:

```
/connectors        one adapter per feed → Finding schema (read-only)
/resolve           entity resolution (deterministic + probabilistic)
/graph             capability-state graph store + loaders
/reason            reachability, PRS, choke-point ranking
/policy            crown-jewel policy + overlay
/validate          phase-gated, non-destructive checks (allow-list, rate-limit, audit)
/orchestrate       continuous loop + human-gate checkpoints (phase enforcement)
/report            read-only views
/fixtures          synthetic topologies with known ground truth (no real data)
/tests             unit + fixture-based integration + negative/mutation cases
```

Phase enforcement is a single, well-tested module every action routes through:
it knows the current phase and refuses anything the phase does not permit. That
module is the most security-critical code in the system and gets the heaviest
review.

---

## 7. Definition of done (per milestone and overall)

- Every WP: tests written first, acceptance met, adversarial + safety review
  passed, draft PR with the run record, human merge.
- Every milestone: the `PLAN.md` §12 gate met on evidence, signed off by a human
  before the next milestone starts.
- Overall: the platform advances only as far up the autonomy ladder as its gates
  are met; the fixed ceiling holds at every phase.
