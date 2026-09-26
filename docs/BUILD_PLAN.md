# BUILD PLAN — implementing the Attack Path Management agent

This is the **execution plan**. It is separate from the design (`PLAN.md`). An engineer or an AI coding session works through it one work-package (WP) at a time, and each WP ends in a reviewed, tested pull request.

It builds a **defensive** exposure-management platform, not offensive tooling. Every WP inherits:
- the Rules of Engagement and platform-security controls in `PLAN.md` §14;
- the permanent ceiling: the software never applies a fix, never performs a destructive action, never uses a gained foothold, and never reads business data.

Read `PLAN.md` first. Its §0 lists the review findings this plan is built to avoid. Then read `reference/` and `tests/`. The reference engine is the **executable specification** for the scoring work-packages: an implementation passes when it reproduces the reference on the shared fixtures and on the gold set (WP-A8).

---

## 0. How to run each work-package

1. **Scope.** Restate the WP goal and its acceptance criteria. List the files it will touch. Do not widen the scope.
2. **Tests first.** Use synthetic fixtures with known answers. **Every "never / always / cannot" claim gets a negative case**: make the bad thing happen and watch the test catch it (`tests/engine.test.mjs` shows the pattern).
3. **Implement** the smallest change that passes.
4. **Verify** against the WP's acceptance criteria and the **evaluation harness** (WP-A8). Matching our own worked example is necessary but never sufficient.
5. **Review.** An adversarial pass in a fresh context tries to refute the change. It always includes two lenses:
   - **Safety:** could this WP let the system act above its current T/W level?
   - **Suppression:** could this WP make a real route disappear?
6. **Draft PR** with the goal, the acceptance results and both lens results. A human merges.

**Guardrails for every WP:**
- **Enforcement lives outside the agent.** Anything that reaches a target or writes to another system goes through the external PDP (WP-S1). It ships dark (T0/W0) by default.
- **No secrets, no real-target data, no organization-specific detail in any repo.** Fixtures are synthetic.
- **Asymmetric trust.** Any code path that removes, down-weights or defers a route needs a test showing that missing or stale input cannot trigger it.

---

## 1. Milestone S — Platform security and enforcement plane (before any real data)

**Goal:** the platform is safe to hold an estate's attack map before it holds one. **This milestone gates M0 on real feeds.** M0 may be built in parallel on synthetic fixtures.

| WP | Objective | Acceptance / verification |
|---|---|---|
| **WP-S1** | External **policy decision point** (default-deny, e.g. OPA). Signed T/W levels; dual control to change them. Per-rung service identities | The PDP being unreachable means deny. A request above the current level is refused and logged. Changing a level with one approver fails |
| **WP-S2** | **Egress lock.** At T0 the platform reaches only connector endpoints. The validation segment's allow-list is generated from the signed scope | Chaos test: code patched to probe a fixture IP from T0 is **blocked at the network layer**, not by the app |
| **WP-S3** | **Kill switch and demotion** (`PLAN.md` §12.4) | Kill halts everything and revokes tokens in ≤ 60 s. Each demotion trigger is injected in a fixture and demotes. Monthly drill runbook |
| **WP-S4** | **Threat model and classification**: STRIDE + MITRE ATLAS; graph and exports classified RESTRICTED | Threat model reviewed by the security architect; every high-severity threat mapped to a control and a test |
| **WP-S5** | **Access control**: ABAC need-to-know views; JIT + MFA for full-map roles; break-glass | An owner-role query for a route that avoids their assets returns 403. A ticket-payload lint finds no node outside the owner's scope. Break-glass use alerts |
| **WP-S6** | **Policy integrity**: signed policy/weights/overlay, two-person review, weight bounds, change-impact gate, tier ratchet | Unsigned policy is rejected. A weight change that removes V0 risk requires a second approver. A fixture re-tagged V0 → V3 stays V0 and raises a tier-downgrade finding |
| **WP-S7** | **Tamper-evident audit**: hash-chained, shipped to WORM or a SIEM outside admin control | Editing a record fails verification. A platform admin cannot delete records |
| **WP-S8** | **Connector least privilege**: per-connector scope table, explicit deny on secret/data reads, federated tokens ≤ 1 h, one identity per connector | An IaC policy test finds no write or secret-read actions. Token TTL assertion. Log-redaction and secret-scanning tests in CI |
| **WP-S9** | **Supply chain and privacy**: SBOM, hash-pinned dependencies, signed builds; pinned model, zero-retention; pseudonymous identities; DPIA; retention schedule | The build fails on an unpinned dependency. A schema test rejects `password`/`secret` fields. A fixture carrying a credential value is dropped at the connector |

**Gate S → real data:** all S acceptance criteria pass, and the security architect and the CISO sign off.

---

## 2. Milestone M0 — MVP slice at T0/W0 (8–10 weeks)

**Scope decision:** one cloud account, plus CSPM, plus the IdP, plus network policy for that account. **Not** "all feeds at once". Identity and misconfiguration edges dominate real routes, and cloud IDs give strong keys, so entity resolution is nearly deterministic. EASM and vulnerability scanners arrive in M1.

| WP | Objective | Acceptance / verification |
|---|---|---|
| **WP-A1** | Data model and connector contract (`PLAN.md` §11), with provenance on every record | A golden sample parses into typed records. Records without provenance are rejected |
| **WP-A2** | Entity resolution: deterministic → probabilistic → review band; reversible `sameAs` | Precision/recall reported on a labelled set. A wrong merge is reversed without data loss |
| **WP-A3** | Graph of **entity-bound facts** and classed edges (`finding/config/trust/netReach`), with controls | Reproduces the "facts are entity-bound" and "AND-edges" reference tests |
| **WP-A4** | **Reachability**: monotonic max-product fixpoint; assumed-breach sources; most-likely route per entity | Reproduces the monotonicity, hardest-step and assumed-breach reference tests. Matches the gold-set gateways (WP-A8) |
| **WP-A5** | Value-tier policy V0–V3, control plane by policy, transitive value, tier ratchet, **coverage and blind spots** | Tiers assigned on a fixture. Unclassified candidates are scored pessimistically as V1 and listed as blind spots |
| **WP-A6** | **Scoring and plan**: p(e), band (pessimistic/optimistic), R_j, R(G), greedy ΔR/cost plan, dominators, decision layer | Reproduces **every** `tests/engine.test.mjs` scoring case **and** meets the WP-A8 gold-set targets. Every score decomposes to inputs |
| **WP-A7** | **Reporting**: executive and analyst views, and finding statuses (on-route / floor / deferred-covered / deferred-unproven) | Views render from engine output only (no hand-entered numbers). A feed going dark cannot create a deferral (negative test). The executive view contains no analyst jargon |
| **WP-A8** | **Evaluation harness**: (a) three synthetic topologies with 500+ nodes and known answers; (b) ≥ 30 real routes blind-labelled by the red/purple team; (c) property tests (monotonicity; a weight change moves rank only in the expected direction); (d) a backtest: does the known route land in the top-k? | Harness runs in CI. Results are published per build. It becomes a regression gate |
| **WP-A9** | **Baseline and shadow mode**: four weeks of the current process's metrics (`PLAN.md` §13.2), then side-by-side ranking | Baseline dashboard exists before T0/W0 goes live on real feeds |

**Gate T0/W0 → next** (`PLAN.md` §12.3):
- entity-resolution precision;
- zero gateways wrongly called dead-ends;
- top-10 acceptance ≥ 70% over 8 shadow cycles;
- coverage ≥ 90%.

This is a **human sign-off**, not a merge.

---

## 3. Milestone M1 — Fusion and scale, T0/W1 (≈ 8 weeks)

| WP | Objective | Acceptance / verification |
|---|---|---|
| **WP-B1** | Remaining connectors: EASM, vulnerability scanners (authenticated package data preferred) | Each normalizes a recorded sample. No write path exists (test). Scopes pass WP-S8 |
| **WP-B2** | Incremental/streaming ingest, columnar store, **freshness TTLs**, **feed-health monitor** | Replaying a feed does not double-count. A 30% volume drop freezes deferrals. Stale evidence reverts to unknown and widens the band |
| **WP-B3** | **Bounded LLM translation** | Evaluation set of ≥ 300 labelled scanner descriptions; ATT&CK top-1 ≥ 80%. An **injection corpus** (hostile banners, certificate CNs, tags) runs in CI with zero route removals. A KEV CVE mis-mapped by the LLM is overridden by the deterministic table. No tools or network are available to the model |
| **WP-B4** | Continuous loop on the orchestrator; every action calls the PDP | The loop runs on schedule. Any target-contacting step at T0 is refused by the PDP and blocked by the egress lock |
| **WP-B5** | **W1 draft tickets**: deduped against open tickets; owner's hop only; held for human release | Drafts never leave the queue without a human. Dedupe matches on asset + control |

**Scale targets:**

| Measure | Target |
|---|---|
| Entities | 1 M |
| Edges | 10 M |
| Full cycle | ≤ 4 h |
| Incremental update | ≤ 15 min |
| Route query p95 | ≤ 5 s |

These are measured on a synthetic generator, and all M0 gates still hold at scale.

---

## 4. Milestone M2 — Least-contact validation, T1–T2 (≈ 6 weeks + a 4-week evidence window)

| WP | Objective | Acceptance / verification |
|---|---|---|
| **WP-C1** | T1 passive checks (passive DNS, CT logs, scan datasets on the organization's own ranges) | No packet or API call reaches an in-scope asset (egress test) |
| **WP-C2** | T2 read-only control-plane checks, including static IAM with SCPs, boundaries and conditions. **Leaked-credential validity by rotation timestamp**, never by login | API-audit assertion against an allow-list of configuration-metadata calls and an explicit deny-list (object, secret, parameter-value, data-plane reads) — not a verb prefix, since `GetObject`/`GetSecretValue` are Gets. No data-plane reads. No authentication attempt ever |
| **WP-C3** | **SOC deconfliction**: run IDs, declared windows, SIEM auto-close by run ID; `detected` recorded per step | Detections fire and are auto-closed. Activity outside the window is refused by the PDP |
| **WP-C4** | **Evidence and asymmetric trust**: vantage + allow-listed flags; expiring blocked evidence; one observation cannot remove a V0 route | A single blocked observation leaves a V0 route in place. A blocked verdict from an allow-listed vantage is ignored |
| **WP-C5** | **Detection-coverage report** by ATT&CK technique | Coverage computed from WP-C3 records |

**Gate:**
- false-route removal ≥ 25%;
- zero out-of-scope actions;
- 100% of checks attributable to their run ID;
- human sign-off.

---

## 5. Milestone M3 — Mobilization, W2 (≈ 6 weeks + a 4-week evidence window)

| WP | Objective | Acceptance / verification |
|---|---|---|
| **WP-D1** | Ownership routing and the **feedback loop** (not-mine / false-positive / accepted-risk / fixed) | "Not mine" re-resolves the owner and labels entity resolution. Disputes feed the top-10 gate |
| **WP-D2** | Open and assign deduped tickets with deadlines from the decision layer; compliance clocks run in parallel; escalation per RACI | No fix applied. Dry-run mode. Overdue items escalate to the accountable role |
| **WP-D3** | **Exceptions**: business owner, approval level by value, expiry ≤ 90 days, auto-reopen when a new route appears | A V0 exception requires C-level approval. Expiry reopens it. A new route to the same jewel reopens it |
| **WP-D4** | **Closure on fresh positive evidence** | A missing observation yields `unverified`, never closed. Closure requires a feed dated after the fix |

**Gate:**
- ticket acceptance ≥ 80%;
- misroutes ≤ 10%;
- closure agreement ≥ 95% against manual re-test;
- human sign-off.

---

## 6. Milestone M4 — Active non-intrusive and sequenced checks, fix proposals (T3–T4, W3; ROE-gated)

| WP | Objective | Acceptance / verification |
|---|---|---|
| **WP-E1** | T3 active non-intrusive checks (TCP connect, TLS, HTTP HEAD), rate-limited, fragile assets excluded, circuit breaker | ≥ 1,000 checks over ≥ 4 weeks with zero out-of-scope actions or state changes. The circuit breaker pauses a target on errors |
| **WP-E2** | T4 **sequenced precondition checks** under a signed, time-boxed ROE with named approvers | Each step confirms a precondition independently using only T0–T3 methods: a test asserts the T4 action set **equals** the T3 action set. A precondition that needs exploitation or an on-host read stays inferred. There is **no code path that uses a gained foothold** (static and dynamic test). The run halts at the ROE boundary. The kill switch works |
| **WP-E3** | W3 **fix proposals** | Each proposal is a strict subset of current permissions (checked by a policy evaluator). There is no code path that applies it |

**Ceiling (permanent):** there is no WP, and never will be, that applies a remediation, performs a destructive action, uses a gained foothold or reads business data.

---

## 7. Pilot and rollout

- **WP-F1 Pilot.** Run in one business unit with named success criteria:
  - the `PLAN.md` §12.3 gates;
  - analyst hours per route closed vs. baseline;
  - critical systems reachable, trending down.

  Hold a go/no-go review after 8 weeks. Fixes go through the existing ITSM/CAB, and deadlines are agreed with the IT Ops director before W2.
- **Build vs. buy checkpoint.** Before M1, score candidate products against `PLAN.md` as a rubric (§1.4, D25), alongside this plan's own estimate. If the team chooses buy or buy-and-extend, keep only S, the policy layer, governance reporting and the evaluation harness.

---

## 8. Estimates (indicative, to be validated)

| Milestone | Duration | Team |
|---|---|---|
| S | 6–8 weeks, overlapping M0 | 1 platform-security engineer + 0.5 security architect |
| M0 | 8–10 weeks | 2 engineers + 0.5 security architect + red-team labelling time |
| M1 | ≈ 8 weeks | 2–3 engineers |
| M2 | ≈ 6 weeks + 4-week evidence window | 2 engineers + SOC liaison |
| M3 | ≈ 6 weeks + 4-week evidence window | 2 engineers + ITSM integration |
| M4 | ≈ 6 weeks, ROE-gated | 2 engineers + red-team oversight |

**Total** to W2/T2 is about 9–12 months with 3–5 engineers. Running cost is 1–2 FTE plus graph-store licensing.

---

## 9. Suggested repository shape for the implementation

The implementation lives in its own repo, separate from this design repo.

```
/connectors     one adapter per feed → Finding (least-privilege, provenance)
/resolve        entity resolution (deterministic + probabilistic + review)
/graph          facts, edges, controls, evidence (TTL)
/reason         fixpoint, band, greedy plan, dominators/cut, decision layer
/policy         signed value-tier policy + overlay + ratchet
/enforce        PDP client, per-rung identities, kill switch, demotion
/validate       T1–T4 workers (separate deployable, separate segment)
/mobilize       tickets, dedupe, deadlines, exceptions, closure
/report         executive + analyst views (ABAC)
/audit          hash-chained log shipping
/eval           gold sets, injection corpus, backtests, property tests
/fixtures       synthetic topologies only
```

`/enforce` and `/audit` are the most security-critical modules and get the heaviest review.

---

## 10. Definition of done

- **Every WP:** tests written first; negative cases for every never/always claim; acceptance met; safety and suppression lens reviews passed; draft PR; human merge.
- **Every milestone:** its `PLAN.md` §12.3 gate met on evidence and signed off by a human before the next starts. Milestone S precedes any real data.
- **Overall:** the platform advances on each autonomy axis only as far as its gates allow, demotes itself automatically, and never crosses the ceiling.
