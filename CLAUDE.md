# CLAUDE.md — EASM_RED project map

This repository holds the **design, build plan and specification** for a
Risk-Based **Attack Path Management (APM)** agent. It is a shareable,
vendor-neutral starting point intended to be handed to a security team to build
and verify. **It must contain no organization-specific data, credentials,
hostnames, internal architecture, or personal information** — everything here is
generic and safe to share.

## What this repo is (and is not)

- **Is:** one consolidated design document, a build-execution plan, an
  interactive operating-model visual, and a small dependency-free reference
  engine + tests that compute and pin every number the docs and visual show.
- **Is not:** a running product, an exploit toolkit, or a place for any real
  target's data. No scan output, asset inventory, credentials, or findings from
  any live environment belong here.

## Directory map

| Path | What |
|---|---|
| `README.md` | Overview, problem statement, how a security team uses this. |
| `docs/PLAN.md` | The single design document: §0 review table, operating model + RACI, build vs buy, entity-bound reasoning, likelihood × impact scoring, finding statuses, two-axis autonomy with gates and demotion, platform security, governance/metrics, decision log (D1–D24), production-ready prompt, flow diagrams. |
| `docs/BUILD_PLAN.md` | The build-execution plan: platform-security milestone S, MVP slice M0, M1–M4, evaluation harness, estimates, pilot. |
| `operating-model.html` | Self-contained mock console: Executive view, Analyst view, two-axis autonomy (T0–T4 × W0–W3), and a step-through walkthrough. Its `<script id="apm-data">` block is **generated** — never hand-edit it. |
| `reference/engine.mjs` | Runnable spec of the scoring (`PLAN.md` §5–§7). |
| `reference/demo-estate.mjs` | The synthetic estate + governance ledger + 12-week trend the console shows. |
| `reference/summary.mjs`, `reference/build-demo.mjs` | Turn engine output into the console's data block (`npm run build:demo`; `--check` to verify). |
| `tests/engine.test.mjs` | `npm test` — pins worked-example numbers, every never/always claim, console-data sync, and no jargon on the executive view. |
| `.github/workflows/` | `pages.yml` (publish console), `check.yml` (tests on PR). |
| `CHANGELOG.md` | Notable changes to the design. |

## Where do I change…?

- **How the system works / architecture / scoring / autonomy / decisions** →
  `docs/PLAN.md` (one document; add a superseding decision entry in §15 rather
  than rewriting an old one).
- **How it gets built / the work-packages** → `docs/BUILD_PLAN.md`.
- **The mock console / visual** → `operating-model.html` (self-contained, no
  external dependencies, theme-aware, synthetic data only; must open offline).
  Change *numbers* in `reference/demo-estate.mjs`, then `npm run build:demo`.
- **The scoring model** → `reference/engine.mjs` **and** `PLAN.md` §7 in the
  same change, then `npm test`; a worked-example number in the doc that the
  engine does not produce is a bug.

## Conventions

- **Framework-first.** Anchored on Gartner CTEM (lifecycle), MITRE ATT&CK
  (technique labels), and EPSS/CISA KEV/CVSS (exploitability).
- **Defensive framing, always.** Detection, prioritization, and authorized
  validation only. No exploit code, payloads, or detection-evasion instructions.
  Verification is non-destructive, authorized, and gated (`PLAN.md` §14).
- **No personal or org data.** Before committing, confirm nothing identifies a
  real person, company, host, repo, or account.
- **Diagrams** are Mermaid (in the markdown) or inline SVG (in the HTML), so they
  render anywhere with no external dependency.

## Gotchas

- This repo is intentionally **separate from any other project**. Do not import
  another repository's conventions, tooling references, or private context.
- The autonomy ladder is load-bearing: no design change should let the agent act
  more autonomously than the current phase's benchmark gate permits. Higher
  autonomy is earned by meeting exit-criteria, never assumed.
- `operating-model.html` must stay dependency-free so it opens offline and is
  safe to share.
- Never hand-type a score, count or trend into a doc or the console: compute
  it with `reference/` and let a test pin it (revision 1's example could not be
  produced by its own formulas — `PLAN.md` §0 #1).
- The executive view must stay jargon-free (a test enforces a term list).
