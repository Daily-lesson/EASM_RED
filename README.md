# EASM_RED — Risk-Based Attack Path Management (APM) Agent

**A design blueprint and build plan for an autonomous agent that turns "CVE
overload" into a short, ranked list of the attack *paths* that actually reach
what matters.**

### [▶ Open the live dashboard](https://htmlpreview.github.io/?https://raw.githubusercontent.com/Daily-lesson/EASM_RED/main/operating-model.html)
One click, opens in your browser — the mock console, the tier switcher, and the walkthrough. No install, no clone.

This repository is a **starting point for a security team** — a concrete,
framework-aligned proposal an engineer can hand to cyber defenders so they can
build and verify it inside their existing flow. It is a design and specification
repo, not a finished product. It contains no organization-specific data,
credentials, or internal details, and is safe to share.

## The problem it addresses

Traditional vulnerability management is a losing race: an unbounded backlog of
individual CVEs, most unexploitable in context or disconnected from anything
valuable. **Attack Path Management (APM) reframes the same data.** Instead of a
list of bugs, the agent produces a graph of *paths* — sequences an attacker
would chain from an exposed entry point to a "crown jewel" (sensitive database,
PII store, or core system). Paths are finite; a few fixes at the right choke
points break many at once.

The design aligns to the **Gartner CTEM** (Continuous Threat Exposure
Management) lifecycle, labels path steps with **MITRE ATT&CK** techniques, and
scores exploitability with **EPSS + CISA KEV + CVSS**, so it speaks the language
a cyber team already uses.

## What's in here

| Path | What it is |
|---|---|
| `docs/PLAN.md` | **The single design document.** Operating model, architecture (ingestion, capability-state graph, reachability), the Path Risk Score, the autonomy ladder, decisions, and the production-ready prompt — with flow diagrams. Start here. |
| `docs/BUILD_PLAN.md` | The execution plan a Claude coding session (or an engineer) works through to build the agent: milestones, work-packages, acceptance/verification, and the safety gates. |
| `operating-model.html` | A self-contained **mock console**: the dashboard a defender would see (choke points, top paths, safe-to-ignore count, coverage), a tier switcher that shows exactly what each autonomy level L0–L3 enables and locks, and a step-through walkthrough of one cycle. Synthetic data; opens in any browser, offline. **[Open it live ▶](https://htmlpreview.github.io/?https://raw.githubusercontent.com/Daily-lesson/EASM_RED/main/operating-model.html)** |

## How a security team is meant to use this

1. Read `docs/PLAN.md`; challenge the assumptions against your own environment.
2. Follow `docs/BUILD_PLAN.md` to build it — one work-package at a time, each
   ending in a reviewed, tested PR, advancing autonomy only as each gate is met.
3. Start at the lowest autonomy phase (report-only), prove the benchmarks, and
   only then grant more autonomy.

## About the name

`EASM_RED` names the *perspective* — reasoning the way an attacker would about
paths to crown jewels — in service of **defence**. It is a blue-team
prioritization and exposure-management tool, not an offensive capability. There
is no exploit code, payload, or attack tooling here or in the system it
describes.

## Scope and safety

This is a **defensive** design. Its verification stages are built around
**authorized, non-destructive, rate-limited, allow-listed** checks bound by
explicit Rules of Engagement, with human gates before anything active and a
fixed ceiling: never autonomous remediation, never a destructive action. See
`docs/PLAN.md` §14.

## Sharing this repository

The document contents carry no organization-specific or personal data and are
safe to share. Two mechanical caveats:

- **The live-dashboard link above depends on this repo staying public** and on
  `htmlpreview.github.io`, a free third-party render proxy for raw GitHub HTML
  — reliable, but not something this repo controls. For a link you control
  outright, enable GitHub Pages on this repo (Settings → Pages → Deploy from
  branch `main`, root) and it will serve at
  `https://daily-lesson.github.io/EASM_RED/operating-model.html` — update the
  link above to that URL once it's on.
- **Keep it data-free.** Never commit real scan output, asset inventories,
  findings, credentials, hostnames, or environment details (the `.gitignore`
  blocks the obvious cases; the discipline is the real control).
