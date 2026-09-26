# CLAUDE.md — EASM_RED project map

This repository holds the **design, build plan and specification** for a
Risk-Based **Attack Path Management (APM)** agent. It is a shareable,
vendor-neutral starting point intended to be handed to a security team to build
and verify. **It must contain no organization-specific data, credentials,
hostnames, internal architecture, or personal information** — everything here is
generic and safe to share.

## What this repo is (and is not)

- **Is:** one consolidated design document, a build-execution plan, and an
  interactive operating-model visual.
- **Is not:** a running product, an exploit toolkit, or a place for any real
  target's data. No scan output, asset inventory, credentials, or findings from
  any live environment belong here.

## Directory map

| Path | What |
|---|---|
| `README.md` | Overview, problem statement, how a security team uses this. |
| `docs/PLAN.md` | The single design document: operating model, architecture, capability-state graph, reachability, Path Risk Score, autonomy ladder, decision log, production-ready prompt, flow diagrams. |
| `docs/BUILD_PLAN.md` | The build-execution plan (milestones, work-packages, acceptance, safety gates) for a coding session to work through. |
| `operating-model.html` | Self-contained mock console: synthetic dashboard, autonomy-tier switcher (what each of L0–L3 enables/locks), and a step-through walkthrough. |
| `CHANGELOG.md` | Notable changes to the design. |

## Where do I change…?

- **How the system works / architecture / scoring / autonomy / decisions** →
  `docs/PLAN.md` (one document; add a superseding decision entry in §15 rather
  than rewriting an old one).
- **How it gets built / the work-packages** → `docs/BUILD_PLAN.md`.
- **The mock console / visual** → `operating-model.html` (self-contained, no
  external dependencies, theme-aware, synthetic data only; must open offline).

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
