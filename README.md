# EASM_RED — Risk-Based Attack Path Management (APM) Agent

**A design blueprint, build plan and runnable reference for an agent that turns
"CVE overload" into a short, ordered set of remediation actions that remove the
most risk to critical systems per unit of effort — and shows leadership whether
that risk is going down.**

### [▶ Open the live dashboard](https://daily-lesson.github.io/EASM_RED/operating-model.html)
One click, opens in your browser — an **executive view** leadership can read in a minute, the **threat debt** view (the same exposure read as a balance), the analyst console, the two-axis autonomy ladder, and a one-cycle walkthrough. No install, no clone.

<!-- brief:start — numbers are computed by reference/ and pinned by tests/engine.test.mjs -->
## The one-page brief

**The problem.** Vulnerability management is a losing race: an unbounded list of CVEs, most of which lead nowhere that matters. A small team cannot work that list.

**The idea.** Stop ranking bugs; rank the *routes* an attacker could take to the systems that matter, and the few fixes that break the most of them. Routes are finite. Bugs are not.

**What it looks like** (synthetic demo estate, computed by the reference engine):

| | |
|---|---|
| Critical systems an attacker could reach today | **4 of 7** |
| After the next three planned fixes | **2 of 7**, and overall exposure down **81%** |
| Open findings that need action now | **13%** (69 of 543) |
| Open findings deferred with evidence | 37% (203), re-checked weekly |
| Open findings waiting on visibility | 50% (271): two unclassified systems. That's a funding decision, not a backlog |

The three fixes are ordinary and cheap. Patch one internet-facing server, make one archive private, and replace one leaked supplier password. The order matters: on its own, the server patch leaves the supplier-password route open, and the model shows that.

**What leadership owns.** Three decisions, each with an owner, a date and evidence:
- approve each step up in the tool's autonomy, only once its safety bar is met;
- escalate overdue fixes;
- fund visibility where the unknowns are.

**What the tool will never do.** Apply a fix, take a destructive action, use access it gains, read business data, or hide from the SOC. Its checks are announced to the SOC and are meant to trip detections.

**Build or buy.** Commercial products cover much of this. `docs/PLAN.md` §1.4 gives a neutral rubric for choosing between build, buy and buy-and-extend.
<!-- brief:end -->

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
| `docs/PLAN.md` | **The single design document.** Starts with §0, the revision-2 table of every flaw an adversarial five-role review found and the evidence-backed fix. Then the operating model and RACI, build-vs-buy, the entity-bound reasoning engine, the likelihood × impact score, finding statuses (never "safe to ignore"), the two-axis autonomy ladder with numeric gates and automatic demotion, platform security, governance, metrics, and the decision log. |
| `docs/BUILD_PLAN.md` | The execution plan: a platform-security milestone before any real data, an MVP slice, an evaluation harness, work-packages with acceptance tests, estimates, and a pilot. |
| `operating-model.html` | Self-contained **mock console**. *Executive*: posture sentence, critical systems reachable, exposure trend vs target, what the next fixes buy, deadline health, exposure by business service, decisions needed. *Threat debt*: the same exposure read as a balance — its weekly movement (added / retired / reclassified), how it is calculated, where it comes from by kind of weakness, what each control is holding down, and the single best next fix (`docs/PLAN.md` §6.4). *Analyst*: the greedy action plan, top routes with per-step likelihoods, finding statuses, validate-next queue. *Autonomy & safety*: both axes, gates, demotion. *How it works*: a step-through of one cycle. Synthetic data; opens offline. **[Open it live ▶](https://daily-lesson.github.io/EASM_RED/operating-model.html)** |
| `reference/` | A dependency-free **runnable specification** of the scoring (`engine.mjs`), the synthetic estate (`demo-estate.mjs`), and `build-demo.mjs`, which writes the console's data block. Every number in the plan and the console comes from here. |
| `tests/` | `npm test` pins every worked-example number and every "never" claim with a negative case, and fails if the console's data drifts from the engine. |
| `.github/workflows/` | `pages.yml` publishes the console to GitHub Pages on push to `main`. `check.yml` runs the tests on every PR. |

## How a security team is meant to use this

1. Read `docs/PLAN.md` §0 first — it is the fastest way to see what a naive
   attack-path design gets wrong. Then challenge the rest against your estate.
2. Decide **build, buy or buy-and-extend** with the neutral rubric in `PLAN.md`
   §1.4. The same rubric scores commercial exposure-management products and
   this design's own build estimate.
3. If you build (or extend): follow `docs/BUILD_PLAN.md`, platform security first, then an
   MVP slice at T0/W0 in shadow mode against your current process. Advance each
   autonomy axis only on its numeric gate; the system demotes itself.
4. Run `npm test` (Node 18+, no dependencies) to see the scoring model's claims
   executed.

## About the name

`EASM_RED` names the *perspective* — reasoning the way an attacker would about
paths to crown jewels — in service of **defence**. It is a blue-team
prioritization and exposure-management tool, not an offensive capability. There
is no exploit code, payload, or attack tooling here or in the system it
describes.

## Scope and safety

This is a **defensive** design. Validation uses the least contact that answers
the question, is deconflicted with the SOC (never suppressed), and is enforced
by an external policy point, per-rung credentials and network egress locks. The
fixed ceiling holds at every level: never applies a fix, never a destructive
action, never uses a gained foothold, never reads business data. The platform
itself is treated as a critical system. See `docs/PLAN.md` §12 and §14.

## Sharing this repository

The document contents carry no organization-specific or personal data and are
safe to share. Three ways to hand it to a security team, from cleanest to
most convenient:

1. **Hand over an export of the tree** — no history, no authorship metadata,
   every file the team needs, and `npm test` passes inside it (Node 18+):

   ```
   git archive --format=zip --prefix=EASM_RED/ -o EASM_RED.zip main
   ```

   This is the recommended hand-over. It omits `CLAUDE.md` (repository
   tooling for AI-assisted sessions, not part of the design; `.gitattributes`
   marks it `export-ignore`). The export still carries the
   live-dashboard link above, which points at this repository's GitHub Pages
   site and therefore names the GitHub account that hosts it.
2. **Share the live dashboard link alone** for a first look — the console is
   self-contained and needs no clone.
3. **Give read access to the repository, or make it public** — the same
   files plus the commit history. That history was written with AI
   assistance and says so in its commit trailers (co-author lines and
   session links); the first four commits carry a neutral author identity,
   the later ones do not. If authorship neutrality matters to the audience,
   use option 1, or create a fresh repository from the export with a single
   commit of your own.

Standing rules, whichever way it is shared:

- **The live-dashboard link is served by GitHub Pages**, built by
  `.github/workflows/pages.yml` on every push to `main` — a link this repo
  controls, no third-party proxy involved.
- **Keep it data-free.** Never commit real scan output, asset inventories,
  findings, credentials, hostnames, or environment details (the `.gitignore`
  blocks the obvious cases; the discipline is the real control). A private
  deployment of this design over a real estate belongs in a separate,
  private repository that vendors `reference/engine.mjs` at a pinned commit
  and never contributes its data back here.
