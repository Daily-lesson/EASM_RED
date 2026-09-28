// Pins the reference engine to the claims docs/PLAN.md makes about it.
// Each "never"/"always" claim in the plan has a negative case here that
// makes the bad thing happen and checks the engine refuses it.
// Run: node --test tests/

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import * as E from '../reference/engine.mjs';
import { workedExample, demoEstate } from '../reference/demo-estate.mjs';
import { summarize } from '../reference/summary.mjs';
import { renderBlock, readBlock } from '../reference/build-demo.mjs';

const near = (a, b, eps = 1e-3) => assert.ok(Math.abs(a - b) < eps, `${a} ≉ ${b}`);
const jr = (m, id, opts) => E.jewelRisk(m, opts).find((j) => j.id === id);

// ---------------------------------------------------------------- §7.4 worked example
test('§7.4 worked example: edge likelihoods', () => {
  const m = workedExample();
  const p = Object.fromEntries(m.edges.map((e) => [e.id, E.edgeP(e)]));
  near(p.e1, 0.64);   // KEV: 1.0 · (1-0.2) · WAF (1 - 0.5·(1-0.6)) = 0.8 · 0.8
  near(p.e2, 0.95);
  near(p.e3, 0.95);
  near(p.e4, 0.80);
  near(p.e5, 0.95);
  near(p.e6, 0.266);  // 0.95 · MFA (1 - 0.9·(1-0.2)) = 0.95 · 0.28
});

test('§7.4 worked example: jewel risk and routes', () => {
  const m = workedExample();
  const db = jr(m, 'db-pii');
  near(db.L, 0.5776);          // 1.0 · 0.64 · 0.95 · 0.95
  assert.equal(db.R, 57.8);    // 100 · I(V0)=1.0 · L
  assert.deepEqual(db.route, ['e1', 'e2', 'e3']);
  assert.equal(E.totalRisk(m), 69.0);   // 57.8 + 6.1 (R) + 5.1 (S); W is V3, not a destination
  const all = (removed) => jr(m, 'db-pii', { removed: new Set(removed) });
  assert.equal(all(['e2']).R, 48.6, 'second-best route: internet → W → S → DB');
  assert.deepEqual(all(['e2']).route, ['e1', 'e4', 'e5']);
  assert.equal(all(['e1']).R, 12.0, 'vendor route: 0.5 · 0.266 · 0.95 · 0.95');
});

test('§7.4 a patch on the choke *node* is not a cut: A1 leaves the vendor route open', () => {
  const m = workedExample();
  const after = jr(m, 'db-pii', { removed: new Set(['e1']) });
  assert.ok(after.R > 0, 'PII database must stay reachable after patching only the RCE');
  assert.equal(after.route[0], 'e6', 'the surviving route enters W through the vendor account');
  near(after.L, 0.5 * 0.266 * 0.95 * 0.95);
  assert.equal(E.actionAlone(m, 'A1'), 54.6);
  assert.equal(E.actionAlone(m, 'A2'), 15.3);
  assert.equal(E.actionAlone(m, 'A3'), 0, 'on its own the vendor fix is worth nothing: the RCE route dominates');
  assert.equal(E.actionAlone(m, 'A4'), 69.0, 'segmenting W cuts every route to the database');
});

test('§7.3 greedy plan recomputes on the residual graph', () => {
  const plan = E.planActions(workedExample());
  assert.deepEqual(plan.map((p) => p.id), ['A1', 'A3']);
  assert.equal(plan[0].delta, 54.6);
  assert.deepEqual(plan[0].severs, [], 'A1 alone severs no jewel');
  assert.equal(plan[1].delta, 14.4, 'A3 is worth 0 alone but 14.4 once A1 is done');
  assert.ok(plan[1].severs.includes('db-pii'));
  assert.equal(plan.at(-1).riskAfter, 0);
});

// ---------------------------------------------------------------- scoring properties
const chain = (ps, prior = 1) => ({
  sources: [{ id: 's', entity: 'src', prior }],
  entities: [{ id: 'src', external: true }, ...ps.map((_, i) => ({ id: `n${i}`, tier: i === ps.length - 1 ? 'V0' : undefined, fresh: true }))],
  edges: ps.map((p, i) => ({ id: `e${i}`, from: i ? `n${i - 1}` : 'src', to: `n${i}`, class: 'config', effort: 1 - p })),
  actions: [], findings: [],
});

test('the hardest step governs a route (product, not max/mean)', () => {
  const oneModerate = jr(chain([0.6]), 'n0').R;
  const twoHardSteps = jr(chain([0.95, 0.1, 0.1]), 'n2').R;
  assert.ok(oneModerate > twoHardSteps, `${oneModerate} should outrank ${twoHardSteps}`);
  near(twoHardSteps, 100 * 0.95 * 0.1 * 0.1, 0.1);
  // adding an easy step never makes a route more likely
  assert.ok(jr(chain([0.9, 0.9, 0.9, 0.2]), 'n3').R < jr(chain([0.9, 0.2]), 'n1').R);
});

test('an impossible route scores zero, not a tier floor', () => {
  assert.equal(jr(chain([0.95, 0]), 'n1').R, 0);
});

test('impact tiers are order-of-magnitude: a trivially easy V2 route never outranks a moderate V0 route', () => {
  const m = chain([0.3]);
  const v0 = jr(m, 'n0').R;
  m.entities[1].tier = 'V2';
  m.edges[0].effort = 0; // trivially easy
  const v2 = jr(m, 'n0').R;
  assert.ok(v0 > v2, `${v0} vs ${v2}`);
  m.entities[1].tier = 'V3';
  assert.equal(jr(m, 'n0'), undefined, 'V3 (ephemeral/test) is never a destination');
});

test('two sources on one entity keep the higher prior', () => {
  const m = chain([1]);
  m.sources.push({ id: 's2', entity: 'src', prior: 0.2 });
  assert.equal(jr(m, 'n0').R, 100);
});

test('a jewel the attacker is assumed to start on is scored at its prior, not dropped', () => {
  const m = demoEstate();
  const before = E.totalRisk(m);
  m.sources.push({ id: 'src-x', entity: 'erp-fin', vector: 'leaked-cred', prior: 0.5 });
  assert.equal(jr(m, 'erp-fin').R, 50);
  assert.equal(E.totalRisk(m), E.round(before + 50, 1));
});

test('facts are entity-bound: a credential gained on one host does not unlock another principal', () => {
  const m = {
    sources: [{ id: 's', entity: 'net', prior: 1 }],
    entities: [{ id: 'net', external: true }, { id: 'web', fresh: true, tier: 'V3' }, { id: 'role-a', fresh: true, tier: 'V2' }, { id: 'role-b', fresh: true, tier: 'V2' }, { id: 'db', tier: 'V0', fresh: true }],
    edges: [
      { id: 'x1', from: 'net', to: 'web', class: 'config', effort: 0.1 },
      { id: 'x2', from: 'web', to: 'role-a', class: 'config', effort: 0.1 }, // creds for role-a live on web
      { id: 'x3', from: 'role-b', to: 'db', class: 'trust', effort: 0.05 },  // only role-b can read db
    ],
    actions: [], findings: [],
  };
  assert.equal(jr(m, 'db').R, 0, 'holding "a credential" must not satisfy role-b');
  m.edges.push({ id: 'x4', from: 'web', to: 'role-b', class: 'config', effort: 0.1 });
  assert.ok(jr(m, 'db').R > 0, 'once role-b’s credential is exposed, the route exists');
});

test('AND-edges need every required foothold', () => {
  const m = chain([0.9, 0.9]);
  m.entities.push({ id: 'k', fresh: true });
  m.edges[1].requires = ['k'];
  assert.equal(jr(m, 'n1').R, 0, 'required foothold k is not held');
  m.edges.push({ id: 'ek', from: 'src', to: 'k', class: 'finding', kev: true, effort: 0.5 });
  near(jr(m, 'n1').L, 0.9 * 0.9 * 0.5);
  const j = jr(m, 'n1');
  assert.ok(j.route.includes('ek'), 'the route explanation includes the required foothold’s edge');
  assert.equal(E.decision(m, j.route, j), 'Act', 'a KEV step on the required branch drives the decision');
});

test('monotonic: adding an edge never lowers any jewel risk; removing one never raises it', () => {
  const base = demoEstate();
  const before = new Map(E.jewelRisk(base).map((j) => [j.id, j.R]));
  const plus = demoEstate();
  plus.edges.push({ id: 'zz', from: 'laptops', to: 'pay-svc', class: 'netReach', effort: 0.5 });
  for (const j of E.jewelRisk(plus)) assert.ok(j.R >= before.get(j.id), `${j.id} dropped after adding an edge`);
  for (const e of base.edges) {
    for (const j of E.jewelRisk(base, { removed: new Set([e.id]) })) assert.ok(j.R <= before.get(j.id), `${j.id} rose after removing ${e.id}`);
  }
});

// ---------------------------------------------------------------- unknowns never lower priority
test('unknown effort widens the band; the pessimistic end is used for ranking', () => {
  const m = demoEstate();
  const hi = jr(m, 'legacy-crm', { mode: 'hi' });
  assert.ok(hi && hi.R > 0, 'an unclassified, unmeasured system is ranked, not hidden');
  assert.equal(jr(m, 'legacy-crm', { mode: 'lo' }), undefined, 'optimistically it is not a jewel at all');
  assert.ok(E.totalRisk(m, { mode: 'hi' }) >= E.totalRisk(m, { mode: 'lo' }));
  assert.equal(E.validateQueue(m)[0].id, 'legacy-crm', 'widest band is first in the validate queue');
});

test('stale control evidence is not credited under the pessimistic view', () => {
  const m = demoEstate();
  const e12 = m.edges.find((e) => e.id === 'e12');
  near(E.edgeP(e12, 'hi'), 0.8);
  near(E.edgeP(e12, 'lo'), 0.8 * (1 - 0.9 * 0.9));
  e12.controls[0].evidenceAgeDays = 10; // refresh the evidence
  near(E.edgeP(e12, 'hi'), E.edgeP(e12, 'lo'));
});

// ---------------------------------------------------------------- findings: never "safe to ignore"
const tally = (m) => E.countBy(E.classifyFindings(m), 'status');

test('a feed going dark cannot increase the deferred-with-evidence count', () => {
  const m = demoEstate();
  const before = tally(m)['deferred-covered'];
  m.entities.find((e) => e.id === 'dev-sandbox').fresh = false; // the sandbox's scanner stops reporting
  const after = tally(m);
  assert.ok(after['deferred-covered'] < before, 'lost visibility must move findings OUT of deferred-covered');
  assert.ok(after['deferred-unproven'] > tally(demoEstate())['deferred-unproven']);
});

test('a feed going dark (its edges vanish) freezes deferrals instead of creating them', () => {
  const m = demoEstate();
  const before = tally(m);
  m.edges = m.edges.filter((e) => e.class !== 'netReach'); // network-policy feed stops reporting
  assert.deepEqual(E.feedsDark(m), ['netReach']);
  const after = tally(m);
  assert.ok((after['deferred-covered'] ?? 0) <= before['deferred-covered'], 'deferred-covered must not grow');
  assert.equal(after['deferred-covered'] ?? 0, 0, 'all deferral is suspended while a feed is dark');
});

test('a finding that falls off a route without verified closure is not deferrable', () => {
  const m = demoEstate();
  m.edges = m.edges.filter((e) => e.id !== 'e15'); // one edge disappears, no closure evidence
  assert.deepEqual(E.feedsDark(m), [], 'a single edge is below the feed-health threshold');
  const f = E.classifyFindings(m).find((x) => x.id === 'F-OPEN-SHARE');
  assert.equal(f.status, 'deferred-unproven');
  m.history.closureVerified.push('F-OPEN-SHARE');
  assert.equal(E.classifyFindings(m).find((x) => x.id === 'F-OPEN-SHARE').status, 'deferred-covered');
});

test('unknown effort is judged pessimistically by the decision layer too', () => {
  const m = demoEstate();
  const crm = jr(m, 'legacy-crm');
  assert.equal(E.decision(m, crm.route, crm), 'Attend', 'null effort must not read as "hard"');
});

test('residual floor: KEV, control-plane and compliance-scope findings are never deferred', () => {
  const f = E.classifyFindings(demoEstate());
  const ents = new Map(demoEstate().entities.map((e) => [e.id, e]));
  for (const x of f.filter((x) => x.status.startsWith('deferred'))) {
    assert.ok(!x.kev, `${x.id} is KEV but deferred`);
    assert.ok(!ents.get(x.entity).controlPlane, `${x.id} is on the control plane but deferred`);
    assert.ok(!ents.get(x.entity).complianceScope, `${x.id} is in compliance scope but deferred`);
  }
  assert.equal(f.find((x) => x.id === 'B-sandbox-kev').status, 'floor');
});

test('assumed-breach sources matter: removing the phished-laptop source hides real routes', () => {
  const m = demoEstate();
  assert.ok(jr(m, 'hr-share').R > 0);
  m.sources = m.sources.filter((s) => s.vector !== 'phish-endpoint');
  assert.equal(jr(m, 'hr-share').R, 0);
});

// ---------------------------------------------------------------- decision layer
test('decision layer: KEV route to V0 is Act (7 days); SLA table is closed', () => {
  const m = workedExample();
  const db = jr(m, 'db-pii');
  assert.equal(E.decision(m, db.route, db), 'Act');
  assert.equal(E.SLA_DAYS.Act, 7);
  for (const r of summarize(demoEstate()).routes) assert.ok(r.decision in E.SLA_DAYS);
});

// ---------------------------------------------------------------- the console can't drift
test('operating-model.html carries exactly the engine’s current output', () => {
  const html = readFileSync(new URL('../operating-model.html', import.meta.url), 'utf8');
  assert.equal(readBlock(html).json, renderBlock(), 'run: node reference/build-demo.mjs');
});

test('console data is internally consistent', () => {
  const s = summarize(demoEstate());
  const t = s.trend;
  assert.equal(t.exposureIndex.at(-1), s.exposure.total, 'trend ends at the computed exposure');
  assert.equal(t.criticalReachable.at(-1), s.exposure.criticalReachable);
  assert.equal(t.openFindings.at(-1), s.findings.total);
  for (const k of Object.keys(t)) if (k !== 'movement') assert.equal(t[k].length, 12, `${k} has 12 weeks`);
  for (const k of Object.keys(t.movement)) assert.equal(t.movement[k].length, 12, `movement.${k} has 12 weeks`);
  const byStatus = Object.values(s.findings.byStatus).reduce((a, b) => a + b, 0);
  assert.equal(byStatus, s.findings.total);
  const c = s.governance.complianceClock;
  assert.equal(c.onTime + c.dueSoon + c.overdue, c.total, 'compliance clock split sums to its total');
  for (const p of s.plan) assert.ok(p.id in s.governance.ticketAgeDays, `${p.id} has a ticket age`);
  assert.ok(s.afterTop3.total < s.exposure.total && s.afterPlan.total <= s.afterTop3.total);
  const svc = s.services.reduce((a, x) => a + x.critical + x.other, 0);
  near(svc, s.exposure.total, 0.2);
});

test('README one-page brief matches the engine', () => {
  const md = readFileSync(new URL('../README.md', import.meta.url), 'utf8');
  const a = md.indexOf('<!-- brief:start');
  const b = md.indexOf('<!-- brief:end -->');
  assert.ok(a >= 0 && b > a, 'brief markers present');
  const brief = md.slice(a, b);
  const s = summarize(demoEstate());
  const f = s.findings;
  const pctOf = (n) => `${Math.round((100 * n) / f.total)}%`;
  for (const want of [
    `**${s.exposure.criticalReachable} of ${s.exposure.criticalTotal}**`,
    `**${s.afterTop3.criticalReachable} of ${s.exposure.criticalTotal}**`,
    `**${Math.round((100 * (s.exposure.total - s.afterTop3.total)) / s.exposure.total)}%**`,
    `**${f.needActionPct}%** (${f.needAction} of ${f.total})`,
    `${pctOf(f.byStatus['deferred-covered'])} (${f.byStatus['deferred-covered']})`,
    `${f.unprovenPct}% (${f.byStatus['deferred-unproven']})`,
    `${['Three', 'Four', 'Five'][s.governance.decisions.length - 3] ?? s.governance.decisions.length} decisions`,
  ]) assert.ok(brief.includes(want), `README brief is stale: expected "${want}"`);
});

// ---------------------------------------------------------------- threat debt (PLAN §6.4, D27–D29)
test('adversary relevance: unknown is 1.0, the floor holds, and a step seen in the wild is never discounted', () => {
  const m = workedExample();
  assert.equal(E.totalRisk(m), 69.0, 'no relevance set: every §7.4 number is unchanged');
  const e2 = m.edges.find((e) => e.id === 'e2');
  e2.relevance = 0.8;
  near(E.edgeP(e2), 0.95 * 0.8);
  e2.relevance = 0.05; // below the floor
  near(E.edgeP(e2), 0.95 * E.RELEVANCE_FLOOR, 1e-9);
  assert.ok(E.edgeP(e2) >= 0.95 * 0.5, 'relevance can discount a step by at most half');
  const e1 = m.edges.find((e) => e.id === 'e1'); // KEV
  e1.relevance = 0.5;
  near(E.edgeP(e1), 0.64, 1e-9);
  assert.equal(E.threat(e1), 1.0, 'a known-exploited step ignores the actor model');
  // fail closed: relevance never raises priority above the base, and never removes a route
  e2.relevance = 5;
  near(E.edgeP(e2), 0.95, 1e-9);
  e2.relevance = 0;
  assert.ok(jr(m, 'db-pii').R > 0, 'zero relevance cannot make a route disappear');
  // fail closed on garbage: an unparseable enrichment value is "unknown", never NaN
  for (const bad of [NaN, 'n/a', 'abc', Infinity, {}, []]) {
    e2.relevance = bad;
    assert.equal(E.relevance(e2), 1.0, `relevance ${String(bad)} reads as unknown`);
  }
  e2.relevance = 'n/a';
  assert.equal(E.totalRisk(m), 69.0, 'a bad value leaves every number as if unset');
  assert.ok(Number.isFinite(jr(m, 'db-pii').R) && jr(m, 'db-pii').R > 0, 'no NaN reaches a route');
  // the exemption is by evidence, not by class: an active-exploitation trust edge is never discounted either
  assert.equal(E.threat({ class: 'trust', exploitation: 'active', relevance: 0.5 }), 1.0);
  assert.equal(E.threat({ class: 'config', kev: true, relevance: 0.5 }), 1.0);
  // the bound is per step and compounds: k discounted steps can drop a route by up to 0.5^k, never to zero
  const w = workedExample();
  for (const e of w.edges) if (!e.kev) e.relevance = 0;
  near(jr(w, 'db-pii').R, 57.8 * 0.25, 0.1);
});

test('threat debt by weakness class: ΔR per class, non-additive by design, and the residual is real', () => {
  const m = demoEstate();
  const rows = E.debtByClass(m);
  const total = E.totalRisk(m);
  assert.deepEqual(rows.map((r) => r.class), [...E.EDGE_CLASSES, 'stale-controls']);
  for (const r of rows) assert.ok(r.delta >= 0 && r.delta <= total, `${r.class} in [0, R(G)]`);
  assert.ok(rows.reduce((a, r) => a + r.delta, 0) > total, 'classes overlap: their sum exceeds R(G), which is why they are never summed on the console');
  const finding = rows.find((r) => r.class === 'finding');
  const noFindings = new Set(m.edges.filter((e) => e.class === 'finding').map((e) => e.id));
  assert.equal(finding.delta, E.round(total - E.totalRisk(m, { removed: noFindings }), 1));
  assert.ok(finding.routes <= E.jewelRisk(m).filter((j) => j.R > 0).length, 'route counts are bounded by jewels, never enumerated paths');
  // mutation: removing every classed edge leaves no debt
  const all = new Set(m.edges.map((e) => e.id));
  assert.equal(E.totalRisk(m, { removed: all }), 0);
  // the stale-controls row is exactly the debt a re-verification would settle
  const stale = rows.find((r) => r.class === 'stale-controls');
  const fresh = demoEstate();
  for (const e of fresh.edges) for (const c of e.controls ?? []) c.evidenceAgeDays = 0;
  assert.equal(stale.delta, E.round(total - E.totalRisk(fresh), 1));
  assert.ok(stale.delta > 0, 'the demo estate carries stale control evidence (the consent policy)');
});

test('threat debt held down by each control: credited controls hold down risk, stale ones hold down 0 and say so', () => {
  const m = demoEstate();
  const rows = E.debtByControl(m);
  const byType = Object.fromEntries(rows.map((r) => [r.type, r]));
  assert.ok(byType.WAF.holdsDown > 0 && !byType.WAF.stale);
  assert.equal(byType['consent-policy'].holdsDown, 0, 'stale evidence is not credited, so it holds nothing down today');
  assert.ok(byType['consent-policy'].stale && byType['consent-policy'].ifVerified > 0, 'but it says what re-verification would buy');
  for (const r of rows) if (!r.stale) assert.equal(r.ifVerified, r.holdsDown, `${r.type}: a fresh control's "if verified" is what it holds down today`);
  assert.equal(byType.MFA.holdsDown, 0, 'MFA on the vendor route holds down nothing while the internet route dominates (the A3 lesson)');
  const afterA1 = demoEstate(); afterA1.edges = afterA1.edges.filter((e) => e.id !== 'e1');
  assert.ok(E.debtByControl(afterA1).find((r) => r.type === 'MFA').holdsDown > 0, 'once the easier route is cut, the same control holds debt down');
  for (let i = 1; i < rows.length; i++) assert.ok(rows[i - 1].holdsDown >= rows[i].holdsDown, 'sorted by what is held down');
  // mutation: refresh the stale evidence and the control starts holding debt down
  for (const e of m.edges) for (const c of e.controls ?? []) if (c.type === 'consent-policy') c.evidenceAgeDays = 1;
  assert.ok(E.debtByControl(m).find((r) => r.type === 'consent-policy').holdsDown > 0);
});

test('threat-debt movement reconciles to the index every week, and the console block carries it', () => {
  const s = summarize(demoEstate());
  const t = s.trend, mv = t.movement;
  for (let i = 1; i < t.weeks.length; i++) {
    const delta = E.round(t.exposureIndex[i] - t.exposureIndex[i - 1], 1);
    near(mv.added[i] - mv.severed[i] + mv.reclassified[i], delta, 0.051);
    assert.ok(mv.severed[i] >= 0 && mv.added[i] >= 0, `week ${i}: no negative retirement or addition`);
  }
  assert.equal(mv.severed.at(-1), demoEstate().trend.movement.severed.at(-1), 'the final week’s retirement is recorded, never derived');
  assert.equal(s.threatDebt.index, s.exposure.total, 'threat debt IS the exposure index, not a second score');
  assert.equal(s.threatDebt.priorIndex, t.exposureIndex.at(-2));
  assert.equal(s.threatDebt.thisPeriod.severed, mv.severed.at(-1));
  // in flight is one joint ΔR of the ticketed set, not a sum of order-dependent plan deltas
  const m = demoEstate();
  const ticketed = new Set(m.actions.filter((a) => a.id in m.governance.ticketAgeDays).flatMap((a) => a.removesEdges));
  assert.equal(s.threatDebt.inFlight, E.round(E.totalRisk(m) - E.totalRisk(m, { removed: ticketed }), 1));
  const partial = demoEstate(); delete partial.governance.ticketAgeDays.A1;
  const want = E.round(E.totalRisk(partial) - E.totalRisk(partial, { removed: new Set(['e7', 'e6', 'e8', 'e12', 'e11']) }), 1);
  assert.equal(summarize(partial).threatDebt.inFlight, want, 'without A1 ticketed, A3’s conditional plan delta is not counted as in flight');
  assert.ok(s.threatDebt.inFlight <= s.exposure.total - s.afterPlan.total + 1e-9, 'debt in flight never exceeds what the whole plan removes');
  // mutation: a movement that does not sum is caught
  const bad = demoEstate();
  bad.trend.movement.added[3] += 1;
  const sb = summarize(bad).trend;
  assert.ok(Math.abs(sb.movement.added[3] - sb.movement.severed[3] + sb.movement.reclassified[3] - (sb.exposureIndex[3] - sb.exposureIndex[2])) > 0.5);
  // mutation: the derived week fails closed — a residual that would need a negative addition is refused, never plugged
  const over = demoEstate();
  over.trend.movement.severed[11] = 5; // recorded retirement smaller than the fall
  assert.throws(() => summarize(over), /record the movement, do not plug it/);
  const neg = demoEstate();
  neg.trend.movement.severed[4] = -1;
  assert.throws(() => summarize(neg), /negative retirement/);
});

test('PLAN §6.4 worked numbers match the engine', () => {
  const md = readFileSync(new URL('../docs/PLAN.md', import.meta.url), 'utf8');
  const a = md.indexOf('<!-- worked:start');
  const b = md.indexOf('<!-- worked:end -->');
  assert.ok(a >= 0 && b > a, 'worked-numbers markers present');
  const text = md.slice(a, b);
  const td = summarize(demoEstate()).threatDebt;
  const f = (n) => n.toFixed(1);
  const cls = Object.fromEntries(td.byClass.map((r) => [r.class, r]));
  const ctl = Object.fromEntries(td.controls.map((r) => [r.type, r]));
  for (const want of [
    `the index is ${f(td.index)} (optimistic ${f(td.indexLo)})`,
    `down from ${f(td.priorIndex)}`,
    `${f(td.thisPeriod.severed)} retired, ${f(td.thisPeriod.added)} added`,
    `misconfigurations ${f(cls.config.delta)} (${cls.config.routes} routes)`,
    `vulnerabilities ${f(cls.finding.delta)} (${cls.finding.routes})`,
    `identity & access ${f(cls.trust.delta)} (${cls.trust.routes})`,
    `network exposure ${f(cls.netReach.delta)} (${cls.netReach.routes})`,
    `unverified controls ${f(cls['stale-controls'].delta)} (${cls['stale-controls'].routes})`,
    `web application firewall ${f(ctl.WAF.holdsDown)}`,
    `network segmentation ${f(ctl.segmentation.holdsDown)}`,
    `endpoint detection ${f(ctl.EDR.holdsDown)}`,
    `app consent policy ${ctl['consent-policy'].holdsDown}`,
    `${f(ctl['consent-policy'].ifVerified)} once re-verified`,
    `vendor account ${ctl.MFA.holdsDown}`,
    `Debt with a fix in flight: ${f(td.inFlight)}`,
  ]) assert.ok(text.includes(want), `PLAN §6.4 is stale: expected "${want}"`);
});

const EXEC_BANNED = ['κ', 'PRS', 'min-cut', 'T1190', 'ATT&CK', 'EPSS', 'Tier-0', 'V0', 'RCE', 'PoC', 'OAuth', 'L0', 'L1', 'Level 1', 'top-10', 'KEV', 'CVE', 'ΔR', 'R(G)'];

function assertJargonFree(viewId) {
  const html = readFileSync(new URL('../operating-model.html', import.meta.url), 'utf8');
  const a = html.indexOf(`<section id="${viewId}"`);
  const b = html.indexOf(`</section><!-- /${viewId} -->`);
  assert.ok(a > 0 && b > a, `${viewId} section markers present`);
  const s = summarize(demoEstate());
  // every data string the leadership views render
  const rendered = [
    html.slice(a, b),
    ...s.plan.flatMap((p) => [p.plain, p.owner, p.protects]),
    ...s.governance.decisions.flatMap((d) => [d.ask, d.owner, d.evidence]),
    s.governance.complianceClock.label, s.governance.triageHoursPerWeek.note,
    ...s.services.map((x) => x.service),
    ...s.threatDebt.byClass.map((r) => r.label),
    ...s.threatDebt.controls.map((r) => r.label),
  ];
  for (const text of rendered) for (const term of EXEC_BANNED) {
    assert.ok(!text.includes(term), `${viewId} shows jargon "${term}" in: ${text}`);
  }
}

test('the executive view uses no analyst jargon (markup and rendered data)', () => assertJargonFree('view-exec'));
test('the threat-debt view uses no analyst jargon (markup, rendered data and the renderer’s own copy)', () => {
  assertJargonFree('view-debt');
  const html = readFileSync(new URL('../operating-model.html', import.meta.url), 'utf8');
  const a = html.indexOf('/* ================= THREAT DEBT ================= */');
  const b = html.indexOf('/* ================= AUTONOMY');
  assert.ok(a > 0 && b > a, 'renderDebt markers present');
  // the string literals the renderer writes into the page
  const literals = html.slice(a, b).match(/'([^'\\]|\\.)*'/g) ?? [];
  for (const lit of literals) for (const term of EXEC_BANNED) assert.ok(!lit.includes(term), `renderDebt copy shows jargon "${term}" in: ${lit}`);
});
