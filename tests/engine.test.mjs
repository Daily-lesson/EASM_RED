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
  assert.equal(E.totalRisk(m), 69.6);
});

test('§7.4 a patch on the choke *node* is not a cut: A1 leaves the vendor route open', () => {
  const m = workedExample();
  const after = jr(m, 'db-pii', { removed: new Set(['e1']) });
  assert.ok(after.R > 0, 'PII database must stay reachable after patching only the RCE');
  assert.equal(after.route[0], 'e6', 'the surviving route enters W through the vendor account');
  near(after.L, 0.5 * 0.266 * 0.95 * 0.95);
  assert.equal(E.actionAlone(m, 'A1'), 55.1);
  assert.equal(E.actionAlone(m, 'A3'), 0, 'on its own the vendor fix is worth nothing: the RCE route dominates');
  assert.equal(E.actionAlone(m, 'A4'), 69.0, 'segmenting W cuts every route to the database');
});

test('§7.3 greedy plan recomputes on the residual graph', () => {
  const plan = E.planActions(workedExample());
  assert.deepEqual(plan.map((p) => p.id), ['A1', 'A3']);
  assert.equal(plan[0].delta, 55.1);
  assert.deepEqual(plan[0].severs, [], 'A1 alone severs no jewel');
  assert.equal(plan[1].delta, 14.5, 'A3 is worth 0 alone but 14.5 once A1 is done');
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

test('impact tiers are order-of-magnitude: an easy V3 box never outranks a moderate V0 route', () => {
  const m = chain([0.3]);
  const v0 = jr(m, 'n0').R;
  m.entities[1].tier = 'V3';
  m.edges[0].effort = 0; // trivially easy
  const v3 = jr(m, 'n0').R;
  assert.ok(v0 > v3, `${v0} vs ${v3}`);
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
  m.edges.push({ id: 'ek', from: 'src', to: 'k', class: 'config', effort: 0.5 });
  near(jr(m, 'n1').L, 0.9 * 0.9 * 0.5);
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
  for (const k of Object.keys(t)) assert.equal(t[k].length, 12, `${k} has 12 weeks`);
  const byStatus = Object.values(s.findings.byStatus).reduce((a, b) => a + b, 0);
  assert.equal(byStatus, s.findings.total);
  const c = s.governance.complianceClock;
  assert.equal(c.onTime + c.dueSoon + c.overdue, c.total, 'compliance clock split sums to its total');
  for (const p of s.plan) assert.ok(p.id in s.governance.ticketAgeDays, `${p.id} has a ticket age`);
  assert.ok(s.afterTop3.total < s.exposure.total && s.afterPlan.total <= s.afterTop3.total);
  const svc = s.services.reduce((a, x) => a + x.critical + x.other, 0);
  near(svc, s.exposure.total, 0.2);
});

test('the executive view uses no analyst jargon', () => {
  const html = readFileSync(new URL('../operating-model.html', import.meta.url), 'utf8');
  const a = html.indexOf('<section id="view-exec"');
  const b = html.indexOf('</section><!-- /view-exec -->');
  assert.ok(a > 0 && b > a, 'executive view section markers present');
  const exec = html.slice(a, b);
  for (const term of ['κ', 'PRS', 'min-cut', 'T1190', 'ATT&CK', 'EPSS', 'Tier-0', 'V0']) {
    assert.ok(!exec.includes(term), `executive view contains jargon: ${term}`);
  }
});
