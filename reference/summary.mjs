// Builds the data the mock console renders (operating-model.html), entirely
// from the engine. `node reference/build-demo.mjs` writes it into the page;
// tests/engine.test.mjs fails if the page and this output ever disagree.

import * as E from './engine.mjs';

const byId = (xs) => new Map(xs.map((x) => [x.id, x]));

export function summarize(model) {
  const ents = byId(model.entities);
  const edges = byId(model.edges);
  const acts = byId(model.actions);
  const risk = E.jewelRisk(model, { mode: 'hi' });
  const riskLo = byId(E.jewelRisk(model, { mode: 'lo' }));
  const total = E.totalRisk(model, { mode: 'hi' });
  const totalLo = E.totalRisk(model, { mode: 'lo' });
  const plan = E.planActions(model, { mode: 'hi' });

  const critical = risk.filter((j) => j.tier === 'V0' || j.controlPlane);
  const reachable = (list) => list.filter((j) => j.R > 0).length;

  // risk after the first k plan steps, for the before/after view
  const afterSteps = (k) => {
    const removed = new Set(plan.slice(0, k).flatMap((p) => acts.get(p.id).removesEdges));
    const r = E.jewelRisk(model, { removed, mode: 'hi' });
    return { total: E.round(r.reduce((a, j) => a + j.R, 0), 1), criticalReachable: reachable(r.filter((j) => j.tier === 'V0' || j.controlPlane)) };
  };

  // SSVC-style decision + SLA per plan step, from the jewel it helps most
  const decided = plan.map((p, i) => {
    const removedBefore = new Set(plan.slice(0, i).flatMap((q) => acts.get(q.id).removesEdges));
    const removedAfter = new Set([...removedBefore, ...acts.get(p.id).removesEdges]);
    const before = E.jewelRisk(model, { removed: removedBefore, mode: 'hi' });
    const after = byId(E.jewelRisk(model, { removed: removedAfter, mode: 'hi' }));
    const top = before
      .map((j) => ({ j, d: j.R - (after.get(j.id)?.R ?? 0) }))
      .sort((a, b) => b.d - a.d)[0].j;
    const dec = E.decision(model, top.route, top);
    const age = model.governance?.ticketAgeDays?.[p.id] ?? 0;
    const sla = E.SLA_DAYS[dec];
    return { ...p, protects: top.name, protectsTier: top.controlPlane ? 'control plane' : top.tier, decision: dec, slaDays: sla, dueInDays: sla == null ? null : sla - age };
  });

  const findings = E.classifyFindings(model, { mode: 'hi' });
  const fCount = E.countBy(findings, 'status');
  const critDeferred = findings.filter((f) => f.severity === 'critical' && f.status.startsWith('deferred')).reduce((a, f) => a + (f.count ?? 1), 0);
  const totalFindings = findings.reduce((a, f) => a + (f.count ?? 1), 0);

  const routes = risk
    .filter((j) => j.R > 0 && j.route.length)
    .sort((a, b) => b.R - a.R)
    .map((j) => {
      const lo = riskLo.get(j.id);
      return {
        jewel: j.name,
        tier: j.controlPlane ? 'CP' : j.tier,
        service: j.service,
        R: j.R,
        Rlo: lo ? lo.R : 0,
        L: j.L,
        decision: E.decision(model, j.route, j),
        source: model.sources.find((s) => s.id === j.source)?.label,
        steps: j.route.map((id) => {
          const e = edges.get(id);
          return { to: ents.get(e.to).name, technique: e.technique, grants: e.grants, p: E.round(E.edgeP(e, 'hi'), 3), cls: e.class };
        }),
        hardest: j.route.reduce((m, id) => Math.min(m, E.edgeP(edges.get(id), 'hi')), 1),
      };
    });

  const services = {};
  for (const j of risk) {
    if (!j.service) continue;
    const s = (services[j.service] ??= { service: j.service, critical: 0, other: 0 });
    if (j.tier === 'V0' || j.controlPlane) s.critical = E.round(s.critical + j.R, 1);
    else s.other = E.round(s.other + j.R, 1);
  }

  const cov = E.coverage(model);
  const clockTotal = findings
    .filter((f) => ents.get(f.entity)?.complianceScope && (f.severity === 'critical' || f.severity === 'high'))
    .reduce((a, f) => a + (f.count ?? 1), 0);
  const governance = model.governance
    ? { ...model.governance, complianceClock: { ...model.governance.complianceClock, total: clockTotal } }
    : null;
  const trend = model.trend ? {
    ...model.trend,
    exposureIndex: model.trend.exposureIndex.map((v) => (v == null ? total : v)),
    criticalReachable: model.trend.criticalReachable.map((v) => (v == null ? reachable(critical) : v)),
    openFindings: model.trend.openFindings.map((v) => (v == null ? totalFindings : v)),
  } : null;

  return {
    generatedBy: 'reference/build-demo.mjs',
    exposure: { total, totalLo, criticalTotal: critical.length, criticalReachable: reachable(critical) },
    afterTop3: afterSteps(3),
    afterPlan: afterSteps(plan.length),
    plan: decided,
    actionsAlone: model.actions.map((a) => ({ id: a.id, label: a.label, alone: E.actionAlone(model, a.id) })),
    routes,
    services: Object.values(services).sort((a, b) => b.critical + b.other - (a.critical + a.other)),
    findings: {
      total: totalFindings,
      byStatus: fCount,
      criticalDeferred: critDeferred,
      feedsDark: E.feedsDark(model),
      needAction: (fCount['on-route'] ?? 0) + (fCount.floor ?? 0),
      needActionPct: Math.round((100 * ((fCount['on-route'] ?? 0) + (fCount.floor ?? 0))) / totalFindings),
      unprovenPct: Math.round((100 * (fCount['deferred-unproven'] ?? 0)) / totalFindings),
    },
    graph: { edges: model.edges.length, byClass: E.countBy(model.edges, 'class') },
    coverage: cov,
    validateQueue: E.validateQueue(model),
    governance,
    trend,
  };
}
