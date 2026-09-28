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
  if (trend && model.trend.movement) {
    // The final week's `added` reconciles the recorded movement to the
    // computed index, the same way the final index point is computed. It is
    // `added`, never `severed`, that is derived: a retirement is a verified
    // closure and is always recorded, so an unexplained residual books as new
    // debt (fail closed, PLAN §2.5). A negative residual means more fell than
    // was recorded as retired — an inconsistent ledger the build refuses.
    const idx = trend.exposureIndex;
    const mv = model.trend.movement;
    const last = idx.length - 1;
    for (let i = 1; i <= last; i++) if (mv.severed[i] < 0) throw new Error(`trend.movement: negative retirement in week ${i}`);
    const added = mv.added.map((v, i) => {
      if (!(i === last && v == null)) return v;
      const residual = E.round((idx[i] - idx[i - 1]) + mv.severed[i] - mv.reclassified[i], 1) || 0; // `|| 0` folds a rounded −0
      if (residual < 0) throw new Error(`trend.movement: week ${i} retired ${mv.severed[i]} but the index fell by more than that minus reclassification (${residual}); record the movement, do not plug it`);
      return residual;
    });
    trend.movement = { added, severed: mv.severed, reclassified: mv.reclassified };
  }

  // Threat debt (PLAN §6.4): the leadership reading of R(G). Same number,
  // attributed two ways, plus this period's movement and the fixes in flight.
  const CLASS_LABEL = { finding: 'Vulnerabilities', config: 'Misconfigurations', trust: 'Identity & access', netReach: 'Network exposure', 'stale-controls': 'Unverified controls' };
  const CONTROL_LABEL = { WAF: 'Web application firewall', MFA: 'Strong sign-in (MFA)', EDR: 'Endpoint detection', segmentation: 'Network segmentation', 'consent-policy': 'App consent policy' };
  // Debt with a fix in flight: what R(G) would lose if every TICKETED action
  // landed — one joint ΔR, not a sum of order-dependent plan deltas.
  const ticketed = model.actions.filter((a) => (model.governance?.ticketAgeDays?.[a.id]) != null);
  const inFlight = total - E.totalRisk(model, { removed: new Set(ticketed.flatMap((a) => a.removesEdges)), mode: 'hi' });
  const lastWeek = trend?.movement ? trend.exposureIndex.length - 1 : null;
  const threatDebt = {
    index: total,
    indexLo: totalLo,
    priorIndex: trend ? trend.exposureIndex.at(-2) : null,
    byClass: E.debtByClass(model, { mode: 'hi' }).map((r) => ({ ...r, label: CLASS_LABEL[r.class] ?? r.class })),
    controls: E.debtByControl(model, { mode: 'hi' }).map((r) => ({ ...r, label: CONTROL_LABEL[r.type] ?? r.type })),
    inFlight: E.round(inFlight, 1),
    thisPeriod: lastWeek == null ? null : {
      added: trend.movement.added[lastWeek],
      severed: trend.movement.severed[lastWeek],
      reclassified: trend.movement.reclassified[lastWeek],
    },
  };

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
    threatDebt,
  };
}
