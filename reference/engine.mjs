// Reference scoring engine for the APM design (docs/PLAN.md §5–§7).
//
// This is a *specification you can run*, not the product. It exists so that
// every number in PLAN.md and operating-model.html is computed from the
// formulas rather than typed by hand, and so the formulas are pinned by tests
// (tests/engine.test.mjs). Dependency-free; Node 18+.
//
// Model in one paragraph: attacker positions are *entity-bound* facts (a
// foothold on a host, a credential for a principal, the right to assume a
// role) — never a global capability set. Each edge has a traversal likelihood
// p(e) in [0,1]. A route's likelihood is the source's prior times the product
// of its edges' p (the hardest step governs). A jewel's risk is its impact
// weight times its most-likely route. A remediation *action* removes specific
// edges; its value is the drop in total risk when those edges go, recomputed
// greedily on what remains. Unknowns widen a [lo, hi] band — they never lower
// priority.

/** Impact weight per value tier — order-of-magnitude spacing (PLAN §7.2). */
export const IMPACT = Object.freeze({ V0: 1.0, V1: 0.3, V2: 0.1, V3: 0.01 });

/** Conservative / optimistic stand-ins for an unknown effort (PLAN §7.4). */
export const UNKNOWN_EFFORT = Object.freeze({ hi: 0.2, lo: 0.9 });

/** Tier assumed for an unclassified asset: V1 when pessimistic, not a jewel when optimistic. */
export const UNKNOWN_TIER = Object.freeze({ hi: 'V1', lo: null });

/** Threat term t(e) for an edge (PLAN §7.1). Config/trust/network edges need no exploit: 1.0. */
export function threat(edge) {
  if (edge.class !== 'finding') return 1.0;
  if (edge.kev || edge.exploitation === 'active') return 1.0;
  if (edge.exploitation === 'poc') return 0.6;
  // EPSS percentile, floored: EPSS is a 30-day in-the-wild signal, not path ease.
  return Math.max(0.1, edge.epssPercentile ?? 0.1);
}

/** Is a control's evidence still fresh? Stale evidence is treated as unknown. */
function controlFresh(c) {
  return c.evidenceAgeDays == null || c.ttlDays == null || c.evidenceAgeDays <= c.ttlDays;
}

/**
 * Traversal likelihood p(e) under 'hi' (pessimistic) or 'lo' (optimistic) assumptions.
 *   p(e) = t(e) · (1 − effort(e)) · Π_controls (1 − coverage · (1 − bypass))
 * A control whose evidence is stale is ignored under 'hi' and applied under 'lo'.
 */
export function edgeP(edge, mode = 'hi') {
  const effort = edge.effort == null ? UNKNOWN_EFFORT[mode] : edge.effort;
  let p = threat(edge) * (1 - effort);
  for (const c of edge.controls ?? []) {
    if (mode === 'hi' && !controlFresh(c)) continue;
    p *= 1 - c.coverage * (1 - c.bypass);
  }
  return clamp01(p);
}

/** The tier used for scoring an entity under a mode (unknown tier widens the band). */
export function tierOf(entity, mode = 'hi') {
  if (entity.tier) return entity.tier;
  return entity.controlPlane ? 'V0' : UNKNOWN_TIER[mode];
}

/**
 * Monotonic max-product fixpoint (PLAN §5.2). Returns Map<entityId, {L, via}>
 * where L is the best likelihood of holding a foothold on that entity and
 * `via` is the edge that achieved it. Gained footholds are never lost
 * (monotonicity), so this terminates in at most |E| relaxation rounds.
 * An edge with `requires: [entityId…]` is an AND-edge: it is usable only when
 * every required foothold is also held, and its likelihood is multiplied by them.
 */
export function reach(model, { removed = new Set(), mode = 'hi' } = {}) {
  const best = new Map();
  for (const s of model.sources) {
    // two sources on one entity: keep the higher prior
    const cur = best.get(s.entity);
    if (!cur || s.prior > cur.L) best.set(s.entity, { L: s.prior, via: null, source: s.id });
  }
  const edges = model.edges.filter((e) => !removed.has(e.id));
  for (let round = 0; round <= edges.length; round++) {
    let changed = false;
    for (const e of edges) {
      const from = best.get(e.from);
      if (!from) continue;
      let L = from.L * edgeP(e, mode);
      for (const r of e.requires ?? []) {
        const held = best.get(r);
        if (!held) { L = 0; break; }
        L *= held.L;
      }
      if (L <= 0) continue;
      const cur = best.get(e.to);
      if (!cur || L > cur.L + 1e-12) {
        best.set(e.to, { L, via: e.id, source: from.source });
        changed = true;
      }
    }
    if (!changed) break;
  }
  return best;
}

/** Reconstruct the most-likely route (list of edge ids) that reached an entity. */
export function routeTo(model, best, entityId) {
  // Includes the routes to every AND-edge's required footholds, so the
  // explanation, the decision layer and the "hardest step" see all of them.
  const byId = new Map(model.edges.map((e) => [e.id, e]));
  const route = [];
  const seen = new Set();
  const visit = (id) => {
    const cur = best.get(id);
    if (!cur || !cur.via || seen.has(cur.via)) return;
    seen.add(cur.via);
    const e = byId.get(cur.via);
    for (const r of e.requires ?? []) visit(r);
    visit(e.from);
    route.push(e.id);
  };
  visit(entityId);
  return route;
}

/** Tiers that are route destinations. V3 (ephemeral/test) is never a destination. */
export const DESTINATION_TIERS = Object.freeze(['V0', 'V1', 'V2']);

/**
 * Jewels = route destinations: V0–V2, the control plane, and (pessimistically)
 * unclassified jewel candidates as V1. A jewel that is also a source (the
 * attacker is assumed to start there) is scored at its prior — not dropped.
 */
export function jewels(model, mode = 'hi') {
  return model.entities.filter((en) => {
    if (en.external) return false;
    if (!en.tier && !en.controlPlane && !(mode === 'hi' && en.jewelCandidate)) return false;
    return DESTINATION_TIERS.includes(tierOf(en, mode));
  });
}

/**
 * Risk per jewel: R_j = 100 · I(tier_j) · L*_j, where L*_j is the most-likely
 * route's likelihood. Returned with the route for explanation.
 */
export function jewelRisk(model, { removed = new Set(), mode = 'hi' } = {}) {
  const best = reach(model, { removed, mode });
  return jewels(model, mode).map((en) => {
    const tier = tierOf(en, mode);
    const hit = best.get(en.id);
    const L = hit ? hit.L : 0;
    return {
      id: en.id,
      name: en.name,
      tier,
      service: en.service,
      controlPlane: !!en.controlPlane,
      L: round(L, 4),
      R: round(100 * IMPACT[tier] * L, 1),
      route: hit ? routeTo(model, best, en.id) : [],
      source: hit ? hit.source : null,
    };
  });
}

/** Total estate risk R(G) = Σ_j R_j (the "exposure index"). */
export function totalRisk(model, opts = {}) {
  return round(jewelRisk(model, opts).reduce((a, j) => a + j.R, 0), 1);
}

/**
 * Greedy remediation plan (PLAN §7.3). Each round picks the action with the
 * largest risk reduction per unit cost on the *residual* graph, so the second
 * pick is the best given the first is done. Greedy set-cover is an
 * ln(n)-approximation — good enough to rank, not a proof of optimality.
 */
export function planActions(model, { mode = 'hi', limit = Infinity } = {}) {
  const removed = new Set();
  const remaining = [...model.actions];
  const plan = [];
  let before = totalRisk(model, { removed, mode });
  while (remaining.length && plan.length < limit) {
    let pick = null;
    for (const a of remaining) {
      const trial = new Set([...removed, ...a.removesEdges]);
      const after = totalRisk(model, { removed: trial, mode });
      const delta = round(before - after, 1);
      const score = delta / a.cost;
      if (!pick || score > pick.score + 1e-9 || (Math.abs(score - pick.score) < 1e-9 && a.cost < pick.action.cost)) {
        pick = { action: a, delta, after, score };
      }
    }
    if (!pick || pick.delta <= 0) break;
    const severs = jewelRisk(model, { removed, mode })
      .filter((j) => j.R > 0)
      .filter((j) => {
        const trial = new Set([...removed, ...pick.action.removesEdges]);
        const after = jewelRisk(model, { removed: trial, mode }).find((x) => x.id === j.id);
        return !after || after.R === 0;
      })
      .map((j) => j.id);
    for (const e of pick.action.removesEdges) removed.add(e);
    remaining.splice(remaining.indexOf(pick.action), 1);
    plan.push({
      id: pick.action.id,
      label: pick.action.label,
      plain: pick.action.plain ?? pick.action.label,
      owner: pick.action.owner,
      cost: pick.action.cost,
      riskBefore: before,
      delta: pick.delta,
      riskAfter: pick.after,
      perCost: round(pick.score, 1),
      severs,
    });
    before = pick.after;
  }
  return plan;
}

/** Value of each action on the *full* graph, independent of order (for "what if only this"). */
export function actionAlone(model, actionId, mode = 'hi') {
  const a = model.actions.find((x) => x.id === actionId);
  const before = totalRisk(model, { mode });
  const after = totalRisk(model, { removed: new Set(a.removesEdges), mode });
  return round(before - after, 1);
}

/**
 * Human decision layer: a simplified SSVC-style decision for a route
 * (CISA SSVC deployer tree, reduced to the decision points this model holds).
 * The adopting team should replace this with their own full tree.
 */
export function decision(model, route, jewel) {
  const es = route.map((id) => model.edges.find((e) => e.id === id));
  // A misconfiguration or trust edge usable with no skill counts like a public exploit.
  const eff = (e) => e.effort ?? UNKNOWN_EFFORT.hi; // unknown effort is judged pessimistically, as in scoring
  const trivial = (e) => e.class !== 'finding' && eff(e) <= 0.05;
  const exploitation = es.some((e) => e.kev || e.exploitation === 'active')
    ? 'active'
    : es.some((e) => e.exploitation === 'poc' || trivial(e)) ? 'poc' : 'none';
  const automatable = es.length > 0 && es.every((e) => eff(e) <= 0.2);
  const high = jewel.tier === 'V0' || jewel.controlPlane;
  const medium = jewel.tier === 'V1';
  if (high && (exploitation === 'active' || (automatable && exploitation !== 'none'))) return 'Act';
  if (exploitation === 'active' || (automatable && (high || medium)) || (exploitation === 'poc' && high)) return 'Attend';
  if (exploitation === 'poc' || high) return 'Track*';
  return 'Track';
}

/** SLA days per decision (PLAN §10). Compliance clocks run independently. */
export const SLA_DAYS = Object.freeze({ Act: 7, Attend: 30, 'Track*': 90, Track: null });

/**
 * Classify every finding (PLAN §6.2). Never "safe to ignore":
 *   on-route         — enables an edge on a route that reaches a jewel
 *   floor            — off-route, but a residual-floor rule still requires action
 *   deferred-covered — off-route, and the asset and its neighbours have fresh evidence
 *   deferred-unproven— off-route only because we cannot see enough; never counted as deferrable
 */
/**
 * Feed health (PLAN §4.2): edge classes whose count fell more than 30% below
 * the last cycle's baseline. A dark feed makes edges vanish, which would
 * otherwise make findings look off-route — so any dark feed suspends deferral.
 */
export function feedsDark(model) {
  const base = model.feedBaseline ?? {};
  const now = {};
  for (const e of model.edges) now[e.class] = (now[e.class] ?? 0) + 1;
  return Object.keys(base).filter((k) => (now[k] ?? 0) < 0.7 * base[k]);
}

export function classifyFindings(model, { mode = 'hi' } = {}) {
  const best = reach(model, { mode });
  const frozen = feedsDark(model).length > 0;
  // a finding that was on a route last cycle stays unproven until closure is verified (PLAN §10.4)
  const wasOnRoute = new Set(model.history?.onRoute ?? []);
  const closed = new Set(model.history?.closureVerified ?? []);
  const jewelIds = new Set(jewels(model, mode).map((j) => j.id));
  // entities that can reach some jewel (reverse reachability over live edges)
  const canReachJewel = new Set(jewelIds);
  let grew = true;
  while (grew) {
    grew = false;
    for (const e of model.edges) {
      if (canReachJewel.has(e.to) && !canReachJewel.has(e.from)) { canReachJewel.add(e.from); grew = true; }
    }
  }
  const onRouteFindings = new Set();
  for (const e of model.edges) {
    if (best.has(e.from) && canReachJewel.has(e.to)) for (const f of e.findings ?? []) onRouteFindings.add(f);
  }
  const ent = new Map(model.entities.map((x) => [x.id, x]));
  const neighbours = (id) => model.edges.filter((e) => e.from === id || e.to === id).map((e) => (e.from === id ? e.to : e.from));
  const covered = (id) => {
    const self = ent.get(id);
    if (!self || !self.fresh || !(self.tier || self.controlPlane)) return false;
    return neighbours(id).every((n) => ent.get(n)?.fresh ?? true);
  };
  return model.findings.map((f) => {
    const en = ent.get(f.entity);
    let status;
    if (onRouteFindings.has(f.id)) status = 'on-route';
    else if (f.kev || en.controlPlane || en.complianceScope) status = 'floor';
    else if (frozen) status = 'deferred-unproven';
    else if (wasOnRoute.has(f.id) && !closed.has(f.id)) status = 'deferred-unproven';
    else if (covered(f.entity)) status = 'deferred-covered';
    else status = 'deferred-unproven';
    return { ...f, status };
  });
}

/** Tally helper. */
export function countBy(items, key) {
  const out = {};
  for (const it of items) out[it[key]] = (out[it[key]] ?? 0) + (it.count ?? 1);
  return out;
}

/** Coverage (PLAN §6.1): share of in-scope entities that are tiered AND have fresh evidence. */
export function coverage(model) {
  const inScope = model.entities.filter((e) => !e.external);
  const ok = inScope.filter((e) => (e.tier || e.controlPlane) && e.fresh);
  return { assets: inScope.length, visible: ok.length, pct: round((100 * ok.length) / inScope.length, 0), blindSpots: inScope.filter((e) => !(e.tier || e.controlPlane) || !e.fresh).map((e) => e.id) };
}

/**
 * Validate queue (PLAN §9): jewels ordered by how much a check would tell us —
 * the width of the band (hi − lo). Uncertainty buys a check, never a demotion.
 */
export function validateQueue(model) {
  const hi = jewelRisk(model, { mode: 'hi' });
  const lo = new Map(jewelRisk(model, { mode: 'lo' }).map((j) => [j.id, j]));
  return hi
    .map((j) => ({ id: j.id, name: j.name, hi: j.R, lo: lo.get(j.id)?.R ?? 0, width: round(j.R - (lo.get(j.id)?.R ?? 0), 1) }))
    .filter((j) => j.width > 0)
    .sort((a, b) => b.width - a.width);
}

export function clamp01(x) { return Math.max(0, Math.min(1, x)); }
export function round(x, dp) { const k = 10 ** dp; return Math.round(x * k) / k; }
