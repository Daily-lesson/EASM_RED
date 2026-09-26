// Synthetic demo estate for the reference engine and the mock console.
// Every name here is invented. No real organization, host, account or finding.
//
// Two views of the same data:
//   workedExample() — the small, hand-checkable graph in docs/PLAN.md §7.4
//   demoEstate()    — the worked example plus enough surrounding estate to
//                     drive the console (six business services, four source
//                     types, blind spots, stale evidence, dead-end findings)

const SOURCES = [
  { id: 'src-internet', entity: 'internet', vector: 'internet', prior: 1.0, label: 'Internet' },
  { id: 'src-vendor', entity: 'vendor-acct', vector: 'leaked-cred', prior: 0.5, label: 'Vendor account (credential seen in a public paste)' },
  { id: 'src-phish', entity: 'laptops', vector: 'phish-endpoint', prior: 0.3, label: 'Staff laptops (assumed phished)' },
  { id: 'src-oauth', entity: 'saas-app', vector: 'saas-oauth', prior: 0.2, label: 'Third-party SaaS app with OAuth consent' },
];

const ENTITIES = [
  // external / source positions (not in the estate's coverage denominator)
  { id: 'internet', name: 'Internet', kind: 'source', external: true, fresh: true },
  { id: 'vendor-acct', name: 'Vendor VPN account', kind: 'identity', external: true, fresh: true },
  { id: 'saas-app', name: 'SaaS app (OAuth)', kind: 'identity', external: true, fresh: true },
  // worked-example core
  { id: 'web-w', name: 'web-host W', kind: 'asset', tier: 'V3', service: 'Customer data', internetFacing: true, fresh: true, owner: 'Platform team' },
  { id: 'role-r', name: 'cloud-role R', kind: 'identity', tier: 'V2', service: 'Customer data', fresh: true, owner: 'Cloud IAM' },
  { id: 'secret-s', name: 'secret-store S', kind: 'asset', tier: 'V2', service: 'Customer data', fresh: true, owner: 'App team' },
  { id: 'db-pii', name: 'Customer PII database', kind: 'data', tier: 'V0', service: 'Customer data', fresh: true, owner: 'Data platform' },
  // surrounding estate
  { id: 'bucket-arch', name: 'Customer archive bucket', kind: 'data', tier: 'V1', service: 'Customer data', internetFacing: true, fresh: true, owner: 'Data platform' },
  { id: 'api-gw', name: 'payments API gateway', kind: 'asset', tier: 'V3', service: 'Payments', internetFacing: true, fresh: true, complianceScope: true, owner: 'Payments eng' },
  { id: 'pay-svc', name: 'payments service', kind: 'asset', tier: 'V2', service: 'Payments', fresh: true, complianceScope: true, owner: 'Payments eng' },
  { id: 'ledger', name: 'Payments ledger', kind: 'data', tier: 'V0', service: 'Payments', fresh: true, complianceScope: true, owner: 'Payments eng' },
  { id: 'laptops', name: 'Staff laptop fleet', kind: 'asset', tier: 'V3', service: 'Internal operations', fresh: true, owner: 'End-user computing' },
  { id: 'idp', name: 'Identity provider', kind: 'identity', controlPlane: true, service: 'Customer login', fresh: true, owner: 'Identity team' },
  { id: 'ci-runner', name: 'CI/CD runner', kind: 'asset', controlPlane: true, service: 'Engineering platform', fresh: true, owner: 'DevOps' },
  { id: 'hr-share', name: 'HR file share', kind: 'data', tier: 'V2', service: 'Internal operations', fresh: true, owner: 'IT ops' },
  { id: 'legacy-crm', name: 'Legacy CRM (unclassified)', kind: 'data', jewelCandidate: true, service: 'Customer data', fresh: false, owner: null },
  { id: 'dev-sandbox', name: 'Dev sandbox', kind: 'asset', tier: 'V3', service: 'Engineering platform', fresh: true, owner: 'DevOps' },
  { id: 'hsm', name: 'Payment key HSM', kind: 'asset', tier: 'V0', service: 'Payments', fresh: true, complianceScope: true, owner: 'Payments eng' },
  { id: 'backup-vault', name: 'Backup vault', kind: 'asset', controlPlane: true, service: 'Engineering platform', fresh: true, owner: 'IT ops' },
  { id: 'erp-fin', name: 'Finance ERP', kind: 'data', tier: 'V0', service: 'Internal operations', fresh: true, owner: 'Finance systems' },
  { id: 'print-srv', name: 'Print server (stale)', kind: 'asset', fresh: false, service: 'Internal operations', owner: null },
];

const WAF = { type: 'WAF', coverage: 0.5, bypass: 0.6 };

const EDGES = [
  // --- worked example (PLAN §7.4) ---
  { id: 'e1', from: 'internet', to: 'web-w', technique: 'T1190', grants: 'execCode(web-w, service)', class: 'finding', findings: ['F-RCE-W'], kev: true, exploitation: 'active', effort: 0.2, controls: [WAF] },
  { id: 'e2', from: 'web-w', to: 'role-r', technique: 'T1552.001', grants: 'hasCred(role-r)', class: 'config', findings: ['F-ENVCRED-W'], effort: 0.05 },
  { id: 'e3', from: 'role-r', to: 'db-pii', technique: 'T1078.004', grants: 'dataRead(db-pii)', class: 'trust', effort: 0.05 },
  { id: 'e4', from: 'web-w', to: 'secret-s', technique: 'T1552', grants: 'hasCred(secret-s reader)', class: 'config', findings: ['F-SECRETTOKEN-W'], effort: 0.2 },
  { id: 'e5', from: 'secret-s', to: 'db-pii', technique: 'T1078', grants: 'dataRead(db-pii)', class: 'trust', effort: 0.05 },
  { id: 'e6', from: 'vendor-acct', to: 'web-w', technique: 'T1133', grants: 'execCode(web-w, user)', class: 'trust', findings: ['F-LEAKED-VENDOR'], effort: 0.05, controls: [{ type: 'MFA', coverage: 0.9, bypass: 0.2 }] },
  // --- surrounding estate ---
  { id: 'e7', from: 'internet', to: 'bucket-arch', technique: 'T1530', grants: 'dataRead(bucket-arch)', class: 'config', findings: ['F-PUBLIC-BUCKET'], effort: 0.05 },
  { id: 'e8', from: 'internet', to: 'api-gw', technique: 'T1190', grants: 'execCode(api-gw, service)', class: 'finding', findings: ['F-POC-APIGW'], exploitation: 'poc', effort: 0.4, controls: [WAF] },
  { id: 'e9', from: 'api-gw', to: 'pay-svc', technique: 'T1021', grants: 'netAccess(pay-svc)', class: 'netReach', effort: 0.4, controls: [{ type: 'segmentation', coverage: 0.7, bypass: 0.3 }] },
  { id: 'e10', from: 'pay-svc', to: 'ledger', technique: 'T1078', grants: 'dataRead(ledger)', class: 'config', findings: ['F-SVCACCT-PAY'], effort: 0.05 },
  { id: 'e11', from: 'laptops', to: 'idp', technique: 'T1539', grants: 'session(idp admin)', class: 'config', findings: ['F-WEAK-CA'], effort: 0.4, controls: [{ type: 'EDR', coverage: 0.8, bypass: 0.5 }] },
  { id: 'e12', from: 'saas-app', to: 'idp', technique: 'T1528', grants: 'token(idp)', class: 'trust', findings: ['F-OAUTH-CONSENT'], effort: 0.2, controls: [{ type: 'consent-policy', coverage: 0.9, bypass: 0.1, evidenceAgeDays: 200, ttlDays: 90 }] },
  { id: 'e13', from: 'web-w', to: 'ci-runner', technique: 'T1552.004', grants: 'hasCred(ci deploy key)', class: 'config', findings: ['F-DEPLOYKEY-W'], effort: 0.2 },
  { id: 'e14', from: 'laptops', to: 'legacy-crm', technique: 'T1021', grants: 'netAccess(legacy-crm)', class: 'netReach', effort: null },
  { id: 'e15', from: 'laptops', to: 'hr-share', technique: 'T1039', grants: 'dataRead(hr-share)', class: 'config', findings: ['F-OPEN-SHARE'], effort: 0.2 },
];

const ACTIONS = [
  { id: 'A1', plain: 'Patch the internet-facing web server (attack seen in the wild)', label: 'Patch the known-exploited RCE on web-host W', removesEdges: ['e1'], cost: 1, owner: 'Platform team' },
  { id: 'A2', plain: 'Remove a stored cloud password from the web server', label: 'Remove the cloud credential from W’s environment', removesEdges: ['e2'], cost: 2, owner: 'Cloud IAM' },
  { id: 'A3', plain: 'Replace the leaked supplier password; require strong sign-in', label: 'Rotate the leaked vendor credential; phishing-resistant MFA', removesEdges: ['e6'], cost: 1, owner: 'Identity team' },
  { id: 'A4', plain: 'Wall off the web server from cloud admin systems', label: 'Segment W from the cloud control plane (egress)', removesEdges: ['e2', 'e4', 'e13'], cost: 3, owner: 'Network' },
  { id: 'A5', plain: 'Make the customer archive private', label: 'Remove public read on the archive bucket', removesEdges: ['e7'], cost: 1, owner: 'Data platform' },
  { id: 'A6', plain: 'Limit which outside apps can connect to our login system', label: 'Restrict OAuth app consent; re-verify the policy', removesEdges: ['e12'], cost: 1, owner: 'Identity team' },
  { id: 'A7', plain: 'Harden admin sign-in against stolen sessions', label: 'Token binding + stricter conditional access for admins', removesEdges: ['e11'], cost: 3, owner: 'Identity team' },
  { id: 'A8', plain: 'Patch the payments gateway', label: 'Patch the payments API gateway (public PoC)', removesEdges: ['e8'], cost: 1, owner: 'Payments eng' },
  { id: 'A9', plain: 'Replace the web server\u2019s long-lived deploy key', label: 'Replace W’s CI deploy key with short-lived OIDC', removesEdges: ['e13'], cost: 1, owner: 'DevOps' },
];

// Findings: the named ones enable edges; the bulk groups are the everyday
// scanner volume that sits on assets but enables no edge.
const FINDINGS = [
  { id: 'F-RCE-W', entity: 'web-w', severity: 'critical', kev: true, cve: true },
  { id: 'F-ENVCRED-W', entity: 'web-w', severity: 'high' },
  { id: 'F-SECRETTOKEN-W', entity: 'web-w', severity: 'high' },
  { id: 'F-LEAKED-VENDOR', entity: 'web-w', severity: 'high' },
  { id: 'F-PUBLIC-BUCKET', entity: 'bucket-arch', severity: 'high' },
  { id: 'F-POC-APIGW', entity: 'api-gw', severity: 'critical', cve: true },
  { id: 'F-SVCACCT-PAY', entity: 'pay-svc', severity: 'medium' },
  { id: 'F-WEAK-CA', entity: 'idp', severity: 'medium' },
  { id: 'F-OAUTH-CONSENT', entity: 'idp', severity: 'medium' },
  { id: 'F-DEPLOYKEY-W', entity: 'web-w', severity: 'high' },
  { id: 'F-OPEN-SHARE', entity: 'hr-share', severity: 'medium' },
  // bulk groups (count = number of findings in the group)
  { id: 'B-web-w', entity: 'web-w', severity: 'medium', count: 34, cve: true },
  { id: 'B-api-gw', entity: 'api-gw', severity: 'high', count: 22, cve: true },
  { id: 'B-pay-svc', entity: 'pay-svc', severity: 'medium', count: 18, cve: true },
  { id: 'B-laptops-crit', entity: 'laptops', severity: 'critical', count: 19, cve: true },
  { id: 'B-laptops', entity: 'laptops', severity: 'medium', count: 146, cve: true },
  { id: 'B-hr-share', entity: 'hr-share', severity: 'low', count: 12, cve: true },
  { id: 'B-sandbox-crit', entity: 'dev-sandbox', severity: 'critical', count: 22, cve: true },
  { id: 'B-sandbox', entity: 'dev-sandbox', severity: 'high', count: 131, cve: true },
  { id: 'B-sandbox-kev', entity: 'dev-sandbox', severity: 'critical', count: 3, kev: true, cve: true },
  { id: 'B-idp', entity: 'idp', severity: 'low', count: 6 },
  { id: 'B-ci', entity: 'ci-runner', severity: 'medium', count: 9, cve: true },
  { id: 'B-legacy-crm', entity: 'legacy-crm', severity: 'critical', count: 7, cve: true },
  { id: 'B-legacy-crm-hi', entity: 'legacy-crm', severity: 'high', count: 41, cve: true },
  { id: 'B-print', entity: 'print-srv', severity: 'high', count: 58, cve: true },
  { id: 'B-archive', entity: 'bucket-arch', severity: 'low', count: 4 },
];

// Governance ledger (synthetic): what execs are asked to decide, fix deadlines,
// risk acceptances. The console and tests check these for internal consistency.
// Last cycle's edge counts per class (feed-health baseline) and last cycle's
// on-route findings (a finding leaves "on-route" only on verified closure).
const FEED_BASELINE = { finding: 2, config: 7, trust: 4, netReach: 2 };
const HISTORY = {
  onRoute: ['F-RCE-W', 'F-ENVCRED-W', 'F-SECRETTOKEN-W', 'F-LEAKED-VENDOR', 'F-PUBLIC-BUCKET', 'F-POC-APIGW', 'F-SVCACCT-PAY', 'F-WEAK-CA', 'F-OAUTH-CONSENT', 'F-DEPLOYKEY-W', 'F-OPEN-SHARE'],
  closureVerified: [],
};

const GOVERNANCE = {
  asOf: '2026-09-26',
  // days since each plan action was ticketed; due date = SLA(decision) − age
  ticketAgeDays: { A1: 2, A5: 9, A3: 16, A8: 12, A6: 4, A7: 20 },
  // compliance clocks run whatever the path analysis says (PLAN §10); the
  // total is computed from the findings, the split below must sum to it
  complianceClock: { label: 'Payment-card-scope critical & high findings', onTime: 21, dueSoon: 2, overdue: 0 },
  exceptions: [
    { id: 'X-01', subject: 'Legacy CRM on an end-of-support OS', owner: 'COO', level: 'C-level', compensatingControl: 'Network ACL to CRM subnet', expiresInDays: 14 },
    { id: 'X-02', subject: 'Dev sandbox critical CVEs (no route to any jewel)', owner: 'VP Engineering', level: 'VP', compensatingControl: 'Isolated account, no trust to production', expiresInDays: 61 },
    { id: 'X-03', subject: 'HR share without SMB signing', owner: 'VP People', level: 'VP', compensatingControl: 'Monthly access review', expiresInDays: 88 },
  ],
  decisions: [
    { ask: 'Pre-approve automated read-only configuration checks for the Customer-data service', owner: 'CISO', due: '2026-10-10', evidence: 'Takes effect only once the last safety bar is met: owners agreed with 68% of the top ten fixes against a 70% bar (5 of 6 bars already met). Expected next cycle.' },
    { ask: 'Escalate the overdue supplier-password fix (A3)', owner: 'CIO', due: '2026-09-30', evidence: '9 days past its 7-day deadline. Once the web-server patch lands, it is the last open route to customer personal data.' },
    { ask: 'Renew or close the Legacy CRM risk acceptance (X-01)', owner: 'COO', due: '2026-10-10', evidence: 'Expires in 14 days; the CRM is unclassified and may hold customer data \u2014 classify before renewing' },
  ],
  triageHoursPerWeek: { before: 118, now: 64, note: 'synthetic; measured against the pre-launch baseline' },
};

// 12 weekly snapshots (synthetic). The final point must equal what the engine
// computes for the current estate — tests/engine.test.mjs enforces that.
const TREND = {
  weeks: ['W1', 'W2', 'W3', 'W4', 'W5', 'W6', 'W7', 'W8', 'W9', 'W10', 'W11', 'W12'],
  exposureIndex: [412.0, 398.5, 377.0, 351.2, 322.4, 301.9, 296.3, 290.8, 262.1, 231.7, 205.0, null],
  target: [412, 390, 368, 346, 324, 302, 280, 258, 236, 214, 192, 170],
  criticalReachable: [7, 7, 7, 6, 6, 6, 6, 5, 5, 5, 5, null],
  openFindings: [480, 488, 495, 503, 509, 514, 520, 526, 531, 535, 539, null],
};

function clone(x) { return JSON.parse(JSON.stringify(x)); }

export function demoEstate() {
  return clone({ sources: SOURCES, entities: ENTITIES, edges: EDGES, actions: ACTIONS, findings: FINDINGS, feedBaseline: FEED_BASELINE, history: HISTORY, governance: GOVERNANCE, trend: TREND });
}

/** The four-node example in PLAN §7.4: internet + vendor sources, W, R, S, the PII database. */
export function workedExample() {
  const keep = new Set(['internet', 'vendor-acct', 'web-w', 'role-r', 'secret-s', 'db-pii']);
  const edges = EDGES.filter((e) => keep.has(e.from) && keep.has(e.to));
  const edgeIds = new Set(edges.map((e) => e.id));
  return clone({
    sources: SOURCES.filter((s) => keep.has(s.entity)),
    entities: ENTITIES.filter((e) => keep.has(e.id)),
    edges,
    actions: ACTIONS.filter((a) => ['A1', 'A2', 'A3', 'A4'].includes(a.id)).map((a) => ({ ...a, removesEdges: a.removesEdges.filter((e) => edgeIds.has(e)) })),
    findings: FINDINGS.filter((f) => edges.some((e) => (e.findings ?? []).includes(f.id))),
  });
}
