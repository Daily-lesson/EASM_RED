// docs/c4.json is this repo's C4 model, read by the owner's status map. Its grammar is checked where it is read;
// this test holds what the file SAYS to what this repo IS, so a renamed file or workflow fails here.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';

const at = (p) => new URL(`../${p}`, import.meta.url);
const read = (p) => readFileSync(at(p), 'utf8');
const model = JSON.parse(read('docs/c4.json'));
const by = (id) => {
  const c = model.containers.find((x) => x.id === id);
  assert.ok(c, `no container ${id}`);
  return c;
};

test('c4: version 1, inside the reader limits', () => {
  assert.equal(model.c4, 1);
  assert.ok(model.containers.length >= 1 && model.containers.length <= 12);
  const ids = new Set();
  for (const c of model.containers) {
    assert.match(c.id, /^[a-z][a-z0-9-]{0,11}$/);
    assert.ok(!ids.has(c.id), c.id);
    ids.add(c.id);
    assert.ok(['front', 'back', 'data'].includes(c.lane), c.id);
    assert.ok(c.label.length <= 28 && c.tech.length <= 60 && c.desc.length <= 160, c.id);
    assert.ok((c.components || []).length <= 8, c.id);
    for (const n of c.components || []) {
      assert.ok(n.label.length <= 28 && (n.tech || '').length <= 60 && (n.desc || '').length <= 160, n.label);
    }
  }
  for (const r of model.rels || []) {
    assert.ok(ids.has(r.from) && ids.has(r.to) && r.from !== r.to, `${r.from} -> ${r.to}`);
    assert.ok(r.label.length <= 80);
  }
  for (const lane of ['front', 'back', 'data']) assert.ok(model.containers.some((c) => c.lane === lane), lane);
});

test('c4: names no URL or host', () => {
  const body = JSON.stringify({ ...model, $comment: undefined });
  assert.ok(!/https?:|\.(com|io|dev|app|now|co)\b/i.test(body));
});

test('c4: every file it names is in this repo', () => {
  for (const c of model.containers) {
    for (const n of c.components || []) assert.ok(existsSync(at(n.tech)), `${c.id}/${n.label}: ${n.tech}`);
  }
  assert.ok(existsSync(at('reference')) && existsSync(at('docs')));
});

test('c4: the workflows and what they run are the ones it states', () => {
  const ci = read('.github/workflows/check.yml');
  assert.match(ci, /node-version: 22/);
  assert.match(ci, /run: npm test/);
  assert.ok(by('ci').tech.includes('Node 22'));
  assert.match(JSON.parse(read('package.json')).scripts.test, /^node --test /);
  assert.equal(by('ci').reads, 'ci');
  const pages = read('.github/workflows/pages.yml');
  assert.match(pages, /deploy-pages/);
  assert.deepEqual(by('console').reads, { workflow: 'pages.yml' });
});

test('c4: the engine and the data build are what it says', () => {
  const pkg = JSON.parse(read('package.json'));
  assert.equal(pkg.dependencies, undefined);
  assert.equal(pkg.devDependencies, undefined);
  assert.equal(pkg.scripts['build:demo'], 'node reference/build-demo.mjs');
  assert.ok(by('builder').tech.includes('npm run build:demo'));
  assert.match(read('reference/build-demo.mjs'), /--check/);
  assert.match(read('reference/build-demo.mjs'), /operating-model\.html/);
  assert.match(read('tests/engine.test.mjs'), /ENGINE_SHA256/);
  assert.match(read('reference/demo-estate.mjs'), /Every name here is invented/);
});

test('c4: the guard fails closed and is what sessions are configured with', () => {
  assert.match(read('.claude/hooks/cve-now-guard.mjs'), /FAILS CLOSED/);
  assert.equal(Object.keys(JSON.parse(read('.mcp.json')).mcpServers).length, 1);
});

test('c4: the relationships it draws', () => {
  const has = (f, t) => (model.rels || []).some((r) => r.from === f && r.to === t);
  for (const [f, t] of [['builder', 'engine'], ['builder', 'estate'], ['builder', 'console'], ['ci', 'engine']]) {
    assert.ok(has(f, t), `${f} -> ${t}`);
  }
});
