// Regenerates the synthetic data block inside operating-model.html from the
// reference engine, so the console can never show a number the model does not
// produce. Run: `node reference/build-demo.mjs` (or `npm run build:demo`).
// `--check` exits non-zero if the page is out of date (used by the tests).

import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { summarize } from './summary.mjs';
import { demoEstate } from './demo-estate.mjs';

const PAGE = fileURLToPath(new URL('../operating-model.html', import.meta.url));
const OPEN = '<script type="application/json" id="apm-data">';
const CLOSE = '</script>';

export function renderBlock() {
  // `</` is escaped so the JSON can never close its own <script> element
  return JSON.stringify(summarize(demoEstate()), null, 1).replace(/<\//g, '<\\/');
}

export function readBlock(html) {
  const a = html.indexOf(OPEN);
  if (a < 0) throw new Error('apm-data block not found in operating-model.html');
  const b = html.indexOf(CLOSE, a + OPEN.length);
  return { a, b, json: html.slice(a + OPEN.length, b).trim() };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const html = readFileSync(PAGE, 'utf8');
  const { a, b, json } = readBlock(html);
  const fresh = renderBlock();
  if (process.argv.includes('--check')) {
    if (json !== fresh) { console.error('operating-model.html is stale: run node reference/build-demo.mjs'); process.exit(1); }
    console.log('operating-model.html data block is current');
  } else {
    writeFileSync(PAGE, html.slice(0, a + OPEN.length) + '\n' + fresh + '\n' + html.slice(b));
    console.log('wrote data block to operating-model.html');
  }
}
