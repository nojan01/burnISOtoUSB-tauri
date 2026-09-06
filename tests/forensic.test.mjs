import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createForensicRenderer, standaloneReport, buildForensicJsonExport } from '../src/forensic-report.mjs';

import { render, fixture } from './forensic-fixture.mjs';

test('UI and HTML export render the same evidence, with no stale DOM dependency', () => {
  const html = render(fixture);
  const exported = standaloneReport({result:fixture,render,styles:'',title:'Test',language:'de'});
  assert.ok(exported.includes(html));
  assert.ok(!html.includes('<script>'));
  assert.ok(html.includes('&lt;script&gt;'));
  assert.ok(html.includes('/a\nb&lt;img&gt;.txt'));
  assert.ok(html.includes('tools.scanIncomplete'));
  assert.ok(html.includes('&lt;Permission denied&gt;'));
  assert.ok(!/font-size:/.test(html));
  assert.ok(html.includes('forensic.files:</span> <span class="forensic-value">0</span>'));
});

test('JSON retains structured scan evidence and acquisition quality', () => {
  const json = buildForensicJsonExport(fixture, 'en');
  assert.equal(json.schema_version, '1.1');
  assert.equal(json.report.language, 'en');
  assert.equal(json.summary.bootable, true);
  assert.deepEqual(json.evidence, fixture);
  assert.equal(json.evidence.filesystem_details.scan_quality.complete, false);
});

test('all report text has one shared size rule, including div and GPT sections', () => {
  const css = readFileSync(new URL('../src/forensic.css', import.meta.url), 'utf8');
  assert.match(css, /\.forensic-report, \.forensic-report \*\s*\{\s*font-size: 12px !important/);
  const main = readFileSync(new URL('../src/main.js', import.meta.url), 'utf8');
  assert.ok(!main.includes('normalizeForensicTypography'));
  assert.ok(!main.includes('renderedReport.outerHTML'));
});

test('minimal forensic payload is renderable', () => assert.ok(render({}).includes('forensic-report')));
