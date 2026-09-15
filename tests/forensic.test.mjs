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

test('denied access is distinguished from I/O errors in UI and exports', () => {
  const result = structuredClone(fixture);
  result.filesystem_details.scan_quality = {
    complete:false, elevated:true, error_count:3, permission_denied_count:3,
    io_error_count:0, other_error_count:0, skipped_mounts:0,
    errors:['/.Trashes: Permission denied <test>']
  };
  const html = render(result);
  assert.ok(html.includes('tools.scanPermissionDenied: 3'));
  assert.ok(html.includes('tools.scanIoErrors: 0'));
  assert.ok(html.includes('tools.scanOtherErrors: 0'));
  assert.ok(html.includes('tools.scanIncomplete'));
  assert.ok(html.includes('tools.scanPermissionHint'));
  assert.ok(html.includes('Permission denied &lt;test&gt;'));
  assert.ok(!html.includes('tools.scanErrors: 3'));
  assert.ok(standaloneReport({result,render,styles:'',title:'Test',language:'de'}).includes(html));
  const exported = buildForensicJsonExport(result, 'de');
  assert.deepEqual(exported.evidence.filesystem_details.scan_quality, result.filesystem_details.scan_quality);
  result.filesystem_details.scan_quality.permission_denied_count = 0;
  result.filesystem_details.scan_quality.io_error_count = 3;
  assert.ok(!render(result).includes('tools.scanPermissionHint'));
  assert.ok(render(result).includes('tools.scanIoErrors: 3'));
});

test('scan categories and access hint are available in both languages', () => {
  for (const lang of ['de', 'en']) {
    const {tools} = JSON.parse(readFileSync(new URL(`../src/i18n/${lang}.json`, import.meta.url)));
    for (const key of ['scanErrors', 'scanPermissionDenied', 'scanIoErrors', 'scanOtherErrors', 'scanPermissionHint']) {
      assert.ok(tools[key]?.length > 0, `${lang}: ${key}`);
    }
  }
});
