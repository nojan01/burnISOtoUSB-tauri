import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import { diagnosticSummary, renderDiagnosticDetails, diagnosticProgress } from '../src/diagnostic-report.mjs';
const t = key => key;
test('F3 results distinguish file verification from a full sector scan and escape volume names', () => {
  const result = {success:true, details:{kind:'f3',volume:'<img src=x>',mount_point:'/Volumes/Test',
    bytes_checked:1048576,good_bytes:1048576,corrupted_sectors:0,changed_sectors:0,overwritten_sectors:0}};
  assert.equal(diagnosticSummary(result,t),'diagnose.f3Complete');
  const html = renderDiagnosticDetails(result,t);
  assert.match(html,/f3Scope/);
  assert.match(html,/1.0 MiB/);
  assert.match(html,/&lt;img/);
  assert.match(html,/f3Cleaned/);
  assert.doesNotMatch(html,/fullCoverage|<img/);
  result.success = false;
  assert.equal(diagnosticSummary(result,t),'diagnose.f3Failed');
  assert.match(diagnosticProgress({phase:'cleanup',details:{kind:'f3'}},t).status,/f3Cleanup/);
});
test('diagnostic results use compact system typography including native table elements', () => {
  const css = readFileSync(new URL('../src/styles.css', import.meta.url), 'utf8');
  assert.match(css, /#diagnose-details\s*\{[^}]*font-family:\s*inherit;[^}]*font-size:\s*12px;/);
  assert.match(css, /#diagnose-details :where\(p, table, thead, tbody, tr, th, td, ul, li\)\s*\{[^}]*font-family:\s*inherit;[^}]*font-size:\s*inherit;/);
});
test('sample success is never presented as a healthy full device', () => {
  const result = {success:true,details:{kind:'sample',sampled:true,coverage_percent:2,bytes_checked:100,device_bytes:5000}};
  assert.equal(diagnosticSummary(result,t),'diagnose.sampleComplete');
  const html = renderDiagnosticDetails(result,t);
  assert.match(html,/sampleCaveat/);
  assert.match(html,/2.00%/);
  assert.doesNotMatch(html,/fullCoverage/);
});
test('speed table shows separate binary-unit results for all block sizes', () => {
  const result = {success:true, details:{kind:'speed',profile:'detailed',speed_results:[1,4,16].map(n=>({block_bytes:n*1048576,write_bytes:1048576,read_bytes:2097152,write_mib_s:10+n,read_mib_s:20+n}))}};
  assert.equal(diagnosticSummary(result,t),'diagnose.measurementComplete');
  const html = renderDiagnosticDetails(result,t);
  assert.equal((html.match(/<tr>/g)||[]).length,4);
  assert.match(html,/16.0 MiB/);
  assert.match(html,/weightedAverage/);
  assert.doesNotMatch(html,/ MB\/s/);
});
test('bad ranges are not mislabelled as individual bad sectors', () => {
  const result = {success:false,details:{kind:'surface',bad_ranges:[{offset:512,length:65536}],bad_ranges_truncated:true}};
  const html = renderDiagnosticDetails(result,t);
  assert.match(html,/512–66047/);
  assert.match(html,/regionCaveat/);
  assert.match(html,/truncatedRanges/);
  assert.equal(diagnosticSummary(result,t),'diagnose.scanFailed');
});
test('live ETA is null-safe and synchronization has no false remaining time', () => {
  const p = diagnosticProgress({phase:'reading',details:{eta_seconds:61.2,sampled:true,target_bytes:1024,bytes_checked:512}},t);
  assert.match(p.status,/sampleLabel/);
  assert.match(p.eta,/1 min 2 s/);
  assert.equal(diagnosticProgress({phase:'synchronizing',details:{eta_seconds:null}},t).eta,'');
  assert.equal(diagnosticSummary({success:true,details:{kind:'surface',retry_count:1}},t),'diagnose.scanRetried');
});
