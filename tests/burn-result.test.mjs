import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {burnCompletion} from '../src/burn-result.mjs';
const de = JSON.parse(readFileSync(new URL('../src/i18n/de.json', import.meta.url)));
const t = key => key.split('.').reduce((value, part) => value[part], de);

test('mount failure preserves verified success and reaches the notification', () => {
  const result = burnCompletion({written:true,verified:true,warning:{action:'mount',detail:'Failed to find disk /dev/disk10'}},t);
  assert.equal(result.message, 'Image geschrieben und vollständig verifiziert');
  assert.match(result.warning,/Wiedereinhängen/);
  assert.match(result.warning,/disk10/);
  assert.match(result.notification,/vollständig verifiziert/);
  assert.match(result.notification,/Warnung/);
});
test('eject failure does not falsely claim verification', () => {
  const result = burnCompletion({written:true,verified:false,warning:{action:'eject',detail:'Resource busy'}},t);
  assert.equal(result.message, 'Image vollständig geschrieben (ohne Verifizierung)');
  assert.match(result.warning,/Auswerfen/);
  assert.doesNotMatch(result.warning,/Wiedereinhängen/);
});
test('normal completion has no warning', () => {
  const result = burnCompletion({written:true,verified:true,warning:null},t);
  assert.equal(result.warning,'');
  assert.equal(result.notification,result.message);
});
test('incomplete or invalid backend evidence is never displayed as success', () => {
  for (const result of [null,{},'Done',{written:false,verified:true},{written:true}]) {
    assert.throws(() => burnCompletion(result,t), /Schreibbestätigung/);
  }
});
