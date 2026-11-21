import test from 'node:test';
import assert from 'node:assert/strict';
import { createToolOperation } from '../src/tool-operation.mjs';

test('a second format cannot enter the dialogs or start while the first format is active', async () => {
  const transitions = [];
  const operation = createToolOperation(() => transitions.push(operation.busy));
  let confirm, complete;
  const dialog = new Promise(resolve => { confirm = resolve; });
  const backend = new Promise(resolve => { complete = resolve; });
  let starts = 0;
  const first = operation.run(async () => { await dialog; starts++; await backend; });
  await operation.run(() => assert.fail('second confirmation opened'));
  confirm();
  await Promise.resolve();
  assert.equal(starts, 1);
  await operation.run(() => assert.fail('second format started'));
  complete();
  await first;
  assert.deepEqual(transitions, [true, false]);
});

test('cancellation and errors release the controls', async () => {
  const operation = createToolOperation(() => {});
  await operation.run(async () => {});
  await assert.rejects(operation.run(async () => { throw Error('failed'); }));
  assert.equal(operation.busy, false);
});
