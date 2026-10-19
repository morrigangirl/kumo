import test from 'node:test';
import assert from 'node:assert/strict';
import {phishingControlState} from '../extension/phishing-status.js';

test('a model-free release cannot advertise enabled analysis even with stale ready status', () => {
  const state = phishingControlState({phishingProtection: {included: false}}, {included: true, enabled: true, health: 'ready'});
  assert.equal(state.included, false); assert.equal(state.enableDisabled, true); assert.equal(state.disableDisabled, true);
  assert.match(state.description, /Not included in this release/); assert.doesNotMatch(state.description, /Enabled|stays on this Mac/);
});

test('unavailable or inconsistent metadata disables permission controls', () => {
  for (const [buildInfo, status] of [[{}, {included: true}], [{phishingProtection: {included: true}}, undefined],
    [{phishingProtection: {included: true}}, {included: false}], [{phishingProtection: {included: 'true'}}, {included: true}]]) {
    const state = phishingControlState(buildInfo, status);
    assert.equal(state.enableDisabled, true); assert.equal(state.disableDisabled, true);
    assert.match(state.description, /unavailable/);
  }
});

test('included classifier retains off, ready and unavailable controls', () => {
  const build = {phishingProtection: {included: true}};
  const off = phishingControlState(build, {included: true, enabled: false, health: 'off'});
  assert.equal(off.enableDisabled, false); assert.equal(off.disableDisabled, true); assert.match(off.description, /^Off\./);
  const ready = phishingControlState(build, {included: true, enabled: true, health: 'ready'});
  assert.equal(ready.enableDisabled, true); assert.equal(ready.disableDisabled, false); assert.match(ready.description, /^Enabled\./);
  const unavailable = phishingControlState(build, {included: true, enabled: true, health: 'unavailable'});
  assert.equal(unavailable.disableDisabled, false); assert.match(unavailable.description, /may go unchecked/);
});
