import test from 'node:test';
import assert from 'node:assert/strict';
import {engineSecurityStatus} from '../extension/security.js';

test('engine status warns about an older actual engine and compares all four numeric parts', () => {
  assert.equal(engineSecurityStatus({engineVersion: '155.0.8059.39-1.1', sourceTargetVersion: '155.0.8059.84'}).kind, 'older');
  assert.equal(engineSecurityStatus({engineVersion: '155.0.8059.9', sourceTargetVersion: '155.0.8059.10'}).kind, 'older');
  assert.equal(engineSecurityStatus({engineVersion: '154.9.9999.999', sourceTargetVersion: '155.0.0.0'}).kind, 'older');
  assert.equal(engineSecurityStatus({engineVersion: '155.1.0.0', sourceTargetVersion: '155.0.8059.84'}).kind, 'newer');
});

test('matching the packaged source target never claims current release or security status', () => {
  for (const engineVersion of ['155.0.8059.84', '155.0.8059.84-1.1']) {
    const status = engineSecurityStatus({engineVersion, sourceTargetVersion: '155.0.8059.84'});
    assert.equal(status.kind, 'matches');
    assert.match(status.title, /this build’s source target/);
    assert.doesNotMatch(status.title, /up.to.date|secure|latest/i);
    assert.match(status.versions, new RegExp(engineVersion.replaceAll('.', '\\.')));
  }
});

test('missing or malformed metadata reports unknown rather than a successful check', () => {
  for (const value of [undefined, null, {}, '155.0.8059', '155.0.8059.84junk', '155.0.8059.9007199254740992', '155.0.8059.84<script>']) {
    assert.equal(engineSecurityStatus({engineVersion: value, sourceTargetVersion: '155.0.8059.84'}).kind, 'unknown');
    assert.equal(engineSecurityStatus({engineVersion: '155.0.8059.84', sourceTargetVersion: value}).kind, 'unknown');
  }
  assert.equal(engineSecurityStatus().kind, 'unknown');
  assert.equal(engineSecurityStatus(null).kind, 'unknown');
});
