import test from 'node:test';
import assert from 'node:assert/strict';
import {headerNames, netLogRequests, verifyAnonymousCwsCheck} from '../scripts/extension-update-netlog.mjs';

const extensionId = 'ddkjiahejlhfcafbddmgiahcphecmpfh';
const version = '2026.1.1.1';
const query = new URLSearchParams({prod: 'chromiumcrx', acceptformat: 'crx3,puff'});
query.append('x', new URLSearchParams({id: extensionId, v: version, installedby: 'internal', uc: ''}).toString());
const url = `https://clients2.google.com/service/update2/crx?${query}`;
const options = {extensionId, version, afterUnixMs: 10050};
function fixture(headers = ['Host: clients2.google.com'], headerType = 'HTTP_TRANSACTION_SEND_REQUEST_HEADERS') {
  return {constants: {timeTickOffset: '10000', logEventTypes: {URL_REQUEST_START_JOB: 1, [headerType]: 2, HTTP_TRANSACTION_READ_RESPONSE_HEADERS: 3}}, events: [
    {type: 1, time: '100', source: {id: 7, type: 1}, params: {url, method: 'GET'}},
    {type: 2, time: '101', source: {id: 7, type: 1}, params: {headers}},
    {type: 3, time: '102', source: {id: 7, type: 1}, params: {headers: ['HTTP/1.1 200 OK', 'Content-Type: text/xml; charset=UTF-8']}},
  ]};
}

test('Default NetLog parser retains header names while never exposing redacted cookie/auth values', () => {
  assert.deepEqual(headerNames(['Cookie: [42 bytes were stripped]', 'Authorization: [19 bytes were stripped]', ':method: GET']), ['cookie', 'authorization', ':method']);
  assert.deepEqual(headerNames({'Cookie': 'synthetic', 'Accept': '*/*'}), ['cookie', 'accept']);
  for (const type of ['HTTP_TRANSACTION_SEND_REQUEST_HEADERS', 'HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS', 'HTTP_TRANSACTION_QUIC_SEND_REQUEST_HEADERS']) {
    const result = netLogRequests(fixture(['Cookie: must-not-be-output'], type));
    assert.deepEqual(result[0].headerNames, ['cookie']);
    assert.equal(result[0].startedAtUnixMs, 10100);
    assert(!JSON.stringify(result).includes('must-not-be-output'));
    assert.throws(() => verifyAnonymousCwsCheck(fixture(['Cookie: [42 bytes were stripped]'], type), options), /cookie or authorization/);
  }
  assert.throws(() => verifyAnonymousCwsCheck(fixture(['Authorization: [19 bytes were stripped]']), options), /cookie or authorization/);
});

test('anonymous manifest evidence never claims an update download, publisher proof, or installation', () => {
  const result = verifyAnonymousCwsCheck(fixture(), options);
  assert.equal(result.manifestChecksObserved, 1);
  assert.equal(result.manifestResponseXMLMimeObserved, true);
  assert.equal(result.xmlManifestParsed, false);
  assert.equal(result.updateDownloadTransportObserved, false);
  assert.equal(result.anonymousDownloadTransportVerified, false);
  assert.equal(result.updateInstallationVerified, false);
  assert.equal(result.publisherProofOnUpdateVerified, false);
  assert.throws(() => verifyAnonymousCwsCheck(fixture(), {...options, afterUnixMs: 11000}), /No successful native/);
  const missingHeaders = fixture(); missingHeaders.events.splice(1, 1);
  assert.throws(() => verifyAnonymousCwsCheck(missingHeaders, options), /sent request-header evidence/);
  for (const contentType of [undefined, 'text/html; charset=UTF-8', 'application/json']) {
    const notXML = fixture();
    notXML.events[2].params.headers = ['HTTP/1.1 200 OK', ...(contentType ? [`Content-Type: ${contentType}`] : [])];
    assert.throws(() => verifyAnonymousCwsCheck(notXML, options), /expected XML MIME/);
  }
  const applicationXML = fixture();
  applicationXML.events[2].params.headers = [':status: 200', 'content-type: Application/XML; charset=utf-8'];
  assert.equal(verifyAnonymousCwsCheck(applicationXML, options).manifestResponseXMLMimeObserved, true);
});

test('native update evidence rejects nested pings, account retry, redirects and failed HTTP responses', () => {
  for (const forbidden of ['ping', 'brand', 'ap', 'authuser', 'r', 'a', 'e', 'dr', 'disable_reasons']) {
    const log = fixture(); const parsed = new URL(log.events[0].params.url);
    const nested = new URLSearchParams(parsed.searchParams.get('x')); nested.set(forbidden, 'synthetic');
    parsed.searchParams.set('x', nested.toString()); log.events[0].params.url = parsed.href;
    assert.throws(() => verifyAnonymousCwsCheck(log, options), /forbidden|ping data/);
  }
  const redirect = fixture(); redirect.events.push({type: 'URL_REQUEST_REDIRECTED', time: '103', source: {id: 7, type: 1}, params: {location: 'https://elsewhere.invalid/'}});
  assert.throws(() => verifyAnonymousCwsCheck(redirect, options), /reject redirects/);
  const unauthorized = fixture(); unauthorized.events[2].params.headers = ['HTTP/1.1 401 Unauthorized'];
  assert.throws(() => verifyAnonymousCwsCheck(unauthorized, options), /successful update response/);
});

test('CDN transport is checked only when exercised and never establishes update installation', () => {
  const log = fixture();
  log.events.push(
    {type: 1, time: '104', source: {id: 8, type: 1}, params: {url: 'https://clients2.googleusercontent.com/crx/blobs/fixture/update.crx', method: 'GET'}},
    {type: 2, time: '105', source: {id: 8, type: 1}, params: {headers: ['Accept: */*']}},
    {type: 3, time: '106', source: {id: 8, type: 1}, params: {headers: ['HTTP/2 200']}},
  );
  const result = verifyAnonymousCwsCheck(log, options);
  assert.equal(result.anonymousDownloadTransportVerified, true);
  assert.equal(result.updateInstallationVerified, false);
  assert.equal(result.publisherProofOnUpdateVerified, false);
  const badHost = structuredClone(log); badHost.events[3].params.url = 'https://other.invalid/crx/blobs/fixture/update.crx';
  assert.throws(() => verifyAnonymousCwsCheck(badHost, options));
  const cookie = structuredClone(log); cookie.events[4].params.headers.push('Cookie: [5 bytes were stripped]');
  assert.throws(() => verifyAnonymousCwsCheck(cookie, options), /cookie or authorization/);
});


test('separate manual update windows cannot borrow a later successful manifest', () => {
  const laterOnly = fixture();
  for (const event of laterOnly.events) event.time = String(Number(event.time) + 200);
  const first = {...options, beforeUnixMs: 10150};
  const second = {...options, afterUnixMs: 10250, beforeUnixMs: 10350};
  assert.throws(() => verifyAnonymousCwsCheck(laterOnly, first), /No successful native/);
  assert.equal(verifyAnonymousCwsCheck(laterOnly, second).manifestChecksObserved, 1);
  const both = fixture();
  both.events.push(...structuredClone(laterOnly.events).map(event => ({...event, source: {...event.source, id: 8}})));
  assert.equal(verifyAnonymousCwsCheck(both, first).manifestChecksObserved, 1);
  assert.equal(verifyAnonymousCwsCheck(both, second).manifestChecksObserved, 1);
  assert.throws(() => verifyAnonymousCwsCheck(both, {...options, beforeUnixMs: options.afterUnixMs}), /window end/);
});
