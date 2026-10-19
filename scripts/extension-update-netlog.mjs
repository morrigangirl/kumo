import assert from 'node:assert/strict';

const SENT_HEADERS = new Set([
  'HTTP_TRANSACTION_SEND_REQUEST_HEADERS',
  'HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS',
  'HTTP_TRANSACTION_QUIC_SEND_REQUEST_HEADERS',
]);

function headerLines(value) {
  if (Array.isArray(value)) return value.filter(line => typeof line === 'string');
  if (typeof value === 'string') return value.split(/\r?\n/);
  if (value && typeof value === 'object') return Object.entries(value).map(([key, item]) => `${key}: ${item}`);
  return [];
}
export function headerNames(value) {
  return headerLines(value).flatMap(line => {
    const match = line.match(/^(:[^:\s]+|[^:\s]+)\s*:/);
    return match ? [match[1].toLowerCase()] : [];
  });
}

// Default NetLog redacts sensitive header VALUES, but retains header names.
// Only request names/status and response MIME types are retained here;
// cookie/auth values, response contents and other header values are not output.
export function netLogRequests(log) {
  assert(log && Array.isArray(log.events), 'NetLog must contain an events array.');
  const names = new Map(Object.entries(log.constants?.logEventTypes || {}).map(([name, number]) => [number, name]));
  const offset = Number(log.constants?.timeTickOffset);
  const active = new Map();
  const requests = [];
  for (const event of log.events) {
    const name = typeof event.type === 'string' ? event.type : names.get(event.type);
    const key = `${event.source?.type}:${event.source?.id}`;
    const params = event.params || {};
    if (name === 'URL_REQUEST_START_JOB' && typeof params.url === 'string') {
      const time = Number(event.time);
      const request = {source: key, url: params.url, method: params.method,
        startedAtUnixMs: Number.isFinite(offset) && Number.isFinite(time) ? offset + time : null,
        headerNames: [], sentHeaderEvents: 0, responseCodes: [], responseMimeTypes: [], redirects: [], errors: []};
      active.set(key, request); requests.push(request);
    }
    const request = active.get(key);
    if (!request) continue;
    if (SENT_HEADERS.has(name)) {
      request.sentHeaderEvents++;
      request.headerNames.push(...headerNames(params.headers));
    }
    if (name === 'HTTP_TRANSACTION_READ_RESPONSE_HEADERS') {
      for (const line of headerLines(params.headers)) {
        const match = line.match(/^(?:HTTP\/\S+\s+|:status:\s*)(\d{3})(?:\s|$)/i);
        if (match) request.responseCodes.push(Number(match[1]));
        const contentType = line.match(/^content-type:\s*([^;\s]+)(?:\s*;|\s*$)/i);
        if (contentType) request.responseMimeTypes.push(contentType[1].toLowerCase());
      }
    }
    if (name === 'URL_REQUEST_REDIRECTED') request.redirects.push(params.location || 'unknown');
    if (typeof params.net_error === 'number' && params.net_error !== 0) request.errors.push(params.net_error);
  }
  return requests;
}

function assertNoTrackingParameters(params, nested = false) {
  for (const [key, value] of params) {
    const lower = key.toLowerCase();
    assert(!['brand', 'ap', 'authuser', 'ping', 'rollcall', 'active', 'enablement', 'disable_reason', 'disable_reasons'].includes(lower) &&
      !/^(?:ping[_-]|.*rollcall|.*enablement|.*disable[_-]?reason)/.test(lower), 'Update URL contains forbidden tracking/account parameters.');
    if (nested) assert(!['r', 'a', 'e', 'dr'].includes(lower), 'Update URL contains enabled-state or activity ping data.');
    if (lower === 'x') assertNoTrackingParameters(new URLSearchParams(value), true);
  }
}
function assertAnonymousTransport(request) {
  assert.equal(request.method, 'GET', 'Native updates must use the reviewed GET transport.');
  assert(request.sentHeaderEvents > 0, 'Default NetLog must include sent request-header evidence.');
  assert(!request.headerNames.some(name => ['cookie', 'cookie2', 'authorization', 'proxy-authorization'].includes(name)), 'Native update sent cookie or authorization headers.');
  assert.equal(request.redirects.length, 0, 'Native update transport must reject redirects.');
  assert.deepEqual(request.errors, [], 'Native update request failed.');
  assert(request.responseCodes.length > 0 && request.responseCodes.every(code => code === 200), 'A real successful update response without redirect/auth retries must be observed.');
}

export function verifyAnonymousCwsCheck(log, {extensionId, version, afterUnixMs, beforeUnixMs}) {
  assert(/^[a-p]{32}$/.test(extensionId), 'A valid expected Store extension ID is required.');
  assert(typeof version === 'string' && /^\d+(?:\.\d+){0,3}$/.test(version), 'A packed extension version is required.');
  assert(Number.isFinite(afterUnixMs), 'A manual Update click timestamp is required.');
  const requests = netLogRequests(log);
  assert(beforeUnixMs === undefined || (Number.isFinite(beforeUnixMs) && beforeUnixMs > afterUnixMs),
    'An optional update window end must be finite and later than its start.');
  const recent = requests.filter(request => request.startedAtUnixMs !== null &&
    request.startedAtUnixMs >= afterUnixMs &&
    (beforeUnixMs === undefined || request.startedAtUnixMs < beforeUnixMs));
  const manifests = [];
  const downloads = [];
  for (const request of recent) {
    let url;
    try { url = new URL(request.url); } catch { continue; }
    if (url.hostname === 'clients2.google.com' && url.pathname === '/service/update2/crx') {
      const groups = url.searchParams.getAll('x').map(value => new URLSearchParams(value));
      if (!groups.some(group => group.get('id') === extensionId)) continue;
      assert.equal(url.origin, 'https://clients2.google.com');
      assert(!url.username && !url.password && !url.hash, 'Store transport URL must not contain credentials or a fragment.');
      assert.notEqual(url.searchParams.get('response'), 'redirect', 'An update check must not use the install/download redirect endpoint.');
      assert.equal(url.searchParams.get('prod'), 'chromiumcrx');
      assert((url.searchParams.get('acceptformat') || '').split(',').includes('crx3'), 'The update check must request CRX3.');
      assertNoTrackingParameters(url.searchParams);
      for (const group of groups) {
        assert.equal(group.get('id'), extensionId, 'This disposable profile must check only its packed Store fixture.');
        assert.equal(group.get('v'), version, 'The native check must advertise the actually installed version.');
        assert.equal(group.get('installedby'), 'internal');
      }
      assertAnonymousTransport(request);
      assert(request.responseMimeTypes.length > 0 && request.responseMimeTypes.every(type => ['text/xml', 'application/xml'].includes(type)),
        'A successful manifest response must declare an expected XML MIME type; HTTP 200 HTML is insufficient.');
      manifests.push(request);
    } else if (url.pathname.startsWith('/crx/blobs/')) {
      assert.equal(url.origin, 'https://clients2.googleusercontent.com');
      assert(!url.username && !url.password && !url.hash);
      assertNoTrackingParameters(url.searchParams);
      assertAnonymousTransport(request);
      downloads.push(request);
    }
  }
  assert(manifests.length > 0, 'No successful native CWS manifest check was observed after the Update click.');
  return {manifestChecksObserved: manifests.length, manifestRequestHeaderNames: [...new Set(manifests.flatMap(request => request.headerNames))].sort(),
    cookieAndAuthorizationHeadersAbsent: true, pingAndAccountParametersAbsent: true,
    manifestResponseXMLMimeObserved: true, xmlManifestParsed: false,
    updateDownloadTransportObserved: downloads.length > 0,
    anonymousDownloadTransportVerified: downloads.length > 0,
    updateInstallationVerified: false, publisherProofOnUpdateVerified: false,
    limitation: 'An HTTP response with XML MIME is not XML-body parsing proof. It or an unchanged installed version does not prove an update download, publisher-proof check, or update installation.'};
}
