#!/usr/bin/env python3
"""Bounded, offline development-updater and real Chromium lease smoke test.

Runs only a disposable browser profile. It never opens Launch Services or the
normal Kumo profile, checks GitHub, stages an update, or accesses an AI account.
"""
import argparse
import base64
import datetime
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import signal
import socket
import stat
import subprocess
import tempfile
import time
import urllib.parse

ROOT = Path(__file__).resolve().parents[1]
LOCK_CONTENT = b'Kumo update coordination v1\n'


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def checked(command, *, env=None, timeout=30):
    result = subprocess.run(command, capture_output=True, text=True, env=env, timeout=timeout)
    require(result.returncode == 0, f'{Path(command[0]).name} failed: {result.stderr[-3000:]}')
    return result


def read_lock(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_mode & 0o022 == 0,
                'Update coordination resource is unsafe')
        require(os.read(descriptor, len(LOCK_CONTENT) + 1) == LOCK_CONTENT,
                'Update coordination resource has unexpected content')
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def exclusive_available(path):
    descriptor = read_lock(path)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return False
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        return True
    finally:
        os.close(descriptor)


def seal(app):
    checked(['codesign', '--verify', '--deep', '--strict', str(app)], timeout=90)
    signature = checked(['codesign', '-dv', '--verbose=4', str(app)]).stderr
    match = re.search(r'^CDHash=([0-9a-f]+)$', signature, re.MULTILINE)
    require(match is not None, 'Signed app CDHash was not reported')
    resource = app / 'Contents/_CodeSignature/CodeResources'
    return {'cdhash': match.group(1), 'codeResourcesSHA256': hashlib.sha256(resource.read_bytes()).hexdigest(),
            'strictDeepValid': True}


def child_exit_status(child):
    # WNOWAIT reserves this process's PID/PGID until cleanup has finished. Never
    # signal a process group after reaping its leader (PID reuse is possible).
    return os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)


def cleanup_owned_child(child):
    try:
        reservation = child_exit_status(child)
    except ChildProcessError:
        # Ownership reservation was lost; do not signal a potentially reused ID.
        raise RuntimeError('Owned child was unexpectedly reaped; skipped process-group signals')
    if reservation is None:
        try:
            require(os.getpgid(child.pid) == child.pid, 'Owned child process-group identity changed')
        except ProcessLookupError:
            # It can exit between the WNOWAIT peek and getpgid.
            reservation = child_exit_status(child)
            require(reservation is not None and reservation.si_pid == child.pid,
                    'Owned child exited without a retained PID reservation')
    else:
        # Darwin may return ESRCH from getpgid for a zombie even though
        # waitid(WNOWAIT) still reserves its PID and original group identifier.
        require(reservation.si_pid == child.pid, 'Owned zombie PID reservation changed')
    # Darwin returns EPERM rather than ESRCH when a process group contains
    # only a zombie. Skip signals after a normal Browser.close if no live
    # member remains; inspect only numeric PID/group/state metadata.
    listing = checked(['ps', '-axo', 'pid=,pgid=,stat='], timeout=5).stdout
    live_members = []
    for line in listing.splitlines():
        fields = line.split()
        if len(fields) == 3 and fields[1].isdigit() and int(fields[1]) == child.pid and not fields[2].startswith('Z'):
            live_members.append(int(fields[0]))
    signalled = bool(live_members)
    if signalled:
        for action, pause in [(signal.SIGTERM, 0.25), (signal.SIGKILL, 0)]:
            try:
                os.killpg(child.pid, action)
            except ProcessLookupError:
                pass
            except PermissionError:
                # Once the final live member exits, Darwin can again report
                # EPERM for the reserved zombie-only group. Never broaden the
                # signal target to work around an actual permissions failure.
                latest = checked(['ps', '-axo', 'pid=,pgid=,stat='], timeout=5).stdout
                remaining = [row.split() for row in latest.splitlines()]
                require(not any(len(row) == 3 and row[1].isdigit() and int(row[1]) == child.pid and not row[2].startswith('Z') for row in remaining),
                        'Cannot stop a live member of the owned process group')
            if pause:
                time.sleep(pause)
    child.wait(timeout=10)
    return {'ownedProcessReaped': True, 'ownedGroupRequiredSignals': signalled,
            'signalsLimitedToOwnedReservedProcessGroup': True}


def version_endpoint(profile, child):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        require(child_exit_status(child) is None, 'Owned Chromium exited before startup completed')
        try:
            value = (profile / 'DevToolsActivePort').read_text()
            require(len(value) <= 1024, 'Oversized owned DevTools port file')
            lines = value.splitlines()
            port = int(lines[0])
            require(0 < port < 65536, 'Invalid owned DevTools port')
            connection = http.client.HTTPConnection('127.0.0.1', port, timeout=3)
            try:
                connection.request('GET', '/json/version')
                response = connection.getresponse()
                body = response.read(65_537)
                require(response.status == 200 and len(body) <= 65_536, 'Invalid owned CDP version response')
                result = json.loads(body)
            finally:
                connection.close()
            endpoint = urllib.parse.urlsplit(result['webSocketDebuggerUrl'])
            require(endpoint.scheme == 'ws' and endpoint.hostname == '127.0.0.1' and endpoint.port == port
                    and endpoint.path.startswith('/devtools/browser/') and not endpoint.query,
                    'DevTools endpoint is not the owned loopback browser')
            return result, port, endpoint.path
        except (FileNotFoundError, ValueError, KeyError, OSError, http.client.HTTPException):
            time.sleep(0.1)
    raise RuntimeError('Owned loopback Chromium endpoint did not become ready')


def close_browser(port, websocket_path):
    # A minimal local WebSocket command keeps this QA independent of Playwright
    # or downloaded dependencies. It only sends Browser.close to the owned port.
    key = base64.b64encode(os.urandom(16)).decode()
    with socket.create_connection(('127.0.0.1', port), timeout=5) as connection:
        request = (f'GET {websocket_path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n'
                   'Upgrade: websocket\r\nConnection: Upgrade\r\n'
                   f'Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n')
        connection.sendall(request.encode('ascii'))
        header = b''
        while b'\r\n\r\n' not in header:
            data = connection.recv(4096)
            require(bool(data), 'Owned WebSocket closed during handshake')
            header += data
            require(len(header) <= 16_384, 'Oversized owned WebSocket handshake')
        lines = header.split(b'\r\n\r\n', 1)[0].decode('ascii').split('\r\n')
        require(lines[0].split()[1] == '101', 'Owned WebSocket upgrade failed')
        fields = dict(line.split(':', 1) for line in lines[1:] if ':' in line)
        expected = base64.b64encode(hashlib.sha1((key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
        normalized = {name.lower(): value.strip() for name, value in fields.items()}
        require(normalized.get('sec-websocket-accept') == expected, 'Owned WebSocket accept mismatch')
        payload = b'{"id":1,"method":"Browser.close"}'
        mask = os.urandom(4)
        frame = bytes([0x81, 0x80 | len(payload)]) + mask + bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
        connection.sendall(frame)
        try:
            connection.recv(4096)
        except (socket.timeout, ConnectionResetError):
            pass  # Browser shutdown can race its final protocol response.


def run(app, output, hold_seconds):
    require(os.uname().sysname == 'Darwin', 'This smoke test requires macOS')
    app = app.resolve(strict=True)
    contents = app / 'Contents'
    lock = contents / 'Resources/kumo-update-lock'
    # Do not launch or stop anything when another browser/updater already owns
    # this installation. A failed baseline leaves that real user's app alone.
    require(exclusive_available(lock), 'Installation is in use; close Kumo before running this disposable smoke test')
    before = seal(app)
    info = json.loads((contents / 'Resources/KumoExtension/build-info.json').read_text())
    require(info.get('appUpdates', {}).get('included') is True, 'Packaged native updater metadata is missing')
    output.mkdir(parents=True, exist_ok=True)
    native = (ROOT / 'native/launcher/main.swift').read_text()
    prefix, separator, _ = native.partition('// Fixed setup actions run relative to this app.')
    require(bool(separator), 'Production launcher function boundary is missing')
    child = None
    cleanup = None
    with tempfile.TemporaryDirectory(prefix='kumo-updater-browser-smoke-', dir='/private/tmp') as temporary:
        temporary = Path(temporary).resolve()
        profile = temporary / 'profile'; profile.mkdir(mode=0o700)
        home = temporary / 'home'; home.mkdir(mode=0o700)
        environment = {**os.environ, 'HOME': str(home), 'CFFIXED_USER_HOME': str(home),
                       'KUMO_SETUP_NONINTERACTIVE': '1'}
        status_executable = contents / 'Helpers/KumoUpdater.app/Contents/MacOS/KumoUpdater'
        def status():
            result = checked([str(status_executable), '--status'], env=environment, timeout=20)
            require(len(result.stdout) <= 16_384, 'Oversized native updater status')
            value = json.loads(result.stdout)
            require(value.get('schemaVersion') == 1 and value.get('provider') == 'github-releases'
                    and value.get('available') is False, 'This bounded smoke test requires a disabled development updater')
            return value
        status_before = status()
        wrapper_source = temporary / 'lease-browser.swift'
        wrapper_source.write_text(prefix + r'''
do {
    let args = CommandLine.arguments
    let contents = URL(fileURLWithPath: args[1], isDirectory: true)
    let descriptor = try acquireBrowserUpdateLock(contents: contents)
    let engine = contents.appendingPathComponent("MacOS/Chromium")
    let command = [engine.path] + Array(args.dropFirst(2))
    let pointers = command.map { strdup($0) } + [nil]
    _ = pointers.withUnsafeBufferPointer { execv(engine.path, $0.baseAddress!) }
    close(descriptor)
    throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
} catch {
    fputs("lease-browser: \(error.localizedDescription)\n", stderr)
    exit(1)
}
''')
        wrapper = temporary / 'lease-browser'
        checked(['swiftc', '-O', '-module-cache-path', str(temporary / 'modules'),
                 str(wrapper_source), '-o', str(wrapper), '-framework', 'AppKit'], timeout=90)
        flags = [f'--user-data-dir={profile}', '--headless=new', '--no-first-run',
                 '--no-default-browser-check', '--use-mock-keychain', '--disable-sync',
                 '--disable-background-networking', '--disable-component-update',
                 '--host-resolver-rules=MAP * ~NOTFOUND', '--no-proxy-server',
                 '--remote-debugging-address=127.0.0.1', '--remote-debugging-port=0', 'about:blank']
        log = output / 'owned-chromium.log'
        with log.open('wb') as log_file:
            try:
                child = subprocess.Popen([str(wrapper), str(contents), *flags],
                                         stdin=subprocess.DEVNULL, stdout=log_file, stderr=log_file,
                                         env=environment, start_new_session=True)
                version, port, websocket_path = version_endpoint(profile, child)
                expected_engine = info['engineVersion'].split('-')[0]
                require(version.get('Browser', '').endswith('/' + expected_engine), 'Actual Chromium version does not match packaged metadata')
                require(not exclusive_available(lock), 'Actual Chromium did not retain its shared update lease after startup')
                reader = read_lock(lock)
                try:
                    fcntl.flock(reader, fcntl.LOCK_SH | fcntl.LOCK_NB)
                    fcntl.flock(reader, fcntl.LOCK_UN)
                finally:
                    os.close(reader)
                time.sleep(hold_seconds)
                require(child_exit_status(child) is None, 'Owned Chromium exited during lease observation')
                require(not exclusive_available(lock), 'Actual Chromium dropped its shared update lease while running')
                close_browser(port, websocket_path)
                deadline = time.monotonic() + 15
                while child_exit_status(child) is None and time.monotonic() < deadline:
                    time.sleep(0.1)
                require(child_exit_status(child) is not None, 'Owned Chromium did not shut down after Browser.close')
                require(exclusive_available(lock), 'Update lease remained held after owned Chromium shutdown')
            finally:
                if child is not None:
                    cleanup = cleanup_owned_child(child)
                    child = None
        status_after = status()
        require(status_after == status_before, 'Read-only native updater status changed during smoke test')
        require(not (contents / 'Resources/KumoExtension/_metadata').exists(), 'Browser wrote generated data inside sealed extension assets')
        after = seal(app)
        require(after == before, 'Signed application seal changed during smoke test')
        return {'passed': True, 'app': str(app.relative_to(ROOT)) if app.is_relative_to(ROOT) else app.name,
                'browserVersion': version['Browser'], 'launcherPrefixSHA256': hashlib.sha256(prefix.encode()).hexdigest(),
                'observationSecondsAfterStartup': hold_seconds,
                'checks': {'baselineExclusiveLeaseAvailable': True, 'actualChromiumSharedLeaseAfterStartup': True,
                           'concurrentSharedLeaseAllowed': True, 'actualChromiumSharedLeaseAfterObservation': True,
                           'browserClosedViaOwnedLoopbackCDP': True, 'exclusiveLeaseAvailableAfterBrowserExit': True,
                           'nativeStatusDisabledAndUnchanged': True, 'signedAppUnchanged': True},
                'nativeStatus': status_after, 'seal': after, 'cleanup': cleanup,
                'scope': {'headless': True, 'disposableProfile': True, 'allDNSDenied': True,
                          'backgroundNetworkingDisabled': True, 'loopbackDebuggingOnlyForQA': True,
                          'feedChecksPerformed': False, 'productionInstallationTested': False,
                          'productionInstallationUnavailableReason': 'Developer ID certificate and notarized release are not configured'}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--app', type=Path, default=ROOT / 'dist/Kumo.app')
    parser.add_argument('--output', type=Path, default=ROOT / '.cache/qa/github-release-updater-smoke')
    parser.add_argument('--hold-seconds', type=int, default=3)
    arguments = parser.parse_args()
    require(2 <= arguments.hold_seconds <= 15, 'Use an observation duration between two and fifteen seconds')
    for name in [signal.SIGINT, signal.SIGTERM]:
        signal.signal(name, lambda signum, frame: (_ for _ in ()).throw(KeyboardInterrupt()))
    result = None
    try:
        result = run(arguments.app, arguments.output, arguments.hold_seconds)
    except BaseException as error:
        result = {'passed': False, 'error': str(error) or type(error).__name__}
        raise
    finally:
        if result is not None:
            result['checkedAtUTC'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            arguments.output.mkdir(parents=True, exist_ok=True)
            (arguments.output / 'results.json').write_text(json.dumps(result, indent=2) + '\n')
            print(json.dumps(result, indent=2), flush=True)


if __name__ == '__main__':
    main()
