import Foundation
import Darwin
import KumoMalwareCore
import KumoMalwareSetupSupport

enum UserInitializer {
    static func initialize(payloads: Payloads, progress: (String) -> Void = { _ in }) throws {
        guard SetupPolicy.userAllowed(real: getuid(), effective: geteuid(), console: try consoleUID()) else { throw SetupError("Open Kumo Setup from the account currently logged into this Mac.") }
        try payloads.verify(progress: progress)
        try payloads.verifyApp(SetupPolicy.destination)
        let lock = try ClamAVLock(url: SetupPolicy.destination.appendingPathComponent("Contents/Resources/clamav-lock.json"))
        let runtime = try ClamAVRuntime(lock: lock)
        try runtime.verify()
        let setup = try ClamAVSetup(lock: lock)
        try setup.ensurePrivateDirectory(setup.base.deletingLastPathComponent())
        try setup.ensurePrivateDirectory(setup.base)
        progress("Preparing your virus definitions…")
        if (try? runtime.databaseState()) == nil {
            let stage = setup.base.appendingPathComponent(".definitions-" + UUID().uuidString, isDirectory: true)
            try setup.ensurePrivateDirectory(stage)
            var transactionOwnsStage = false
            defer { if !transactionOwnsStage { try? FileManager.default.removeItem(at: stage) } }
            for name in try FileManager.default.contentsOfDirectory(atPath: payloads.definitions.path) {
                guard allowedDefinition(name) else { throw SetupError("The bundled definitions contain an unexpected file.") }
                let destination = stage.appendingPathComponent(name)
                try FileManager.default.copyItem(at: payloads.definitions.appendingPathComponent(name), to: destination)
                guard chmod(destination.path, 0o600) == 0 else { throw SetupError("Kumo could not secure your virus definitions.") }
            }
            let seeded = try ClamAVRuntime(lock: lock, database: stage)
            var stale = false
            do { _ = try seeded.databaseState() }
            catch MalwareFailure.staleDatabase { stale = true }
            let transaction = try DefinitionDirectoryTransaction(prepared: stage, destination: runtime.database)
            transactionOwnsStage = true
            try transaction.perform {
                if stale {
                    progress("Updating virus definitions…")
                    _ = try setup.update(runtime: runtime)
                }
                try finishReadiness(runtime: runtime, setup: setup, progress: progress)
            }
        } else {
            try finishReadiness(runtime: runtime, setup: setup, progress: progress)
        }
    }

    private static func finishReadiness(runtime: ClamAVRuntime, setup: ClamAVSetup, progress: (String) -> Void) throws {
        _ = try runtime.databaseState()
        let configuration = try AutomaticDefinitionsUpdates.configuration(database: runtime.database)
        let config = setup.base.appendingPathComponent("freshclam.conf")
        let fd = open(config.path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw SetupError("Kumo could not write your antivirus update settings.") }
        let output = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        try output.write(contentsOf: Data(configuration.utf8))
        try output.close()
        guard chmod(config.path, 0o600) == 0 else { throw SetupError("Kumo could not secure your antivirus update settings.") }
        progress("Enabling automatic definition updates…")
        try setup.enableUpdates(runtime: runtime)
        _ = try run("/bin/launchctl", ["print", "gui/\(getuid())/" + AutomaticDefinitionsUpdates.label], maximumOutput: 131_072)
        progress("Checking download protection…")
        let scanner = SetupPolicy.destination.appendingPathComponent("Contents/Helpers/KumoMalware.app/Contents/MacOS/KumoMalwareHost")
        let result = try run(scanner.path, ["--status"])
        guard let status = try JSONSerialization.jsonObject(with: Data(result.output.utf8)) as? [String: Any], SetupPolicy.ready(status) else { throw SetupError("Download protection is not ready yet. Run the standard Kumo .pkg installer again.") }
        try benignScan(scanner: scanner, base: setup.base)
        guard SetupPolicy.userAllowed(real: getuid(), effective: geteuid(), console: try consoleUID()) else {
            throw SetupError("The logged-in account changed during protection setup. Retry the standard installer from your account.")
        }
    }

    static func allowedDefinition(_ name: String) -> Bool {
        if ["main.cvd", "daily.cvd", "bytecode.cvd"].contains(name) { return true }
        return name.range(of: "\\A(main|daily|bytecode)-[0-9]+\\.cvd\\.sign\\z", options: .regularExpression) != nil
    }

    static func benignScan(scanner: URL, base: URL) throws {
        let bytes = Data("Kumo Setup harmless download-protection check.\n".utf8)
        let file = base.appendingPathComponent(".scan-check-" + UUID().uuidString)
        let writeFD = open(file.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard writeFD >= 0 else { throw SetupError("Kumo could not prepare its harmless scan check.") }
        let writer = FileHandle(fileDescriptor: writeFD, closeOnDealloc: true)
        try writer.write(contentsOf: bytes); try writer.close()
        let fd = open(file.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { try? FileManager.default.removeItem(at: file); throw SetupError("Kumo could not open its harmless scan check.") }
        defer { close(fd); unlink(file.path) }
        let (hash, count) = try MalwareIO.hashDescriptor(fd)
        let id = UUID().uuidString
        let request: [String: Any] = ["version": 1, "requestId": id, "bytes": count, "sha256": hash]
        let input = try MalwareProtocol.encode(request)
        // Spawn with explicit fd3 inheritance. This is the same real sandboxed
        // helper and protocol used by the browser's download-completion gate.
        let response = try scanProcess(scanner: scanner, descriptor: fd, request: input)
        guard let reply = try JSONSerialization.jsonObject(with: response) as? [String: Any],
              let version = reply["version"] as? NSNumber, CFGetTypeID(version) != CFBooleanGetTypeID(), version == 1,
              reply["requestId"] as? String == id, reply["sha256"] as? String == hash,
              let size = reply["bytes"] as? NSNumber, CFGetTypeID(size) != CFBooleanGetTypeID(), size.doubleValue.isFinite,
              size.doubleValue.rounded(.towardZero) == size.doubleValue, size.doubleValue == Double(count),
              reply["verdict"] as? String == "no-known-malware", reply["reason"] as? String == "scan-complete" else {
            throw SetupError("The antivirus engine could not complete a harmless test scan. Run the standard Kumo .pkg installer again.")
        }
    }

    static func scanProcess(scanner: URL, descriptor: Int32, request: Data) throws -> Data {
        var input: [Int32] = [0, 0]; var output: [Int32] = [0, 0]
        guard pipe(&input) == 0 else { throw SetupError("The antivirus check could not start.") }
        guard pipe(&output) == 0 else { close(input[0]); close(input[1]); throw SetupError("The antivirus check could not start.") }
        // Duplicate all inherited descriptors above 3 so adddup2 cannot clobber
        // a pipe endpoint that happened to be allocated as descriptor 3.
        let inherited = fcntl(descriptor, F_DUPFD_CLOEXEC, 10)
        guard inherited >= 0 else { input.forEach { close($0) }; output.forEach { close($0) }; throw SetupError("The antivirus check could not inherit its test file.") }
        defer { close(inherited) }
        var actions: posix_spawn_file_actions_t?; var attributes: posix_spawnattr_t?
        guard posix_spawn_file_actions_init(&actions) == 0, posix_spawnattr_init(&attributes) == 0 else { input.forEach { close($0) }; output.forEach { close($0) }; throw SetupError("The antivirus check could not initialize.") }
        defer { posix_spawn_file_actions_destroy(&actions); posix_spawnattr_destroy(&attributes) }
        let actionResults = [
            posix_spawn_file_actions_adddup2(&actions, input[0], STDIN_FILENO),
            posix_spawn_file_actions_adddup2(&actions, output[1], STDOUT_FILENO),
            posix_spawn_file_actions_adddup2(&actions, output[1], STDERR_FILENO),
            posix_spawn_file_actions_adddup2(&actions, inherited, 3),
            posix_spawnattr_setpgroup(&attributes, 0),
            posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_CLOEXEC_DEFAULT)),
        ]
        guard actionResults.allSatisfy({ $0 == 0 }) else { input.forEach { close($0) }; output.forEach { close($0) }; throw SetupError("The antivirus check could not configure its helper.") }
        let environment = ["PATH=/usr/bin:/bin", "HOME=" + (try MalwareIO.actualHome().path), "LANG=C", "LC_ALL=C", "TMPDIR=" + FileManager.default.temporaryDirectory.path]
        var args = [strdup(scanner.path), nil]
        var env = environment.map { strdup($0) } + [nil]
        defer { args.forEach { free($0) }; env.forEach { free($0) } }
        var pid: pid_t = 0
        let code = posix_spawn(&pid, scanner.path, &actions, &attributes, &args, &env)
        close(input[0]); close(output[1])
        guard code == 0 else { close(input[1]); close(output[0]); throw SetupError("The signed download scanner could not start.") }
        let requestOutput = FileHandle(fileDescriptor: input[1], closeOnDealloc: true)
        do { try requestOutput.write(contentsOf: request); try requestOutput.close() }
        catch { kill(-pid, SIGKILL); var status: Int32 = 0; waitpid(pid, &status, 0); close(output[0]); throw error }
        let flags = fcntl(output[0], F_GETFL)
        _ = fcntl(output[0], F_SETFL, flags | O_NONBLOCK)
        defer { close(output[0]) }
        let deadline = ProcessInfo.processInfo.systemUptime + 180
        var collected = Data(); var status: Int32 = 0
        while true {
            var buffer = [UInt8](repeating: 0, count: 8192)
            let count = Darwin.read(output[0], &buffer, buffer.count)
            if count > 0 { collected.append(contentsOf: buffer.prefix(count)) }
            let waited = waitpid(pid, &status, WNOHANG)
            if waited == pid {
                while true {
                    let remaining = Darwin.read(output[0], &buffer, buffer.count)
                    if remaining <= 0 { break }; collected.append(contentsOf: buffer.prefix(remaining))
                    if collected.count > MalwareProtocol.maxJSON { break }
                }
                break
            }
            if waited < 0 || ProcessInfo.processInfo.systemUptime >= deadline || collected.count > MalwareProtocol.maxJSON {
                kill(-pid, SIGKILL)
                while waitpid(pid, &status, 0) < 0 { if errno != EINTR { break } }
                throw SetupError("The harmless download-protection check timed out or returned an invalid response.")
            }
            Thread.sleep(forTimeInterval: 0.02)
        }
        guard status == 0, collected.count <= MalwareProtocol.maxJSON else { throw SetupError("The signed download scanner did not complete its check.") }
        return collected
    }
}
