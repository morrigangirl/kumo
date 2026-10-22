import Foundation
import Darwin

// A prepared, verified definition directory is published only while its old
// inode remains available for rollback. Readiness includes the real final scan.
// Parent and directory identities are rechecked before every rename/removal;
// a changed path is preserved rather than overwritten during recovery.
final class DefinitionDirectoryTransaction {
    static let recoveryPrefix = "Kumo could not safely restore the previous virus definitions. The private transaction is preserved at "
    static let recoverySuffix = ". Retry the standard installer after checking that folder."
    private struct Identity: Equatable {
        let device: dev_t
        let inode: ino_t
        init(_ state: stat) { device = state.st_dev; inode = state.st_ino }
    }
    private let destination: URL
    let prepared: URL
    private let parent: URL
    private let directory: Int32
    private let parentIdentity: Identity
    private let incoming: Identity
    private let previous: Identity?
    private var published = false
    private var finished = false

    init(prepared: URL, destination: URL) throws {
        self.prepared = prepared.standardizedFileURL
        self.destination = destination.standardizedFileURL
        parent = self.destination.deletingLastPathComponent()
        guard self.prepared.deletingLastPathComponent() == parent,
              self.prepared != self.destination,
              !["", ".", ".."].contains(self.prepared.lastPathComponent),
              !["", ".", ".."].contains(self.destination.lastPathComponent) else {
            throw SetupError("Virus definitions must be staged beside their private destination.")
        }
        let fd = open(parent.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw SetupError("The private definition folder cannot be opened safely.") }
        do {
            var state = stat()
            guard fstat(fd, &state) == 0, state.st_mode & S_IFMT == S_IFDIR,
                  state.st_uid == getuid(), state.st_mode & 0o077 == 0 else {
                throw SetupError("The private definition folder has unsafe ownership or permissions.")
            }
            parentIdentity = Identity(state)
            incoming = try Self.entry(fd, self.prepared.lastPathComponent, required: true)!
            previous = try Self.entry(fd, self.destination.lastPathComponent, required: false)
            directory = fd
        } catch { close(fd); throw error }
    }
    deinit { close(directory) }

    private static func entry(_ directory: Int32, _ name: String, required: Bool) throws -> Identity? {
        var state = stat()
        guard fstatat(directory, name, &state, AT_SYMLINK_NOFOLLOW) == 0 else {
            if errno == ENOENT && !required { return nil }
            throw SetupError("A definition directory disappeared during setup.")
        }
        guard state.st_mode & S_IFMT == S_IFDIR, state.st_uid == getuid(), state.st_mode & 0o022 == 0 else {
            throw SetupError("A definition directory is a link or has unsafe ownership or permissions.")
        }
        return Identity(state)
    }

    private func checkParent() throws {
        var state = stat(), held = stat()
        guard lstat(parent.path, &state) == 0, fstat(directory, &held) == 0,
              state.st_mode & S_IFMT == S_IFDIR, state.st_uid == getuid(), state.st_mode & 0o077 == 0,
              Identity(state) == parentIdentity, Identity(held) == parentIdentity else {
            throw SetupError("The private definition folder changed during setup.")
        }
    }

    private func require(_ name: String, _ expected: Identity?) throws {
        guard try Self.entry(directory, name, required: expected != nil) == expected else {
            throw SetupError("A definition directory changed during setup.")
        }
    }

    private func publish() throws {
        try checkParent()
        try require(prepared.lastPathComponent, incoming)
        try require(destination.lastPathComponent, previous)
        let flags = previous == nil ? UInt32(RENAME_EXCL) : UInt32(RENAME_SWAP)
        guard renameatx_np(directory, prepared.lastPathComponent, directory, destination.lastPathComponent, flags) == 0 else {
            throw SetupError("Kumo could not activate your virus definitions.")
        }
        published = true
        try require(destination.lastPathComponent, incoming)
        try require(prepared.lastPathComponent, previous)
    }

    private func discardPrepared(_ expected: Identity) throws {
        try checkParent(); try require(prepared.lastPathComponent, expected)
        // The containing directory is verified private and the path still
        // names the recorded inode. Never remove an unrecognized replacement.
        try FileManager.default.removeItem(at: prepared)
    }

    private func rollback() throws {
        try checkParent()
        try require(destination.lastPathComponent, incoming)
        try require(prepared.lastPathComponent, previous)
        if let previous {
            guard renameatx_np(directory, prepared.lastPathComponent, directory, destination.lastPathComponent, UInt32(RENAME_SWAP)) == 0 else {
                throw SetupError("The previous virus definitions could not be restored.")
            }
            try require(destination.lastPathComponent, previous)
        } else {
            guard renameatx_np(directory, destination.lastPathComponent, directory, prepared.lastPathComponent, UInt32(RENAME_EXCL)) == 0 else {
                throw SetupError("The incomplete virus definitions could not be withdrawn.")
            }
        }
        finished = true
        // The previous directory has already been restored (or no prior
        // directory existed). Cleanup failure preserves only failed new data.
        try? discardPrepared(incoming)
    }

    private func commit() throws {
        try checkParent()
        try require(destination.lastPathComponent, incoming)
        try require(prepared.lastPathComponent, previous)
        finished = true
        // Only successful FULL readiness permits deleting the old definitions.
        // Failure to clean a backup does not undo a healthy committed database.
        if let previous { try? discardPrepared(previous) }
    }

    private func recoveryLocation() -> String {
        // If the parent was renamed, its held descriptor still identifies the
        // preserved transaction. Report that location, not a replacement path.
        var bytes = [CChar](repeating: 0, count: Int(PATH_MAX))
        if fcntl(directory, F_GETPATH, &bytes) == 0 {
            return URL(fileURLWithPath: String(cString: bytes), isDirectory: true)
                .appendingPathComponent(prepared.lastPathComponent).path
        }
        return prepared.path
    }

    func perform(readiness: () throws -> Void) throws {
        guard !finished && !published else { throw SetupError("This definition transaction has already run.") }
        do {
            try publish()
            try readiness()
            try commit()
        } catch {
            if published && !finished {
                do { try rollback() }
                catch {
                    let reason = Self.recoveryPrefix + recoveryLocation() + Self.recoverySuffix
                    throw SetupError(reason, recoveryReason: reason)
                }
            }
            throw error
        }
    }
}
