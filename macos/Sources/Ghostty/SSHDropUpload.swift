import Foundation
import OSLog

/// Uploads files dropped on a surface that is sitting in an SSH session.
///
/// Terminals type the local path when you drop a file on them, which names
/// nothing on the remote host. This finds the `ssh` process behind the
/// surface, copies the files up with `scp`, and hands back the remote paths
/// so the caller can insert those instead.
///
/// The SSH destination comes from this surface's own process tree rather than
/// from anything the remote reports. That is deliberate: OSC 7 is rejected
/// from non-local hosts (see `reportPwd` in stream_handler.zig) and window
/// titles are free-form strings set by whatever prompt the remote happens to
/// run. The local process tree is the only signal that needs nothing installed
/// on the far side, and it is unaffected by a multiplexer, since the `ssh`
/// process is local whether or not tmux is involved.
enum SSHDropUpload {
    private static let logger = Logger(
        subsystem: Bundle.main.bundleIdentifier ?? "com.mitchellh.ghostty",
        category: "ssh-drop-upload"
    )

    /// An SSH session discovered in a process tree.
    struct Destination {
        /// The `[user@]host` argument given to ssh.
        let host: String

        /// Connection options worth replaying for scp: identity, config file,
        /// jump host, `-o` overrides, and the port (as scp's `-P`).
        let options: [String]
    }

    // MARK: - Discovery

    /// ssh options that consume the following argument. Anything here must be
    /// skipped in pairs, otherwise its value gets mistaken for the host.
    private static let optionsWithValue: Set<Character> = [
        "b", "c", "D", "E", "e", "F", "I", "i", "J", "L",
        "l", "m", "O", "o", "p", "Q", "R", "S", "W", "w",
    ]

    /// Find the SSH session running under `pid`, if any.
    static func find(under pid: pid_t) -> Destination? {
        guard pid > 0 else { return nil }
        let table = processTable()
        guard !table.isEmpty else { return nil }

        var children: [pid_t: [pid_t]] = [:]
        var command: [pid_t: String] = [:]
        for row in table {
            children[row.ppid, default: []].append(row.pid)
            command[row.pid] = row.command
        }

        // Walk breadth-first and keep the deepest ssh we find, so a nested
        // hop (ssh into a box that ssh's onward) resolves to the outermost
        // local one we can actually drive -- that is the first hop, which is
        // the shallowest ssh. We take the shallowest deliberately: scp can
        // only reach the host we connect to directly.
        var queue: [(pid: pid_t, depth: Int)] = [(pid, 0)]
        var best: (destination: Destination, depth: Int)?
        while !queue.isEmpty {
            let (current, depth) = queue.removeFirst()
            if let line = command[current], let destination = parse(command: line) {
                if best == nil || depth < best!.depth {
                    best = (destination, depth)
                }
            }
            for child in children[current] ?? [] {
                queue.append((child, depth + 1))
            }
        }

        return best?.destination
    }

    /// Parse an ssh command line into a destination, or nil if it is not ssh.
    ///
    /// Exposed for testing; `ps` gives us a flat string with no quoting
    /// information, which is fine for ssh arguments in practice.
    static func parse(command line: String) -> Destination? {
        let tokens = line.split(separator: " ").map(String.init)
        guard let first = tokens.first else { return nil }
        guard (first as NSString).lastPathComponent == "ssh" else { return nil }

        var options: [String] = []
        var host: String?
        var index = 1
        while index < tokens.count {
            let token = tokens[index]
            if token == "--" {
                index += 1
                continue
            }

            guard token.hasPrefix("-"), token.count >= 2 else {
                // First bare word is the destination; everything after it is
                // the remote command, which tells us nothing.
                host = token
                break
            }

            let flag = token[token.index(token.startIndex, offsetBy: 1)]
            if optionsWithValue.contains(flag) {
                // Value may be attached (-p22) or separate (-p 22).
                let attached = token.count > 2
                let value = attached
                    ? String(token.dropFirst(2))
                    : (index + 1 < tokens.count ? tokens[index + 1] : nil)
                guard let value else { break }

                switch flag {
                case "p":
                    // scp spells the port -P.
                    options.append(contentsOf: ["-P", value])
                case "i", "F", "J", "o":
                    options.append(contentsOf: ["-\(flag)", value])
                default:
                    break
                }

                index += attached ? 1 : 2
                continue
            }

            index += 1
        }

        guard let host, !host.isEmpty else { return nil }
        return Destination(host: host, options: options)
    }

    // MARK: - Upload

    /// Copy `urls` to the remote host, returning absolute remote paths.
    ///
    /// Blocking: callers run this off the main queue.
    static func upload(
        _ urls: [URL],
        to destination: Destination,
        directory configured: String
    ) -> [String]? {
        guard let script = remoteDirectoryScript(configured) else {
            logger.warning(
                "refusing unsafe ssh-drop-upload-dir: \(configured, privacy: .public)"
            )
            return nil
        }

        // One round trip resolves and creates the directory, so the path we
        // insert is absolute rather than a `~` or `$TMPDIR` the program in the
        // pane may not expand.
        guard let directory = remoteDirectory(destination, script: script) else { return nil }

        let stamp = timestamp()
        var remotePaths: [String] = []
        for (index, url) in urls.enumerated() {
            let suffix = urls.count > 1 ? "-\(index)" : ""
            let name = "\(stamp)\(suffix)-\(sanitize(name: url.lastPathComponent))"
            let remotePath = "\(directory)/\(name)"

            var arguments = ["-q"]
            arguments.append(contentsOf: destination.options)
            // Do NOT quote the remote path. Modern scp speaks SFTP rather
            // than piping through a remote shell, so quotes would become
            // literal characters in the filename rather than grouping it.
            arguments.append(contentsOf: [
                "--", url.path, "\(destination.host):\(remotePath)",
            ])

            let result = run("/usr/bin/scp", arguments)
            guard result.status == 0 else {
                logger.warning("scp failed: \(result.error, privacy: .public)")
                return nil
            }

            remotePaths.append(remotePath)
        }

        restrictPermissions(destination, paths: remotePaths)
        return remotePaths
    }

    /// Build the remote snippet that resolves, creates, and prints the
    /// destination directory.
    ///
    /// Returns nil if the configured value could break out of the quoting.
    private static func remoteDirectoryScript(_ configured: String) -> String? {
        let value = configured.trimmingCharacters(in: .whitespaces)

        guard value.isEmpty else {
            guard !value.contains(where: { "\"'`$\\\n\r".contains($0) }) else { return nil }
            let path = value.hasPrefix("~/")
                ? "$HOME/\(value.dropFirst(2))"
                : value
            guard path.hasPrefix("/") || path.hasPrefix("$HOME/") else { return nil }
            return "d=\"\(path)\"; mkdir -p \"$d\" && printf %s \"$d\""
        }

        // Default: a private directory inside the remote's temp dir. The temp
        // dir itself is world-writable, so the 0700 mode is what makes this
        // safe to drop files into.
        return "d=\"${TMPDIR:-/tmp}\"; d=\"${d%/}/ghostty-drop-$(id -u)\"; " +
            "mkdir -p \"$d\" && chmod 700 \"$d\" && printf %s \"$d\""
    }

    private static func remoteDirectory(
        _ destination: Destination,
        script: String
    ) -> String? {
        var arguments = destination.options.map { $0 == "-P" ? "-p" : $0 }
        arguments.append(destination.host)
        arguments.append(script)

        let result = run("/usr/bin/ssh", arguments)
        guard result.status == 0 else {
            logger.warning("remote mkdir failed: \(result.error, privacy: .public)")
            return nil
        }

        let directory = result.output.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !directory.isEmpty, directory.hasPrefix("/") else { return nil }
        return directory
    }

    /// Best-effort tightening of the uploaded files' mode. A failure here is
    /// not fatal: the file is already there and the directory is private.
    private static func restrictPermissions(_ destination: Destination, paths: [String]) {
        guard !paths.isEmpty else { return }
        let quoted = paths.map { "'\($0)'" }.joined(separator: " ")

        var arguments = destination.options.map { $0 == "-P" ? "-p" : $0 }
        arguments.append(destination.host)
        arguments.append("chmod 600 \(quoted) 2>/dev/null")

        let result = run("/usr/bin/ssh", arguments)
        if result.status != 0 {
            logger.debug("could not chmod uploaded files: \(result.error, privacy: .public)")
        }
    }

    // MARK: - Helpers

    /// Keep remote filenames boring so the inserted path needs no quoting.
    private static func sanitize(name: String) -> String {
        let mapped = name.map { character -> Character in
            character.isLetter || character.isNumber || character == "." ||
                character == "_" || character == "-" ? character : "_"
        }
        let cleaned = String(mapped).drop(while: { $0 == "." })
        return cleaned.isEmpty ? "file" : String(cleaned)
    }

    private static func timestamp() -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyyMMdd-HHmmss"
        formatter.locale = Locale(identifier: "en_US_POSIX")
        return formatter.string(from: Date())
    }

    private static func processTable() -> [(pid: pid_t, ppid: pid_t, command: String)] {
        let result = run("/bin/ps", ["-axo", "pid=,ppid=,command="])
        guard result.status == 0 else { return [] }

        return result.output.split(separator: "\n").compactMap { line in
            let parts = line.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: true)
            guard parts.count == 3,
                  let pid = pid_t(parts[0]),
                  let ppid = pid_t(parts[1]) else { return nil }
            return (pid, ppid, String(parts[2]))
        }
    }

    private static func run(
        _ executable: String,
        _ arguments: [String]
    ) -> (status: Int32, output: String, error: String) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments

        let out = Pipe()
        let err = Pipe()
        process.standardOutput = out
        process.standardError = err
        // Never let scp or ssh stop on a password or host-key prompt; there is
        // no terminal attached to answer it and the drop would hang forever.
        process.standardInput = FileHandle.nullDevice

        do {
            try process.run()
        } catch {
            return (-1, "", "\(error)")
        }

        // Drain before waiting: a full pipe buffer would deadlock the child.
        let outData = out.fileHandleForReading.readDataToEndOfFile()
        let errData = err.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()

        return (
            process.terminationStatus,
            String(decoding: outData, as: UTF8.self),
            String(decoding: errData, as: UTF8.self)
        )
    }
}
