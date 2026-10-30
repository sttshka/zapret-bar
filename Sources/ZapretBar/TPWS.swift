import Foundation

enum TPWSError: LocalizedError {
    case binaryMissing
    case exited(String)

    var errorDescription: String? {
        switch self {
        case .binaryMissing: return "Не найден tpws. Пересоберите приложение скриптом scripts/build.sh."
        case .exited(let msg): return msg.isEmpty ? "tpws неожиданно завершился" : msg
        }
    }
}

/// Запускает и останавливает один процесс tpws в режиме SOCKS-прокси.
final class TPWSProcess {
    private var process: Process?
    private var output = ""
    private let lock = NSLock()
    var onExit: ((String) -> Void)?

    let port: Int
    init(port: Int) { self.port = port }

    var isRunning: Bool { process?.isRunning ?? false }

    static func networkArgs(port: Int) -> [String] {
        ["--socks", "--bind-addr=127.0.0.1", "--port=\(port)"]
    }

    /// Полный набор параметров для боевого запуска: файлы списков пишутся заранее.
    static func arguments(for s: AppSettings, port: Int) -> [String] {
        var args = networkArgs(port: port)
        writeLists(s)
        switch s.coverage {
        case .selected:
            args.append("--hostlist=\(Paths.hostlist.path)")
            if s.autoHostlist {
                if !FileManager.default.fileExists(atPath: Paths.autoHostlist.path) {
                    write([], to: Paths.autoHostlist)
                }
                args.append("--hostlist-auto=\(Paths.autoHostlist.path)")
            }
        case .everything:
            if !s.excludedDomains.compactMap(AppSettings.normalize).isEmpty {
                args.append("--hostlist-exclude=\(Paths.exclude.path)")
            }
        }
        if s.verboseLog { args.append("--debug=1") }
        let custom = s.customArgs.split(whereSeparator: \.isWhitespace).map(String.init)
        return args + (custom.isEmpty ? strategyArgs(s.strategy) : custom)
    }

    /// Параметры способа обхода. Для подмены добавляются файл приветствия и канал до роутера;
    /// если подмена сейчас невозможна (нет доступа, VPN, нет сети) — откат на «лишний байт».
    static func strategyArgs(_ st: Strategy) -> [String] {
        guard st.fake else { return st.args }
        if FakeAccess.granted, let file = FakeAccess.fakeFile, let link = FakeAccess.currentLink() {
            return [link.arg, "--fake-tls=\(file.path)"] + st.args
        }
        return Catalog.strategy("oob").args
    }

    /// Списки сайтов для tpws (и для службы шлюза, которая читает те же файлы).
    static func writeLists(_ s: AppSettings) {
        write(s.allDomains, to: Paths.hostlist)
        write(s.excludedDomains.compactMap(AppSettings.normalize), to: Paths.exclude)
    }

    /// Пишет только при изменении: служба шлюза перезапускается по дате изменения файла.
    private static func write(_ lines: [String], to url: URL) {
        let text = lines.joined(separator: "\n") + "\n"
        guard (try? String(contentsOf: url, encoding: .utf8)) != text else { return }
        try? text.write(to: url, atomically: true, encoding: .utf8)
    }

    func start(arguments: [String]) throws {
        guard let bin = Paths.tpws else { throw TPWSError.binaryMissing }
        Self.killStale(port: port)

        let p = Process()
        p.executableURL = bin
        p.arguments = arguments
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = pipe
        pipe.fileHandleForReading.readabilityHandler = { [weak self] h in
            let data = h.availableData
            guard !data.isEmpty, let text = String(data: data, encoding: .utf8) else { return }
            self?.append(text)
        }
        p.terminationHandler = { [weak self] proc in
            pipe.fileHandleForReading.readabilityHandler = nil
            // Штатная остановка нами — не ошибка.
            guard let self, self.process === proc else { return }
            self.onExit?(self.lastLines())
        }
        try p.run()
        process = p

        // Дадим tpws мгновение: ошибки параметров и занятый порт проявляются сразу.
        Thread.sleep(forTimeInterval: 0.3)
        if !p.isRunning {
            throw TPWSError.exited(lastLines())
        }
    }

    func stop() {
        guard let p = process else { return }
        process = nil
        if p.isRunning {
            p.terminate()
            p.waitUntilExit()
        }
    }

    private func append(_ text: String) {
        lock.lock(); defer { lock.unlock() }
        output += text
        if output.count > 20_000 { output = String(output.suffix(10_000)) }
        if let h = try? FileHandle(forWritingTo: Paths.log) {
            h.seekToEndOfFile(); h.write(Data(text.utf8)); try? h.close()
        } else {
            try? text.write(to: Paths.log, atomically: false, encoding: .utf8)
        }
    }

    func lastLines(_ n: Int = 6) -> String {
        lock.lock(); defer { lock.unlock() }
        return output.split(separator: "\n").suffix(n).joined(separator: "\n")
    }

    /// Убивает tpws, оставшийся от прошлого запуска (например, после падения), если он держит наш порт.
    static func killStale(port: Int) {
        let lsof = Shell.run("/usr/sbin/lsof", ["-nP", "-t", "-iTCP:\(port)", "-sTCP:LISTEN"])
        for pid in lsof.output.split(separator: "\n").compactMap({ Int32($0) }) {
            let name = Shell.run("/bin/ps", ["-p", "\(pid)", "-o", "comm="]).output
            if name.hasSuffix("tpws") { kill(pid, SIGTERM) }
        }
    }
}

enum Shell {
    struct Result { let status: Int32; let output: String }

    @discardableResult
    static func run(_ path: String, _ args: [String], timeout: TimeInterval = 30) -> Result {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: path)
        p.arguments = args
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = pipe
        do { try p.run() } catch { return Result(status: -1, output: error.localizedDescription) }
        let deadline = DispatchTime.now() + timeout
        let group = DispatchGroup()
        group.enter()
        var data = Data()
        DispatchQueue.global().async {
            data = pipe.fileHandleForReading.readDataToEndOfFile()
            group.leave()
        }
        if group.wait(timeout: deadline) == .timedOut { p.terminate() }
        p.waitUntilExit()
        _ = group.wait(timeout: .now() + 1)
        return Result(status: p.terminationStatus,
                      output: String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? "")
    }
}
