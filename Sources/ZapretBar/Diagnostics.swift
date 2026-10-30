import AppKit

/// Запускает scripts/diagnose.sh (лежит внутри .app) и транслирует его вывод в окно настроек.
@MainActor
final class Diagnostics: ObservableObject {
    @Published private(set) var output = ""
    @Published private(set) var running = false
    @Published private(set) var report: URL?

    static let dir = Paths.support.appendingPathComponent("diagnostics", isDirectory: true)
    private var process: Process?

    private static var script: URL? {
        let candidates = [
            Bundle.main.url(forResource: "diagnose", withExtension: "sh"),
            URL(fileURLWithPath: FileManager.default.currentDirectoryPath).appendingPathComponent("scripts/diagnose.sh"),
        ]
        return candidates.compactMap { $0 }.first { FileManager.default.fileExists(atPath: $0.path) }
    }

    /// Похоже ли, что сейчас включён VPN. Клиенты вроде Happ/sing-box ставят маршруты 0/1 и 128/1,
    /// не трогая default, поэтому смотрим путь до внешнего адреса.
    static var vpnLikelyOn: Bool {
        Shell.run("/sbin/route", ["-n", "get", "1.1.1.1"], timeout: 3).output
            .split(separator: "\n").contains { line in
                line.contains("interface:") && ["utun", "ipsec", "ppp"].contains { line.contains($0) }
            }
    }

    func run(quick: Bool) {
        guard !running else { return }
        guard let script = Self.script, let tpws = Paths.tpws else {
            output = "Не найден скрипт диагностики или tpws. Пересоберите приложение scripts/build.sh."
            return
        }
        output = ""
        report = nil
        running = true

        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/bash")
        p.arguments = [script.path] + (quick ? ["--quick"] : [])
        var env = ProcessInfo.processInfo.environment
        env["TPWS"] = tpws.path
        env["DIAG_DIR"] = Self.dir.path
        if FakeAccess.granted, let file = FakeAccess.fakeFile, let link = FakeAccess.currentLink() {
            env["FAKE_LINK"] = link.arg
            env["FAKE_FILE"] = file.path
        }
        p.environment = env
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = pipe
        pipe.fileHandleForReading.readabilityHandler = { [weak self] h in
            let data = h.availableData
            guard !data.isEmpty, let text = String(data: data, encoding: .utf8) else { return }
            DispatchQueue.main.async { self?.output += text }
        }
        p.terminationHandler = { [weak self] _ in
            pipe.fileHandleForReading.readabilityHandler = nil
            DispatchQueue.main.async { self?.finished() }
        }
        do {
            try p.run()
            process = p
        } catch {
            running = false
            output = "Не удалось запустить диагностику: \(error.localizedDescription)"
        }
    }

    func stop() {
        guard let p = process, p.isRunning else { return }
        // Скрипт сам гасит свои tpws и Chrome по выходу.
        p.interrupt()
        DispatchQueue.main.asyncAfter(deadline: .now() + 2) { if p.isRunning { p.terminate() } }
    }

    private func finished() {
        running = false
        process = nil
        let files = (try? FileManager.default.contentsOfDirectory(at: Self.dir, includingPropertiesForKeys: [.contentModificationDateKey])) ?? []
        report = files.filter { $0.pathExtension == "txt" }
            .max { ($0.modificationDate ?? .distantPast) < ($1.modificationDate ?? .distantPast) }
    }

    func openReport() { if let report { NSWorkspace.shared.open(report) } }
    func revealReport() {
        if let report { NSWorkspace.shared.activateFileViewerSelecting([report]) }
        else { NSWorkspace.shared.open(Self.dir) }
    }
    func copyReport() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(output, forType: .string)
    }
}

private extension URL {
    var modificationDate: Date? { try? resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate }
}
