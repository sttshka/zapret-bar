import Foundation

/// Подмена ClientHello (как winws/nfqws на Windows/Linux): tpws пишет поддельный пакет прямо
/// в сетевой интерфейс через /dev/bpf. Доступ к /dev/bpf выдаётся один раз с паролем
/// администратора — так же, как это делает ChmodBPF у Wireshark.
enum FakeAccess {
    static let daemonLabel = "dev.sttshka.zapretbar.bpf"
    static let daemonPlist = "/Library/LaunchDaemons/\(daemonLabel).plist"
    static let daemonScript = "/Library/Application Support/ZapretBar/bpf-access.sh"

    /// Есть ли у нас право писать в /dev/bpf.
    static var granted: Bool {
        (0..<8).contains { access("/dev/bpf\($0)", R_OK | W_OK) == 0 }
    }

    static var installed: Bool { FileManager.default.fileExists(atPath: daemonPlist) }

    /// Поддельное приветствие из набора zapret (SNI www.google.com).
    static var fakeFile: URL? {
        let candidates = [
            Bundle.main.url(forResource: "tls_clienthello_www_google_com", withExtension: "bin", subdirectory: "fake"),
            URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
                .appendingPathComponent("vendor/zapret/files/fake/tls_clienthello_www_google_com.bin"),
        ]
        return candidates.compactMap { $0 }.first { FileManager.default.fileExists(atPath: $0.path) }
    }

    struct Link: Equatable {
        let iface: String
        let srcMAC: String
        let gatewayMAC: String
        var arg: String { "--fake-link=\(iface),\(srcMAC),\(gatewayMAC)" }
    }

    /// Интерфейс, через который реально идёт трафик в интернет, и MAC роутера.
    /// nil — подмена невозможна: например, включён VPN (utun) или нет сети.
    static func currentLink() -> Link? {
        let route = keyValues(Shell.run("/sbin/route", ["-n", "get", "1.1.1.1"], timeout: 3).output)
        guard let iface = route["interface"], !iface.hasPrefix("utun"), !iface.hasPrefix("ipsec"),
              !iface.hasPrefix("ppp"), let gw = route["gateway"] else { return nil }
        guard let src = Shell.run("/sbin/ifconfig", [iface], timeout: 3).output
            .split(separator: "\n").first(where: { $0.contains("ether ") })?
            .split(separator: " ").dropFirst().first.map(String.init) else { return nil }
        var mac = arpMAC(gw)
        if mac == nil {
            // Запись ARP могла устареть: один ping освежит её.
            Shell.run("/sbin/ping", ["-c", "1", "-t", "1", gw], timeout: 3)
            mac = arpMAC(gw)
        }
        guard let gwMAC = mac else { return nil }
        return Link(iface: iface, srcMAC: src, gatewayMAC: gwMAC)
    }

    private static func arpMAC(_ ip: String) -> String? {
        let out = Shell.run("/usr/sbin/arp", ["-n", ip], timeout: 3).output
        guard let r = out.range(of: " at ") else { return nil }
        let mac = out[r.upperBound...].split(separator: " ").first.map(String.init) ?? ""
        // arp пишет "0:1b:2:..." без ведущих нулей — tpws понимает и так, но приведём к виду xx:xx.
        let parts = mac.split(separator: ":")
        guard parts.count == 6, parts.allSatisfy({ UInt8($0, radix: 16) != nil }) else { return nil }
        return parts.map { $0.count == 1 ? "0" + $0 : String($0) }.joined(separator: ":")
    }

    private static func keyValues(_ text: String) -> [String: String] {
        var d: [String: String] = [:]
        for line in text.split(separator: "\n") {
            let p = line.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
            if p.count == 2 { d[p[0]] = p[1] }
        }
        return d
    }

    // MARK: - Установка доступа

    /// Ставит LaunchDaemon, который при каждой загрузке отдаёт /dev/bpf* текущему пользователю,
    /// и сразу запускает его. Один запрос пароля.
    static func install() throws {
        let user = NSUserName()
        let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("zapretbar-bpf-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmp) }

        let script = """
        #!/bin/bash
        # ZapretBar: даёт пользователю \(user) доступ к /dev/bpf* (как ChmodBPF у Wireshark).
        # Нужен tpws, чтобы отправлять поддельный ClientHello перед настоящим.
        i=1
        while [ $i -lt 64 ]; do
          read -r -n 0 < /dev/bpf$i > /dev/null 2>&1   # открытие создаёт следующее устройство
          i=$((i+1))
        done
        chown \(user) /dev/bpf*
        chmod u+rw /dev/bpf*
        """
        let plist = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>Label</key><string>\(daemonLabel)</string>
            <key>ProgramArguments</key><array><string>/bin/bash</string><string>\(daemonScript)</string></array>
            <key>RunAtLoad</key><true/>
        </dict>
        </plist>
        """
        let s = tmp.appendingPathComponent("bpf-access.sh"), p = tmp.appendingPathComponent("daemon.plist")
        try script.write(to: s, atomically: true, encoding: .utf8)
        try plist.write(to: p, atomically: true, encoding: .utf8)

        try Admin.run([
            ["/bin/mkdir", "-p", (daemonScript as NSString).deletingLastPathComponent],
            ["/usr/bin/install", "-o", "root", "-g", "wheel", "-m", "755", s.path, daemonScript],
            ["/usr/bin/install", "-o", "root", "-g", "wheel", "-m", "644", p.path, daemonPlist],
            ["/bin/launchctl", "bootout", "system/\(daemonLabel)"],
            ["/bin/launchctl", "bootstrap", "system", daemonPlist],
        ], prompt: "ZapretBar хочет получить доступ к сетевому интерфейсу, чтобы обходить блокировку Discord и других сайтов.")

        // Демон отрабатывает за доли секунды.
        for _ in 0..<20 where !granted { Thread.sleep(forTimeInterval: 0.1) }
        if !granted { throw NSError(domain: "ZapretBar", code: 2, userInfo: [NSLocalizedDescriptionKey: "Доступ к /dev/bpf так и не появился"]) }
    }

    static func uninstall() throws {
        try Admin.run([
            ["/bin/launchctl", "bootout", "system/\(daemonLabel)"],
            ["/bin/rm", "-f", daemonPlist, daemonScript],
            ["/bin/sh", "-c", "chown root /dev/bpf*"],
        ], prompt: "ZapretBar убирает свой доступ к сетевому интерфейсу.")
    }
}

/// Выполнение команд с правами администратора одним системным запросом пароля.
enum Admin {
    static func run(_ cmds: [[String]], prompt: String) throws {
        let quote: (String) -> String = { "'" + $0.replacingOccurrences(of: "'", with: "'\\''") + "'" }
        // bootout падает, если демона ещё нет, — это не ошибка.
        let script = cmds.map { c -> String in
            let line = c.map(quote).joined(separator: " ")
            return c.contains("bootout") ? "(\(line) 2>/dev/null || true)" : line
        }.joined(separator: " && ")
        let escaped = script.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
        let source = "do shell script \"\(escaped)\" with administrator privileges with prompt \"\(prompt)\""
        // NSAppleScript не потокобезопасен — только с главного потока.
        var err: NSDictionary?
        let exec = { _ = NSAppleScript(source: source)?.executeAndReturnError(&err) }
        if Thread.isMainThread { exec() } else { DispatchQueue.main.sync(execute: exec) }
        if let err {
            throw NSError(domain: "ZapretBar", code: 1, userInfo: [NSLocalizedDescriptionKey:
                (err[NSAppleScript.errorMessage] as? String) ?? "Не удалось выполнить с правами администратора"])
        }
    }
}
