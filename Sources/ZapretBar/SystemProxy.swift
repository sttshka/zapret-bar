import Foundation

/// Включает системный SOCKS-прокси на tpws для всех сетевых служб и возвращает всё как было.
enum SystemProxy {
    private static let tool = "/usr/sbin/networksetup"

    static let bypass = ["localhost", "127.0.0.1", "::1", "*.local", "169.254/16",
                         "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]

    struct Saved: Codable {
        var socksEnabled: Bool
        var server: String
        var port: String
        var bypass: [String]
    }

    static func services() -> [String] {
        Shell.run(tool, ["-listallnetworkservices"]).output
            .split(separator: "\n").map(String.init)
            .filter { !$0.hasPrefix("*") && !$0.hasPrefix("An asterisk") && !$0.isEmpty }
    }

    /// Включён ли наш прокси хоть на одной службе (нужно, чтобы починить сеть после падения).
    static func isPointingTo(port: Int) -> Bool {
        services().contains { svc in
            let info = parse(Shell.run(tool, ["-getsocksfirewallproxy", svc]).output)
            return info["Enabled"] == "Yes" && info["Server"] == "127.0.0.1" && info["Port"] == "\(port)"
        }
    }

    static func enable(port: Int) throws {
        let svcs = services()
        // Бэкап делаем только если его ещё нет: иначе после падения сохраним свои же настройки.
        if !FileManager.default.fileExists(atPath: Paths.proxyBackup.path) {
            var saved: [String: Saved] = [:]
            for svc in svcs {
                let info = parse(Shell.run(tool, ["-getsocksfirewallproxy", svc]).output)
                let byp = Shell.run(tool, ["-getproxybypassdomains", svc]).output
                    .split(separator: "\n").map(String.init).filter { !$0.contains(" ") }
                saved[svc] = Saved(socksEnabled: info["Enabled"] == "Yes",
                                   server: info["Server"] ?? "", port: info["Port"] ?? "0", bypass: byp)
            }
            try? JSONEncoder().encode(saved).write(to: Paths.proxyBackup, options: .atomic)
        }

        var cmds: [[String]] = []
        for svc in svcs {
            let byp = Array(Set(bypass + (loadBackup()[svc]?.bypass ?? []))).sorted()
            cmds.append(["-setsocksfirewallproxy", svc, "127.0.0.1", "\(port)", "off"])
            cmds.append(["-setproxybypassdomains", svc] + byp)
            cmds.append(["-setsocksfirewallproxystate", svc, "on"])
        }
        try execute(cmds)
    }

    static func disable() throws {
        let saved = loadBackup()
        var cmds: [[String]] = []
        for svc in services() {
            if let s = saved[svc] {
                if s.socksEnabled, !s.server.isEmpty {
                    cmds.append(["-setsocksfirewallproxy", svc, s.server, s.port, "off"])
                    cmds.append(["-setsocksfirewallproxystate", svc, "on"])
                } else {
                    cmds.append(["-setsocksfirewallproxystate", svc, "off"])
                }
                cmds.append(["-setproxybypassdomains", svc] + (s.bypass.isEmpty ? ["Empty"] : s.bypass))
            } else {
                cmds.append(["-setsocksfirewallproxystate", svc, "off"])
            }
        }
        try execute(cmds)
        try? FileManager.default.removeItem(at: Paths.proxyBackup)
    }

    private static func loadBackup() -> [String: Saved] {
        guard let data = try? Data(contentsOf: Paths.proxyBackup) else { return [:] }
        return (try? JSONDecoder().decode([String: Saved].self, from: data)) ?? [:]
    }

    private static func parse(_ text: String) -> [String: String] {
        var d: [String: String] = [:]
        for line in text.split(separator: "\n") {
            let parts = line.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
            if parts.count == 2 { d[parts[0]] = parts[1] }
        }
        return d
    }

    /// Сначала пробуем без пароля (администраторам обычно можно), иначе — один системный запрос пароля на всё.
    private static func execute(_ cmds: [[String]]) throws {
        guard !cmds.isEmpty else { return }
        let first = Shell.run(tool, cmds[0])
        if first.status == 0 && !first.output.lowercased().contains("admin") {
            for c in cmds.dropFirst() { Shell.run(tool, c) }
            return
        }
        let script = cmds.map { ([tool] + $0).map(shellQuote).joined(separator: " ") }.joined(separator: "; ")
        let apple = "do shell script \"\(script.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\""))\" with administrator privileges with prompt \"ZapretBar хочет настроить системный прокси.\""
        var err: NSDictionary?
        NSAppleScript(source: apple)?.executeAndReturnError(&err)
        if let err {
            throw NSError(domain: "ZapretBar", code: 1, userInfo: [NSLocalizedDescriptionKey:
                (err[NSAppleScript.errorMessage] as? String) ?? "Не удалось изменить настройки прокси"])
        }
    }

    private static func shellQuote(_ s: String) -> String {
        "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
}
