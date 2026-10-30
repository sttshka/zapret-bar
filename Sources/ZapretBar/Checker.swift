import Foundation

struct ProbeResult {
    let ok: Bool
    let seconds: Double
    let detail: String
}

enum Checker {
    /// Открывает адрес через curl: напрямую или через наш SOCKS-прокси.
    static func probe(_ url: String, viaPort port: Int?, timeout: Int = 8) -> ProbeResult {
        var args = ["-s", "-o", "/dev/null", "-m", "\(timeout)", "-A", "Mozilla/5.0",
                    "-w", "%{http_code} %{time_total} %{size_download}"]
        if let port { args += ["--socks5-hostname", "127.0.0.1:\(port)"] }
        args.append(url)
        let r = Shell.run("/usr/bin/curl", args, timeout: TimeInterval(timeout + 3))
        let parts = r.output.split(separator: " ")
        let code = parts.first.map(String.init) ?? "000"
        let secs = parts.count > 1 ? Double(parts[1]) ?? 0 : 0
        let bytes = parts.count > 2 ? Int(parts[2]) ?? 0 : 0
        let ok = r.status == 0 && code != "000"
        let detail: String
        switch r.status {
        case 0: detail = "HTTP \(code)"
        // Ответ пошёл и замер на первых килобайтах — так ТСПУ «замораживает» сайты за Cloudflare.
        case 28 where bytes > 0: detail = "замирает после \(max(1, bytes / 1024)) КБ"
        case 28: detail = "нет ответа"
        case 35, 56: detail = "соединение сброшено"
        case 6: detail = "сайт не найден (DNS)"
        case 7: detail = "не удалось подключиться"
        default: detail = "ошибка \(r.status)"
        }
        return ProbeResult(ok: ok, seconds: secs, detail: detail)
    }

    static func probeAll(_ services: [Service], viaPort port: Int?) -> [String: ProbeResult] {
        var results: [String: ProbeResult] = [:]
        let lock = NSLock()
        DispatchQueue.concurrentPerform(iterations: services.count) { i in
            let all = services[i].probeURLs.map { probe($0, viaPort: port) }
            // Показываем первую неудачу; если всё открылось — суммарное время.
            let r = all.first { !$0.ok } ?? ProbeResult(ok: true, seconds: all.map(\.seconds).reduce(0, +), detail: "")
            lock.lock(); results[services[i].id] = r; lock.unlock()
        }
        return results
    }

    struct StrategyScore {
        let strategy: Strategy
        let passed: Int
        let time: Double
    }

    /// Перебирает стратегии на временном порту и возвращает лучшую.
    static func pickBest(for services: [Service], testPort: Int,
                         progress: (Strategy, Int, Int) -> Void) -> [StrategyScore] {
        var scores: [StrategyScore] = []
        for (i, st) in Catalog.strategies.enumerated() {
            progress(st, i + 1, Catalog.strategies.count)
            let t = TPWSProcess(port: testPort)
            if st.fake && !FakeAccess.granted { continue }
            do { try t.start(arguments: TPWSProcess.networkArgs(port: testPort) + TPWSProcess.strategyArgs(st)) } catch { continue }
            let res = probeAll(services, viaPort: testPort)
            t.stop()
            let ok = res.values.filter(\.ok)
            scores.append(StrategyScore(strategy: st, passed: ok.count, time: ok.map(\.seconds).reduce(0, +)))
            // Всё прошло быстро — дальше искать незачем.
            if ok.count == services.count && (ok.map(\.seconds).max() ?? 0) < 2 { break }
        }
        return scores.sorted { $0.passed != $1.passed ? $0.passed > $1.passed : $0.time < $1.time }
    }
}
