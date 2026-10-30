import Foundation

enum Coverage: String, Codable, CaseIterable, Identifiable {
    case selected   // только выбранные сервисы и свои сайты
    case everything // все сайты, кроме исключений
    var id: String { rawValue }
    var title: String {
        switch self {
        case .selected: return "Только выбранные"
        case .everything: return "Все сайты"
        }
    }
}

struct AppSettings: Codable, Equatable {
    var enabledServices: Set<String> = ["youtube", "discord"]
    var customDomains: [String] = []
    var excludedDomains: [String] = []
    var coverage: Coverage = .selected
    var strategyID: String = "fake"
    /// Свои параметры tpws; если не пусто — используются вместо стратегии.
    var customArgs: String = ""
    var autoHostlist: Bool = true
    var port: Int = 10_888
    var startOnLaunch: Bool = true
    /// Подробный журнал tpws — для разбора, почему что-то не открывается.
    var verboseLog: Bool = false

    var strategy: Strategy { Catalog.strategy(strategyID) }

    var allDomains: [String] {
        var seen = Set<String>()
        let fromServices = Catalog.services.filter { enabledServices.contains($0.id) }.flatMap(\.domains)
        return (fromServices + customDomains).compactMap(AppSettings.normalize).filter { seen.insert($0).inserted }
    }

    /// Превращает «https://www.Example.com/path» в «example.com».
    static func normalize(_ raw: String) -> String? {
        var s = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if s.isEmpty || s.hasPrefix("#") { return nil }
        if let r = s.range(of: "://") { s = String(s[r.upperBound...]) }
        if let slash = s.firstIndex(where: { $0 == "/" || $0 == ":" || $0 == "?" }) { s = String(s[..<slash]) }
        if s.hasPrefix("*.") { s.removeFirst(2) }
        if s.hasPrefix("www.") { s.removeFirst(4) }
        guard s.contains("."), s.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "." || $0 == "-" }) else { return nil }
        return s
    }
}

enum Paths {
    static let support: URL = {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        let dir = base.appendingPathComponent("ZapretBar", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }()
    static let settings = support.appendingPathComponent("settings.json")
    static let hostlist = support.appendingPathComponent("hostlist.txt")
    static let exclude = support.appendingPathComponent("exclude.txt")
    static let autoHostlist = support.appendingPathComponent("autohostlist.txt")
    static let proxyBackup = support.appendingPathComponent("proxy-backup.json")
    static let log = support.appendingPathComponent("tpws.log")

    /// tpws лежит внутри .app; для запуска из `swift run` — рядом в vendor.
    static var tpws: URL? {
        let candidates = [
            Bundle.main.url(forResource: "tpws", withExtension: nil),
            support.appendingPathComponent("tpws"),
            URL(fileURLWithPath: FileManager.default.currentDirectoryPath).appendingPathComponent("vendor/zapret/tpws/tpws"),
        ]
        return candidates.compactMap { $0 }.first { FileManager.default.isExecutableFile(atPath: $0.path) }
    }
}

enum SettingsStore {
    static func load() -> AppSettings {
        guard let data = try? Data(contentsOf: Paths.settings),
              let s = try? JSONDecoder().decode(AppSettings.self, from: data) else { return AppSettings() }
        return s
    }

    static func save(_ s: AppSettings) {
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        try? enc.encode(s).write(to: Paths.settings, options: .atomic)
    }
}

extension AppSettings {
    /// Терпимое чтение: отсутствующие поля берутся по умолчанию, чтобы старые настройки не терялись.
    init(from decoder: Decoder) throws {
        self.init()
        let c = try decoder.container(keyedBy: CodingKeys.self)
        enabledServices = try c.decodeIfPresent(Set<String>.self, forKey: .enabledServices) ?? enabledServices
        customDomains = try c.decodeIfPresent([String].self, forKey: .customDomains) ?? customDomains
        excludedDomains = try c.decodeIfPresent([String].self, forKey: .excludedDomains) ?? excludedDomains
        coverage = (try? c.decodeIfPresent(Coverage.self, forKey: .coverage)) ?? coverage
        strategyID = try c.decodeIfPresent(String.self, forKey: .strategyID) ?? strategyID
        customArgs = try c.decodeIfPresent(String.self, forKey: .customArgs) ?? customArgs
        autoHostlist = try c.decodeIfPresent(Bool.self, forKey: .autoHostlist) ?? autoHostlist
        port = try c.decodeIfPresent(Int.self, forKey: .port) ?? port
        startOnLaunch = try c.decodeIfPresent(Bool.self, forKey: .startOnLaunch) ?? startOnLaunch
        verboseLog = try c.decodeIfPresent(Bool.self, forKey: .verboseLog) ?? verboseLog
    }
}
