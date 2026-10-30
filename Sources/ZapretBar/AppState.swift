import AppKit
import Combine
import Network
import ServiceManagement

enum Status: Equatable {
    case off, starting, on, stopping
    case failed(String)

    var title: String {
        switch self {
        case .off: return "Выключено"
        case .starting: return "Включаю…"
        case .on: return "Работает"
        case .stopping: return "Выключаю…"
        case .failed: return "Ошибка"
        }
    }
}

@MainActor
final class AppState: ObservableObject {
    @Published var settings: AppSettings {
        didSet {
            guard settings != oldValue else { return }
            SettingsStore.save(settings)
            checks = [:]
            scheduleApply(portChanged: settings.port != oldValue.port)
        }
    }
    @Published private(set) var status: Status = .off
    @Published private(set) var checks: [String: ProbeResult] = [:]
    @Published private(set) var checking = false
    @Published private(set) var pickProgress: String?
    @Published private(set) var lastPick: String?
    /// Есть ли доступ к /dev/bpf для подмены ClientHello.
    @Published private(set) var fakeGranted = FakeAccess.granted
    @Published private(set) var fakeMessage: String?
    @Published var launchAtLogin: Bool = SMAppService.mainApp.status == .enabled {
        didSet { setLaunchAtLogin(launchAtLogin) }
    }

    var isOn: Bool { status == .on }
    var busy: Bool { status == .starting || status == .stopping || pickProgress != nil }

    private let worker = DispatchQueue(label: "zapretbar.worker")
    /// Был ли обход включён перед выходом — чтобы при запуске вернуть как было.
    private var wasOn: Bool {
        get { UserDefaults.standard.bool(forKey: "wasOn") }
        set { UserDefaults.standard.set(newValue, forKey: "wasOn") }
    }
    private var tpws: TPWSProcess?
    private var applyTask: DispatchWorkItem?
    private let pathMonitor = NWPathMonitor()
    private var lastLink: FakeAccess.Link?

    init() {
        settings = SettingsStore.load()
        recoverAfterCrash()
        watchNetwork()
    }

    // MARK: - Вкл/выкл

    func toggle() { isOn ? stop() : start() }

    func start() {
        guard !busy else { return }
        status = .starting
        checks = [:]
        let s = settings
        worker.async { [weak self] in
            let result: Result<TPWSProcess, Error> = Result {
                let p = TPWSProcess(port: s.port)
                try p.start(arguments: TPWSProcess.arguments(for: s, port: s.port))
                do { try SystemProxy.enable(port: s.port) } catch { p.stop(); throw error }
                return p
            }
            DispatchQueue.main.async { self?.finishStart(result) }
        }
    }

    private func finishStart(_ result: Result<TPWSProcess, Error>) {
        switch result {
        case .success(let p):
            tpws = p
            p.onExit = { [weak self] log in
                DispatchQueue.main.async { self?.crashed(log) }
            }
            status = .on
            wasOn = true
        case .failure(let e):
            status = .failed(e.localizedDescription)
            // Прокси мог остаться от прошлого запуска и вести в никуда.
            if FileManager.default.fileExists(atPath: Paths.proxyBackup.path) {
                worker.async { try? SystemProxy.disable() }
            }
        }
    }

    func stop(completion: (() -> Void)? = nil) {
        guard status != .stopping else { return }
        status = .stopping
        wasOn = false
        let p = tpws
        tpws = nil
        worker.async { [weak self] in
            let err = Result { try SystemProxy.disable() }
            p?.stop()
            DispatchQueue.main.async {
                if case .failure(let e) = err { self?.status = .failed(e.localizedDescription) } else { self?.status = .off }
                completion?()
            }
        }
    }

    /// tpws умер сам: снимаем прокси, иначе у пользователя пропадёт интернет.
    private func crashed(_ log: String) {
        tpws = nil
        worker.async { try? SystemProxy.disable() }
        status = .failed("tpws остановился. " + log)
    }

    /// Прошлый запуск закончился падением — прокси мог остаться и «сломать» интернет.
    private func recoverAfterCrash() {
        let port = settings.port
        let autostart = settings.startOnLaunch && wasOn
        worker.async { [weak self] in
            let stale = FileManager.default.fileExists(atPath: Paths.proxyBackup.path) || SystemProxy.isPointingTo(port: port)
            if stale && !autostart { try? SystemProxy.disable() }
            DispatchQueue.main.async {
                if autostart { self?.start() }
            }
        }
    }

    /// Остановка при выходе из приложения: синхронно, чтобы не оставить прокси.
    func shutdownSync() {
        tpws?.onExit = nil
        tpws?.stop()
        tpws = nil
        if FileManager.default.fileExists(atPath: Paths.proxyBackup.path) { try? SystemProxy.disable() }
    }

    // MARK: - Применение настроек на лету

    private func scheduleApply(portChanged: Bool) {
        applyTask?.cancel()
        guard isOn else { return }
        let task = DispatchWorkItem { [weak self] in self?.restart(portChanged: portChanged) }
        applyTask = task
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.6, execute: task)
    }

    private func restart(portChanged: Bool) {
        guard isOn, let old = tpws else { return }
        if portChanged { stop { [weak self] in self?.start() }; return }
        status = .starting
        old.onExit = nil
        let s = settings
        worker.async { [weak self] in
            old.stop()
            let result: Result<TPWSProcess, Error> = Result {
                let p = TPWSProcess(port: s.port)
                try p.start(arguments: TPWSProcess.arguments(for: s, port: s.port))
                return p
            }
            if case .failure = result { try? SystemProxy.disable() }
            DispatchQueue.main.async { self?.finishStart(result) }
        }
    }

    // MARK: - Проверка и автоподбор

    var selectedServices: [Service] { Catalog.services.filter { settings.enabledServices.contains($0.id) } }

    func check() {
        guard !checking else { return }
        checking = true
        let services = selectedServices
        let port: Int? = isOn ? settings.port : nil
        DispatchQueue.global().async { [weak self] in
            let r = Checker.probeAll(services, viaPort: port)
            DispatchQueue.main.async {
                self?.checks = r
                self?.checking = false
            }
        }
    }

    func autoPick() {
        guard pickProgress == nil else { return }
        let services = selectedServices.isEmpty ? [Catalog.services[0]] : selectedServices
        let testPort = settings.port + 1
        pickProgress = "Готовлюсь…"
        lastPick = nil
        DispatchQueue.global().async { [weak self] in
            let scores = Checker.pickBest(for: services, testPort: testPort) { st, i, n in
                DispatchQueue.main.async { self?.pickProgress = "Пробую «\(st.name)» (\(i) из \(n))" }
            }
            DispatchQueue.main.async {
                guard let self else { return }
                self.pickProgress = nil
                guard let best = scores.first, best.passed > 0 else {
                    self.lastPick = "Ни один способ не помог. Возможно, сайт заблокирован по IP — тут нужен VPN."
                    return
                }
                self.lastPick = "Лучший способ: «\(best.strategy.name)» — открылось \(best.passed) из \(services.count)."
                self.settings.customArgs = ""
                self.settings.strategyID = best.strategy.id
                if !self.isOn { self.start() }
            }
        }
    }

    // MARK: - Автозапуск

    private func setLaunchAtLogin(_ on: Bool) {
        do {
            if on { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() }
        } catch {
            NSLog("ZapretBar: автозапуск: \(error)")
        }
    }

    // MARK: - Подмена ClientHello

    /// Нужна ли подмена для текущих настроек и есть ли она.
    var fakeNeeded: Bool { settings.customArgs.isEmpty && settings.strategy.fake }

    func grantFake() {
        fakeMessage = "Жду пароль администратора…"
        worker.async { [weak self] in
            let result = Result { try FakeAccess.install() }
            DispatchQueue.main.async {
                guard let self else { return }
                self.fakeGranted = FakeAccess.granted
                switch result {
                case .success:
                    self.fakeMessage = nil
                    self.scheduleApply(portChanged: false)
                case .failure(let e):
                    self.fakeMessage = e.localizedDescription
                }
            }
        }
    }

    func revokeFake() {
        worker.async { [weak self] in
            let result = Result { try FakeAccess.uninstall() }
            DispatchQueue.main.async {
                guard let self else { return }
                self.fakeGranted = FakeAccess.granted
                if case .failure(let e) = result { self.fakeMessage = e.localizedDescription }
                self.scheduleApply(portChanged: false)
            }
        }
    }

    /// Подмена идёт через конкретный интерфейс и MAC роутера: при смене сети
    /// (другой Wi-Fi, кабель, включили/выключили VPN) tpws надо перезапустить.
    private func watchNetwork() {
        pathMonitor.pathUpdateHandler = { [weak self] _ in
            DispatchQueue.main.async { self?.networkChanged() }
        }
        pathMonitor.start(queue: DispatchQueue(label: "zapretbar.path"))
    }

    private func networkChanged() {
        guard fakeNeeded, fakeGranted else { return }
        worker.async { [weak self] in
            let link = FakeAccess.currentLink()
            DispatchQueue.main.async {
                guard let self, link != self.lastLink else { return }
                self.lastLink = link
                if self.isOn { self.scheduleApply(portChanged: false) }
            }
        }
    }

    func openSupportFolder() { NSWorkspace.shared.open(Paths.support) }
    func openLog() { NSWorkspace.shared.open(Paths.log) }
}
