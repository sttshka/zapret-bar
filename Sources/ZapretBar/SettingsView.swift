import SwiftUI

struct SettingsView: View {
    var body: some View {
        TabView {
            SitesTab().tabItem { Label("Сайты", systemImage: "globe") }
            StrategyTab().tabItem { Label("Способ обхода", systemImage: "slider.horizontal.3") }
            DiagnosticsTab().tabItem { Label("Диагностика", systemImage: "stethoscope") }
            GeneralTab().tabItem { Label("Общее", systemImage: "gearshape") }
        }
        .padding(20)
        .frame(width: 640, height: 560)
    }
}

/// Многострочный редактор списка доменов, который сохраняется по кнопке, а не на каждую букву.
private struct DomainListEditor: View {
    let title: String
    let hint: String
    @Binding var domains: [String]
    @State private var text = ""
    @State private var loaded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title).font(.headline)
            Hint(hint)
            TextEditor(text: $text)
                .font(.system(.body, design: .monospaced))
                .frame(minHeight: 90)
                .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color.secondary.opacity(0.3)))
            HStack {
                let parsed = parse(text)
                Text("Распознано сайтов: \(parsed.count)").font(.caption).foregroundStyle(.secondary)
                Spacer()
                Button("Сохранить") { domains = parsed; text = parsed.joined(separator: "\n") }
                    .disabled(parsed == domains)
                    .keyboardShortcut("s", modifiers: .command)
            }
        }
        .onAppear {
            guard !loaded else { return }
            loaded = true
            text = domains.joined(separator: "\n")
        }
    }

    private func parse(_ t: String) -> [String] {
        var seen = Set<String>()
        return t.split(whereSeparator: { $0.isNewline || $0 == "," || $0 == " " })
            .compactMap { AppSettings.normalize(String($0)) }
            .filter { seen.insert($0).inserted }
    }
}

private struct SitesTab: View {
    @EnvironmentObject var state: AppState
    @State private var autoList: [String] = []

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                DomainListEditor(
                    title: "Свои сайты",
                    hint: "Вставьте адреса — по одному в строке, можно прямо ссылками. Поддомены включаются сами.",
                    domains: $state.settings.customDomains)

                DomainListEditor(
                    title: "Исключения (для режима «Все сайты»)",
                    hint: "Сайты, которые работают хуже с обходом — например, банки или госуслуги.",
                    domains: $state.settings.excludedDomains)

                VStack(alignment: .leading, spacing: 6) {
                    Toggle("Находить заблокированные сайты автоматически", isOn: $state.settings.autoHostlist)
                        .font(.headline)
                    Hint("Если сайт несколько раз подряд не открывается, приложение само добавит его в список для обхода.")
                    if !autoList.isEmpty {
                        Text(autoList.joined(separator: ", ")).font(.caption.monospaced())
                            .textSelection(.enabled)
                        Button("Очистить найденные") {
                            try? "".write(to: Paths.autoHostlist, atomically: true, encoding: .utf8)
                            autoList = []
                        }
                    }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(4)
        }
        .onAppear {
            autoList = ((try? String(contentsOf: Paths.autoHostlist, encoding: .utf8)) ?? "")
                .split(separator: "\n").map(String.init).filter { !$0.isEmpty }
        }
    }
}

private struct StrategyTab: View {
    @EnvironmentObject var state: AppState
    @State private var custom = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Hint("Провайдеры фильтруют по-разному. Если видео всё равно тормозит — попробуйте другой способ или нажмите «Подобрать» в меню.")
            ForEach(Catalog.strategies) { st in
                let selected = state.settings.customArgs.isEmpty && state.settings.strategyID == st.id
                Button {
                    state.settings.customArgs = ""
                    state.settings.strategyID = st.id
                } label: {
                    HStack(alignment: .top, spacing: 10) {
                        Image(systemName: selected ? "largecircle.fill.circle" : "circle")
                            .foregroundStyle(selected ? Color.accentColor : .secondary)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(st.name).font(.body.weight(.medium))
                            Text(st.summary).font(.caption).foregroundStyle(.secondary)
                            Text(st.args.joined(separator: " ")).font(.caption2.monospaced()).foregroundStyle(.tertiary)
                        }
                        Spacer()
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
            }

            Divider()
            Text("Для опытных: свои параметры tpws").font(.headline)
            HStack {
                TextField("например: --split-pos=2 --oob", text: $custom)
                    .font(.system(.body, design: .monospaced))
                Button("Применить") { state.settings.customArgs = custom.trimmingCharacters(in: .whitespaces) }
                    .disabled(custom.trimmingCharacters(in: .whitespaces) == state.settings.customArgs)
            }
            Hint("Пустое поле — используется выбранный выше способ. Параметры прокси и списков сайтов добавляются сами.")
            Spacer()
        }
        .onAppear { custom = state.settings.customArgs }
    }
}

private struct GeneralTab: View {
    @EnvironmentObject var state: AppState
    @State private var port = ""

    var body: some View {
        Form {
            Toggle("Открывать ZapretBar при входе в систему", isOn: $state.launchAtLogin)
            Toggle("Восстанавливать включённый обход после запуска", isOn: $state.settings.startOnLaunch)
            Toggle("Подробный журнал (для диагностики)", isOn: $state.settings.verboseLog)
            HStack {
                TextField("Порт прокси", text: $port).frame(width: 220)
                Button("Сменить") { if let p = Int(port), (1025...65534).contains(p) { state.settings.port = p } }
                    .disabled(Int(port) == state.settings.port)
            }
            Section("Подмена приветствия") {
                HStack {
                    Image(systemName: state.fakeGranted ? "checkmark.seal.fill" : "xmark.seal")
                        .foregroundStyle(state.fakeGranted ? .green : .secondary)
                    Text(state.fakeGranted ? "Доступ к сетевому интерфейсу есть" : "Доступа нет")
                    Spacer()
                    if state.fakeGranted {
                        Button("Отозвать") { state.revokeFake() }
                    } else {
                        Button("Разрешить") { state.grantFake() }
                    }
                }
                Hint("tpws отправляет поддельный ClientHello через /dev/bpf, как zapret на Windows через WinDivert. Разрешение ставит системную службу, которая при загрузке отдаёт /dev/bpf вашему пользователю (так же делает Wireshark). Подмена не работает при включённом VPN — тогда она и не нужна.")
                if let m = state.fakeMessage { Hint(m) }
            }
            Section {
                Hint("ZapretBar запускает tpws из проекта zapret как локальный SOCKS-прокси (127.0.0.1:\(state.settings.port)) и прописывает его в системные настройки сети. Safari, Chrome, Telegram, Discord и большинство программ подхватят его сами. Firefox — включите в нём «Использовать системные настройки прокси». Голосовые звонки по UDP через SOCKS не идут.")
                HStack {
                    Button("Открыть папку с данными") { state.openSupportFolder() }
                    Button("Журнал tpws") { state.openLog() }
                }
            }
        }
        .formStyle(.grouped)
        .onAppear { port = String(state.settings.port) }
    }
}

private struct DiagnosticsTab: View {
    @StateObject private var diag = Diagnostics()
    @State private var vpn = false

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Hint("Проверяет, что именно режет ваш провайдер и какой способ обхода помогает: YouTube, Discord (включая чат-шлюз), заблокированные сайты, DNS, скорость видео и настоящий Chrome. Настройки сети не меняются — всё на тестовых портах. Отчёт сохраняется в файл.")
            if vpn {
                Label("Похоже, включён VPN. Выключите его на время проверки — иначе результат ничего не покажет.", systemImage: "exclamationmark.triangle.fill")
                    .font(.callout).foregroundStyle(.orange)
            }
            HStack {
                Group {
                    Button { diag.run(quick: true) } label: { Label("Быстрая (~1 мин)", systemImage: "hare") }
                    Button { diag.run(quick: false) } label: { Label("Полная (~7 мин)", systemImage: "tortoise") }
                        .keyboardShortcut(.defaultAction)
                }
                .disabled(diag.running)
                Spacer()
                if diag.running {
                    ProgressView().controlSize(.small)
                    Button("Остановить") { diag.stop() }
                }
            }

            ScrollViewReader { proxy in
                ScrollView {
                    Text(diag.output.isEmpty ? "Здесь появится ход проверки." : diag.output)
                        .font(.system(size: 10.5, design: .monospaced))
                        .foregroundStyle(diag.output.isEmpty ? .secondary : .primary)
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(8)
                    Color.clear.frame(height: 1).id("end")
                }
                .background(RoundedRectangle(cornerRadius: 6).fill(Color(nsColor: .textBackgroundColor)))
                .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color.secondary.opacity(0.3)))
                .onChange(of: diag.output) { _ in proxy.scrollTo("end", anchor: .bottom) }
            }

            HStack {
                Button("Скопировать вывод") { diag.copyReport() }.disabled(diag.output.isEmpty)
                Spacer()
                Button("Открыть отчёт") { diag.openReport() }.disabled(diag.report == nil)
                Button("Показать в Finder") { diag.revealReport() }
            }
        }
        .onAppear { vpn = Diagnostics.vpnLikelyOn }
        .onChange(of: diag.running) { _ in vpn = Diagnostics.vpnLikelyOn }
    }
}
