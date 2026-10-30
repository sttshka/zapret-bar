import SwiftUI

struct MenuView: View {
    @EnvironmentObject var state: AppState
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            PowerCard()
            if state.fakeNeeded && !state.fakeGranted { FakeAccessCard() }

            VStack(alignment: .leading, spacing: 6) {
                SectionTitle("Что разблокировать")
                VStack(spacing: 2) {
                    ForEach(Catalog.services) { ServiceRow(service: $0) }
                }
                Picker("", selection: $state.settings.coverage) {
                    ForEach(Coverage.allCases) { Text($0.title).tag($0) }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .padding(.top, 4)
                if state.settings.coverage == .everything {
                    Hint("Обход применяется ко всем сайтам. Если какой-то сайт сломается — добавьте его в исключения в настройках.")
                } else if !state.settings.customDomains.isEmpty {
                    Hint("И ещё своих сайтов: \(state.settings.customDomains.count)")
                }
            }

            VStack(alignment: .leading, spacing: 6) {
                SectionTitle("Способ обхода")
                StrategyMenu()
                HStack(spacing: 8) {
                    Button { state.check() } label: {
                        Label(state.checking ? "Проверяю…" : "Проверить", systemImage: "checkmark.seal")
                            .frame(maxWidth: .infinity)
                    }
                    .disabled(state.checking || state.selectedServices.isEmpty)
                    Button { state.autoPick() } label: {
                        Label("Подобрать", systemImage: "wand.and.stars").frame(maxWidth: .infinity)
                    }
                    .disabled(state.busy)
                    .help("Перепробует все способы и выберет тот, что открывает ваши сервисы")
                }
                .controlSize(.large)
                if let p = state.pickProgress {
                    HStack(spacing: 6) { ProgressView().controlSize(.small); Hint(p) }
                } else if let r = state.lastPick {
                    Hint(r)
                }
            }

            Divider()
            HStack {
                Button("Настройки…") {
                    NSApp.activate(ignoringOtherApps: true)
                    openWindow(id: "settings")
                }
                Spacer()
                Button("Выйти") { NSApp.terminate(nil) }
            }
            .buttonStyle(.borderless)
        }
        .padding(16)
        .frame(width: 340)
    }
}

private struct PowerCard: View {
    @EnvironmentObject var state: AppState

    var body: some View {
        HStack(spacing: 14) {
            ZStack {
                Circle().fill(color.gradient).frame(width: 44, height: 44)
                Image(systemName: state.isOn ? "bolt.fill" : "bolt.slash.fill")
                    .font(.system(size: 20, weight: .semibold)).foregroundStyle(.white)
            }
            VStack(alignment: .leading, spacing: 2) {
                Text(state.status.title).font(.headline)
                Text(subtitle).font(.caption).foregroundStyle(.secondary).lineLimit(3)
            }
            Spacer(minLength: 0)
            if state.status == .starting || state.status == .stopping {
                ProgressView().controlSize(.small)
            } else {
                Toggle("", isOn: Binding(get: { state.isOn }, set: { _ in state.toggle() }))
                    .toggleStyle(.switch).labelsHidden().controlSize(.large)
                    .disabled(state.pickProgress != nil)
            }
        }
        .padding(12)
        .background(RoundedRectangle(cornerRadius: 14).fill(color.opacity(0.12)))
        .animation(.easeInOut(duration: 0.2), value: state.status)
    }

    private var color: Color {
        switch state.status {
        case .on: return .green
        case .failed: return .red
        case .starting, .stopping: return .orange
        case .off: return .gray
        }
    }

    private var subtitle: String {
        if case .failed(let msg) = state.status { return msg }
        if state.settings.customArgs.isEmpty == false && state.isOn { return "Свои параметры tpws" }
        let names = state.selectedServices.map(\.name)
        let what = state.settings.coverage == .everything ? "Все сайты"
            : names.isEmpty && state.settings.customDomains.isEmpty ? "Ничего не выбрано"
            : names.isEmpty ? "Свои сайты" : names.joined(separator: ", ")
        return state.isOn ? "\(what) · \(state.settings.strategy.name.lowercased()) способ" : "Нажмите, чтобы ускорить \(what.lowercased())"
    }
}

/// Подмена ClientHello требует разового доступа к /dev/bpf — объясняем по-человечески.
private struct FakeAccessCard: View {
    @EnvironmentObject var state: AppState

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Нужно одно разрешение", systemImage: "key.fill").font(.subheadline.weight(.semibold))
            Hint("Чтобы открывались Discord, X и сайты на Cloudflare, ZapretBar показывает фильтру поддельное приветствие — как zapret на Windows. Для этого macOS один раз спросит пароль администратора. Пока разрешения нет, работает обычный способ (YouTube откроется, Discord — нет).")
            HStack {
                Button("Разрешить") { state.grantFake() }
                    .buttonStyle(.borderedProminent)
                if let m = state.fakeMessage { Hint(m) }
            }
        }
        .padding(12)
        .background(RoundedRectangle(cornerRadius: 12).fill(Color.orange.opacity(0.12)))
    }
}

private struct ServiceRow: View {
    @EnvironmentObject var state: AppState
    let service: Service

    var body: some View {
        let enabled = state.settings.enabledServices.contains(service.id)
        HStack(spacing: 10) {
            Image(systemName: service.symbol)
                .font(.system(size: 13, weight: .semibold))
                .foregroundStyle(enabled ? Color.white : Color.secondary)
                .frame(width: 26, height: 26)
                .background(RoundedRectangle(cornerRadius: 7).fill(enabled ? Color.accentColor : Color.secondary.opacity(0.15)))
            VStack(alignment: .leading, spacing: 0) {
                Text(service.name).font(.system(size: 13, weight: .medium))
                Text(checkText ?? service.note).font(.caption2)
                    .foregroundStyle(checkColor ?? .secondary).lineLimit(1)
            }
            Spacer()
            Toggle("", isOn: Binding(
                get: { enabled },
                set: { on in
                    if on { state.settings.enabledServices.insert(service.id) }
                    else { state.settings.enabledServices.remove(service.id) }
                }))
            .toggleStyle(.switch).labelsHidden().controlSize(.mini)
        }
        .padding(.vertical, 3).padding(.horizontal, 4)
        .contentShape(Rectangle())
    }

    private var check: ProbeResult? { state.checks[service.id] }
    private var checkText: String? {
        guard let c = check else { return nil }
        return c.ok ? "Открывается · \(String(format: "%.1f", c.seconds)) с" : "Не открывается: \(c.detail)"
    }
    private var checkColor: Color? {
        guard let c = check else { return nil }
        return c.ok ? .green : .red
    }
}

private struct StrategyMenu: View {
    @EnvironmentObject var state: AppState

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Picker("", selection: Binding(
                get: { state.settings.customArgs.isEmpty ? state.settings.strategyID : "custom" },
                set: { id in
                    guard id != "custom" else { return }
                    state.settings.customArgs = ""
                    state.settings.strategyID = id
                })) {
                ForEach(Catalog.strategies) { Text($0.name).tag($0.id) }
                if !state.settings.customArgs.isEmpty { Text("Свои параметры").tag("custom") }
            }
            .labelsHidden()
            Hint(state.settings.customArgs.isEmpty ? state.settings.strategy.summary : state.settings.customArgs)
        }
    }
}

struct SectionTitle: View {
    let text: String
    init(_ text: String) { self.text = text }
    var body: some View {
        Text(text.uppercased()).font(.system(size: 10, weight: .semibold)).foregroundStyle(.secondary)
    }
}

struct Hint: View {
    let text: String
    init(_ text: String) { self.text = text }
    var body: some View {
        Text(text).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
    }
}
