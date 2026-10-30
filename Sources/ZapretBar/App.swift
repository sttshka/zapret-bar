import SwiftUI

@main
struct ZapretBarApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @StateObject private var state = AppState.shared

    var body: some Scene {
        MenuBarExtra {
            MenuView()
                .environmentObject(state)
        } label: {
            Image(systemName: state.menuBarSymbol)
        }
        .menuBarExtraStyle(.window)

        Window("Настройки ZapretBar", id: "settings") {
            SettingsView()
                .environmentObject(state)
        }
        .windowResizability(.contentSize)
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationWillTerminate(_ notification: Notification) {
        MainActor.assumeIsolated { AppState.shared.shutdownSync() }
    }
}

extension AppState {
    static let shared = AppState()

    var menuBarSymbol: String {
        switch status {
        case .on: return "bolt.shield.fill"
        case .starting, .stopping: return "shield.lefthalf.filled"
        case .failed: return "exclamationmark.shield"
        case .off: return "shield.slash"
        }
    }
}
