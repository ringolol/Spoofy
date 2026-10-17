import SwiftUI

@main
struct SpoofyApp: App {
    @StateObject private var settings: SettingsStore
    @StateObject private var proxyManager: ProxyManager

    init() {
        let settings = SettingsStore()
        _settings = StateObject(wrappedValue: settings)
        _proxyManager = StateObject(wrappedValue: ProxyManager(settings: settings))
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(proxyManager)
                .environmentObject(settings)
                #if targetEnvironment(macCatalyst)
                .onAppear(perform: configureCatalystWindow)
                #endif
        }
    }

    #if targetEnvironment(macCatalyst)
    /// Catalyst opens a wide landscape window by default; keep it phone-shaped instead.
    private func configureCatalystWindow() {
        let preferred = CGSize(width: 420, height: 780)
        for scene in UIApplication.shared.connectedScenes {
            guard let restrictions = (scene as? UIWindowScene)?.sizeRestrictions else { continue }
            // Pin min == max to force the initial size, then relax to allow a narrow resize range.
            restrictions.minimumSize = preferred
            restrictions.maximumSize = preferred
            DispatchQueue.main.async {
                restrictions.minimumSize = CGSize(width: 360, height: 640)
                restrictions.maximumSize = CGSize(width: 560, height: 1200)
            }
        }
    }
    #endif
}
