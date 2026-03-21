import SwiftUI

@main
struct SpoofyApp: App {
    @StateObject private var proxyManager = ProxyManager()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(proxyManager)
        }
    }
}
