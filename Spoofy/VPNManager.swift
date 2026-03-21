import Foundation
import NetworkExtension
import Combine

@MainActor
final class VPNManager: ObservableObject {
    @Published var status: NEVPNStatus = .disconnected
    @Published var isLoading = false
    @Published var errorMessage: String?

    private var manager: NETunnelProviderManager?
    private var statusObserver: NSObjectProtocol?

    init() {
        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: nil,
            queue: .main
        ) { [weak self] notification in
            guard let self = self,
                  let connection = notification.object as? NEVPNConnection else { return }
            Task { @MainActor in
                self.status = connection.status
            }
        }
    }

    deinit {
        if let observer = statusObserver {
            NotificationCenter.default.removeObserver(observer)
        }
    }

    func loadOrCreate() async {
        isLoading = true
        errorMessage = nil
        defer { isLoading = false }

        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            if let existing = managers.first {
                manager = existing
            } else {
                let newManager = NETunnelProviderManager()
                let proto = NETunnelProviderProtocol()
                proto.providerBundleIdentifier = "com.rnglol.Spoofy.PacketTunnel"
                proto.serverAddress = "127.0.0.1"
                proto.providerConfiguration = currentConfiguration()
                newManager.protocolConfiguration = proto
                newManager.localizedDescription = "Spoofy"
                newManager.isEnabled = true

                try await newManager.saveToPreferences()
                try await newManager.loadFromPreferences()
                manager = newManager
            }

            status = manager?.connection.status ?? .disconnected
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func start() async {
        errorMessage = nil

        if manager == nil {
            await loadOrCreate()
            guard manager != nil else { return }
        }

        guard let manager = manager else { return }

        do {
            // Update configuration before starting
            if let proto = manager.protocolConfiguration as? NETunnelProviderProtocol {
                proto.providerConfiguration = currentConfiguration()
            }
            manager.isEnabled = true
            try await manager.saveToPreferences()
            // Reload to pick up any system changes (e.g. user approved VPN profile)
            try await manager.loadFromPreferences()

            try manager.connection.startVPNTunnel()
        } catch let error as NEVPNError where error.code == .configurationReadWriteFailed {
            // Configuration was stale after user approved VPN prompt — retry once
            do {
                try await manager.loadFromPreferences()
                try manager.connection.startVPNTunnel()
            } catch {
                errorMessage = error.localizedDescription
            }
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    func stop() {
        manager?.connection.stopVPNTunnel()
    }

    var isConnected: Bool {
        status == .connected
    }

    var statusText: String {
        switch status {
        case .connected: return "Connected"
        case .connecting: return "Connecting..."
        case .disconnecting: return "Disconnecting..."
        case .disconnected: return "Disconnected"
        case .invalid: return "Invalid"
        case .reasserting: return "Reasserting..."
        @unknown default: return "Unknown"
        }
    }

    private func currentConfiguration() -> [String: Any] {
        let settings = AppSettings.shared
        var config: [String: Any] = [
            "proxyPort": Int(settings.proxyPort),
        ]
        if let data = try? JSONEncoder().encode(settings.profiles) {
            config["profilesData"] = data
        }
        return config
    }
}
