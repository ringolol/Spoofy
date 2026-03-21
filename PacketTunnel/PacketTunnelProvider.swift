import NetworkExtension
import Network
import os.log

class PacketTunnelProvider: NEPacketTunnelProvider {
    private static let logger = Logger(subsystem: "com.rnglol.Spoofy.PacketTunnel", category: "Tunnel")

    private var proxyServer: ProxyServer?

    override func startTunnel(options: [String: NSObject]? = nil) async throws {
        let settings = AppSettings.shared

        // Override settings from provider configuration if present
        if let config = protocolConfiguration as? NETunnelProviderProtocol,
           let providerConfig = config.providerConfiguration {
            if let data = providerConfig["profilesData"] as? Data,
               let decoded = try? JSONDecoder().decode([SpoofProfile].self, from: data) {
                settings.profiles = decoded
            }
            if let port = providerConfig["proxyPort"] as? Int {
                settings.proxyPort = UInt16(port)
            }
        }

        let port = settings.proxyPort

        // Start proxy server
        let server = ProxyServer(port: port, settings: settings)
        self.proxyServer = server

        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            server.start { error in
                if let error = error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume()
                }
            }
        }

        // Configure tunnel network settings — proxy only, no IP routing
        let tunnelSettings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "198.18.0.1")

        let proxySettings = NEProxySettings()
        proxySettings.httpEnabled = true
        proxySettings.httpServer = NEProxyServer(address: "127.0.0.1", port: Int(port))
        proxySettings.httpsEnabled = true
        proxySettings.httpsServer = NEProxyServer(address: "127.0.0.1", port: Int(port))
        proxySettings.matchDomains = [""] // Match all domains
        proxySettings.excludeSimpleHostnames = true
        tunnelSettings.proxySettings = proxySettings

        // DNS settings: use default profile's DoH setting for tunnel-level DNS
        let defaultProfile = settings.profiles.last ?? SpoofProfile.makeDefault()
        if defaultProfile.dohEnabled {
            tunnelSettings.dnsSettings = NEDNSSettings(servers: ["198.18.0.1"])
        } else {
            tunnelSettings.dnsSettings = NEDNSSettings(servers: ["8.8.8.8", "1.1.1.1"])
        }

        try await setTunnelNetworkSettings(tunnelSettings)

        Self.logger.info("Tunnel started with proxy on port \(port)")
    }

    override func stopTunnel(with reason: NEProviderStopReason) async {
        proxyServer?.stop()
        proxyServer = nil
        Self.logger.info("Tunnel stopped, reason: \(String(describing: reason))")
    }

    override func handleAppMessage(_ messageData: Data) async -> Data? {
        return nil
    }
}
