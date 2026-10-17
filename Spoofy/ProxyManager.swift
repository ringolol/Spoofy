import Foundation
import Network
import os.log

@MainActor
final class ProxyManager: ObservableObject {
    private static let logger = Logger(subsystem: "com.rnglol.Spoofy", category: "ProxyManager")

    enum Status: String {
        case stopped = "Stopped"
        case starting = "Starting..."
        case running = "Running"
        case error = "Error"
    }

    @Published var status: Status = .stopped
    @Published var errorMessage: String?

    private var proxyServer: ProxyServer?
    private let audioPlayer = BackgroundAudioPlayer()

    var isRunning: Bool { status == .running }

    func start() {
        guard status == .stopped || status == .error else { return }
        errorMessage = nil
        status = .starting

        let settings = AppSettings.shared
        let port = settings.proxyPort

        audioPlayer.start()

        let server = ProxyServer(port: port, settings: settings)
        self.proxyServer = server

        server.onFailure = { [weak self, weak server] error in
            Task { @MainActor [weak self] in
                guard let self = self, let server = server, self.proxyServer === server else { return }
                Self.logger.error("Proxy listener failed: \(error.localizedDescription)")
                self.fail(with: error)
            }
        }

        server.start { [weak self, weak server] error in
            Task { @MainActor [weak self] in
                // Ignore a late result from a server that was stopped while starting.
                guard let self = self, let server = server, self.proxyServer === server else { return }
                if let error = error {
                    Self.logger.error("Proxy failed to start: \(error.localizedDescription)")
                    self.fail(with: error)
                } else {
                    Self.logger.info("Proxy started on port \(port)")
                    self.status = .running
                }
            }
        }
    }

    private func fail(with error: Error) {
        proxyServer?.stop()
        proxyServer = nil
        audioPlayer.stop()
        status = .error
        errorMessage = error.localizedDescription
    }

    func stop() {
        proxyServer?.stop()
        proxyServer = nil
        audioPlayer.stop()
        status = .stopped
        errorMessage = nil
        Self.logger.info("Proxy stopped")
    }
}
