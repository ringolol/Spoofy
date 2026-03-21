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

        server.start { [weak self] error in
            Task { @MainActor [weak self] in
                guard let self = self else { return }
                if let error = error {
                    Self.logger.error("Proxy failed to start: \(error.localizedDescription)")
                    self.status = .error
                    self.errorMessage = error.localizedDescription
                    self.proxyServer = nil
                } else {
                    Self.logger.info("Proxy started on port \(port)")
                    self.status = .running
                }
            }
        }
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
