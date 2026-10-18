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

    /// The listener's settings, while a server exists. Port and LAN access need a restart.
    @Published private(set) var listening: (port: UInt16, allowLANAccess: Bool)?

    /// What the scanner shows (network-scanner plan §6.1). Outlives servers, so stop/start keeps it.
    let connectionLog = ConnectionLog()

    /// Counts for the main-screen line (§7.1 b). Refreshed every 2 s while running; kept after stop.
    @Published private(set) var logSummary: LogSummary?
    private var summaryTimer: Timer?
    private let summaryQueue = DispatchQueue(label: "com.rnglol.Spoofy.summary", qos: .utility)

    private let settings: SettingsStore
    private var proxyServer: ProxyServer?
    private let audioPlayer = BackgroundAudioPlayer()

    var isRunning: Bool { status == .running }

    /// True while running with a port or LAN setting that differs from the listener's.
    var needsRestart: Bool {
        guard let listening else { return false }
        return listening.port != settings.proxyPort || listening.allowLANAccess != settings.allowLANAccess
    }

    init(settings: SettingsStore) {
        self.settings = settings
        // Routing changes reach the running server, including its open connections (U13).
        settings.onChange = { [weak self] in
            guard let self, let server = self.proxyServer else { return }
            server.update(settings.snapshot)
        }
    }

    func start() {
        guard status == .stopped || status == .error else { return }
        errorMessage = nil
        status = .starting

        let config = settings.snapshot
        let port = config.port

        audioPlayer.start()

        let server = ProxyServer(config: config, observer: connectionLog)
        self.proxyServer = server
        listening = (config.port, config.allowLANAccess)

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
                    self.startSummaryTimer()
                }
            }
        }
    }

    private func fail(with error: Error) {
        stopSummaryTimer()
        proxyServer?.stop()
        proxyServer = nil
        listening = nil
        audioPlayer.stop()
        status = .error
        errorMessage = error.localizedDescription
    }

    func stop() {
        stopSummaryTimer()
        proxyServer?.stop()
        proxyServer = nil
        listening = nil
        audioPlayer.stop()
        status = .stopped
        errorMessage = nil
        Self.logger.info("Proxy stopped")
    }

    // MARK: - Log summary

    private func startSummaryTimer() {
        stopSummaryTimer()
        refreshSummary()
        summaryTimer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in
            Task { @MainActor [weak self] in self?.refreshSummary() }
        }
    }

    private func stopSummaryTimer() {
        summaryTimer?.invalidate()
        summaryTimer = nil
    }

    private func refreshSummary() {
        let log = connectionLog.snapshot()
        let config = settings.snapshot
        let hidden = settings.hiddenHosts
        let now = Date()
        summaryQueue.async { [weak self] in
            let summary = ScannerSnapshot.build(log: log, config: config, hiddenHosts: hidden, now: now).summary
            Task { @MainActor [weak self] in
                guard let self, self.isRunning, self.logSummary != summary else { return }
                self.logSummary = summary
            }
        }
    }
}
