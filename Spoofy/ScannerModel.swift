import Foundation

/// Feeds the scanner screens (network-scanner plan §7.2). Refreshes once a second while a scanner
/// screen is visible; the verdict pass runs on a private queue over copies taken on main.
@MainActor
final class ScannerModel: ObservableObject {
    @Published private(set) var snapshot: ScannerSnapshot?
    /// Set while the user is selecting rows, so they don't move under the finger.
    @Published var isPaused = false {
        didSet { if !isPaused && oldValue { refresh() } }
    }

    let log: ConnectionLog
    private let settings: SettingsStore
    private let queue = DispatchQueue(label: "com.rnglol.Spoofy.scanner", qos: .utility)
    private var timer: Timer?
    /// Screens showing this model: the list and its detail view overlap while pushing.
    private var viewers = 0
    /// Drops a build that finished after a newer one started.
    private var generation = 0

    init(log: ConnectionLog, settings: SettingsStore) {
        self.log = log
        self.settings = settings
    }

    var rows: [HostRow] { snapshot?.rows ?? [] }

    func row(for host: String) -> HostRow? {
        snapshot?.rows.first { $0.host == host }
    }

    func start() {
        viewers += 1
        guard viewers == 1 else { return }
        refresh()
        timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            Task { @MainActor [weak self] in
                guard let self, !self.isPaused else { return }
                self.refresh()
            }
        }
    }

    func stop() {
        viewers = max(0, viewers - 1)
        guard viewers == 0 else { return }
        timer?.invalidate()
        timer = nil
    }

    func refresh() {
        let logSnapshot = log.snapshot()
        let config = settings.snapshot
        let hidden = settings.hiddenHosts
        let now = Date()
        generation += 1
        let current = generation
        queue.async { [weak self] in
            let built = ScannerSnapshot.build(log: logSnapshot, config: config, hiddenHosts: hidden, now: now)
            Task { @MainActor [weak self] in
                guard let self, current == self.generation else { return }
                self.snapshot = built
            }
        }
    }

    func clear() {
        log.clear()
        refresh()
    }

    func hide(_ pattern: String) {
        let pattern = pattern.lowercased()
        guard !settings.hiddenHosts.contains(pattern) else { return }
        settings.setHiddenHosts(settings.hiddenHosts + [pattern])
        refresh()
    }
}
