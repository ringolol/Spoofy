import SwiftUI

struct ContentView: View {
    @EnvironmentObject var proxyManager: ProxyManager
    @EnvironmentObject var settings: SettingsStore

    var body: some View {
        NavigationStack {
            VStack(spacing: 32) {
                Spacer()

                // Status indicator
                Circle()
                    .fill(statusColor)
                    .frame(width: 120, height: 120)
                    .overlay {
                        Image(systemName: statusIcon)
                            .font(.system(size: 48))
                            .foregroundStyle(.white)
                    }
                    .shadow(color: statusColor.opacity(0.5), radius: 20)

                Text(proxyManager.status.rawValue)
                    .font(.title2)
                    .fontWeight(.medium)

                if proxyManager.isRunning, let listening = proxyManager.listening {
                    Text(verbatim: "Configure Wi-Fi proxy to\n127.0.0.1:\(listening.port)")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)

                    if proxyManager.needsRestart {
                        Text("Restart the proxy to apply the new port or LAN setting.")
                            .font(.caption)
                            .foregroundStyle(.orange)
                            .multilineTextAlignment(.center)
                            .padding(.horizontal)
                    }

                    if let summary = proxyManager.logSummary, summary.hostCount > 0 {
                        LogSummaryLink(summary: summary)
                    }
                }

                // Start/Stop button
                Button {
                    if proxyManager.isRunning {
                        proxyManager.stop()
                    } else {
                        proxyManager.start()
                    }
                } label: {
                    Text(proxyManager.isRunning ? "Stop" : "Start")
                        .font(.headline)
                        .frame(maxWidth: .infinity)
                        .padding()
                        .background(proxyManager.isRunning ? Color.red : Color.accentColor)
                        .foregroundStyle(.white)
                        .clipShape(RoundedRectangle(cornerRadius: 16))
                }
                .disabled(proxyManager.status == .starting)
                .padding(.horizontal, 40)

                if let error = proxyManager.errorMessage {
                    Text(error)
                        .font(.caption)
                        .foregroundStyle(.red)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal)
                }

                Spacer()
            }
            .navigationTitle("Spoofy")
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    NavigationLink {
                        ScannerView(initialFilter: .all)
                    } label: {
                        Image(systemName: "list.bullet.rectangle")
                    }
                    .accessibilityLabel("Network scanner")
                }
                ToolbarItem(placement: .topBarTrailing) {
                    NavigationLink(destination: SettingsView()) {
                        Image(systemName: "gear")
                    }
                }
            }
        }
    }

    private var statusColor: Color {
        switch proxyManager.status {
        case .running: return .green
        case .starting: return .orange
        case .stopped, .error: return .gray
        }
    }

    private var statusIcon: String {
        switch proxyManager.status {
        case .running: return "shield.checkered"
        case .starting: return "ellipsis"
        case .stopped, .error: return "shield.slash"
        }
    }
}

/// `42 hosts · 3 blocked ›`, or the network banner when that takes priority (network-scanner
/// plan §7.1 b).
private struct LogSummaryLink: View {
    let summary: LogSummary

    var body: some View {
        NavigationLink {
            ScannerView(initialFilter: summary.blockedCount > 0 ? .problems : .all)
        } label: {
            HStack(spacing: 4) {
                if let banner = ScannerText.shortBanner(for: summary.network) {
                    Text("\(Image(systemName: "exclamationmark.triangle.fill")) \(banner)")
                        .foregroundStyle(.orange)
                } else {
                    Text(summary.hostCount == 1 ? "1 host" : "\(summary.hostCount) hosts")
                    if summary.blockedCount > 0 {
                        Text("· \(summary.blockedCount) blocked")
                            .foregroundStyle(.red)
                    }
                }
                Image(systemName: "chevron.right")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
            }
            .font(.callout)
            .foregroundStyle(.primary)
            .padding(.horizontal, 14)
            .padding(.vertical, 6)
            .background(Color.secondary.opacity(0.12), in: Capsule())
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(accessibilityText)
        .accessibilityAddTraits(.isButton)
    }

    private var accessibilityText: String {
        if let banner = ScannerText.shortBanner(for: summary.network) {
            return "\(banner). Open network scanner."
        }
        return "\(summary.hostCount) hosts seen, \(summary.blockedCount) blocked. Open network scanner."
    }
}
