import SwiftUI

struct ContentView: View {
    @EnvironmentObject var proxyManager: ProxyManager

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

                if proxyManager.isRunning {
                    Text(verbatim: "Configure Wi-Fi proxy to\n127.0.0.1:\(AppSettings.shared.proxyPort)")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
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
