import SwiftUI

/// One host: verdict, rule, addresses and recent connections (network-scanner plan §7.5).
struct HostDetailView: View {
    let host: String
    @ObservedObject var model: ScannerModel

    @EnvironmentObject private var settings: SettingsStore
    /// The row as it was when the sheet opened, so it doesn't change behind it.
    @State private var adding: HostRow?
    @State private var confirmation: String?

    var body: some View {
        List {
            if let row = model.row(for: host) {
                statusSection(row)
                ruleSection(row)
                addressSection(row)
                connectionsSection(row)
            } else {
                Text("This host is no longer in the log.")
                    .foregroundStyle(.secondary)
            }
        }
        .navigationTitle(host)
        .navigationBarTitleDisplayMode(.inline)
        .onAppear { model.start() }
        .onDisappear { model.stop() }
        .sheet(item: $adding) { row in
            AddPatternsSheet(rows: [row], master: settings.master) { text in
                confirmation = text
            } onClose: {
                adding = nil
                // See ScannerView: wakes the run loop so the sheet closes promptly on the Mac.
                DispatchQueue.main.async { CFRunLoopWakeUp(CFRunLoopGetMain()) }
            }
        }
        .confirmationToast($confirmation)
    }

    @ViewBuilder
    private func statusSection(_ row: HostRow) -> some View {
        Section("Status") {
            if let copy = ScannerText.copy(for: row.verdict) {
                VStack(alignment: .leading, spacing: 6) {
                    Text(copy.title)
                        .font(.headline)
                        .foregroundStyle(row.verdict.status.isProblem ? ScannerText.color(for: row.verdict.status) : .primary)
                    Text(copy.explanation)
                        .font(.callout)
                    if !copy.fix.isEmpty {
                        Text(copy.fix)
                            .font(.callout.weight(.medium))
                    }
                    if row.verdict.status.isProblem, let confidence = row.verdict.confidence {
                        Text(ScannerText.confidence(confidence))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                .padding(.vertical, 2)
            } else {
                Text("Not enough recent connections to judge.")
                    .foregroundStyle(.secondary)
            }
        }
    }

    private func ruleSection(_ row: HostRow) -> some View {
        Section("Rule") {
            NavigationLink {
                ProfileEditView(profileID: row.profileID)
            } label: {
                HStack {
                    Text(row.isDefaultProfile ? "No rule (Master)" : (row.profileName.isEmpty ? "Unnamed profile" : row.profileName))
                    Spacer()
                    ProfileBadge(name: row.profileName, isDefault: row.isDefaultProfile)
                }
            }
            Button {
                adding = row
            } label: {
                Label("Add to Profile…", systemImage: "plus.circle")
            }
        }
    }

    @ViewBuilder
    private func addressSection(_ row: HostRow) -> some View {
        Section("Addresses") {
            if !row.ips.isEmpty {
                LabeledContent("IP", value: row.ips.joined(separator: "\n"))
            }
            LabeledContent("Ports", value: portKinds(row))
            if !row.snis.isEmpty {
                LabeledContent("SNI", value: row.snis.joined(separator: "\n"))
            }
            if row.sni != nil {
                Text("The app connected to this IP itself, so domain rules don't match it. Set the app to resolve names through the proxy (SOCKS5h / remote DNS) to use domain rules.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private func connectionsSection(_ row: HostRow) -> some View {
        Section("Recent connections") {
            if row.recent.isEmpty {
                Text("\(row.openCount == 1 ? "1 connection is" : "\(row.openCount) connections are") still open. Results appear when one closes.")
                    .foregroundStyle(.secondary)
            }
            ForEach(Array(row.recent.reversed().enumerated()), id: \.offset) { _, trace in
                ConnectionRow(trace: trace)
            }
        }
    }

    /// `443/TLS, 5222/TCP` (§2.5.5).
    private func portKinds(_ row: HostRow) -> String {
        var pairs: [String] = []
        for trace in row.recent {
            let tag = trace.summary.kind.tag
            let pair = tag == .none ? "\(trace.summary.start.port)" : "\(trace.summary.start.port)/\(tag.rawValue)"
            if !pairs.contains(pair) { pairs.append(pair) }
        }
        let seen = Set(row.recent.map(\.summary.start.port))
        pairs += row.ports.filter { !seen.contains($0) }.map(String.init)
        return pairs.joined(separator: ", ")
    }
}

private struct ConnectionRow: View {
    let trace: ClassifiedTrace

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack {
                Text(ScannerText.outcome(trace.outcome.kind))
                    .font(.callout.weight(.medium))
                    .foregroundStyle(color)
                Spacer()
                Text(trace.summary.endedDate, style: .time)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Text(ScannerText.timeline(trace.summary))
                .font(.caption.monospaced())
                .foregroundStyle(.secondary)
            Text("\(ScannerText.route(trace.summary.start.outbound)) · \(trace.summary.start.profileName)")
                .font(.caption)
                .foregroundStyle(.secondary)
            if let note = ScannerText.strategyNote(trace.summary) {
                Text(note)
                    .font(.caption)
                    .foregroundStyle(.orange)
            }
        }
        .padding(.vertical, 2)
    }

    private var color: Color {
        switch trace.outcome.kind {
        case .ok: return .primary
        case .clientAborted, .interrupted, .inconclusive, .midStreamReset: return .secondary
        default: return BlockKind(trace.outcome.kind) == nil ? .secondary : .red
        }
    }
}
