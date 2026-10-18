import SwiftUI

enum ScannerFilter: String, CaseIterable, Identifiable {
    case all = "All"
    case problems = "Problems"
    case noRule = "No rule"

    var id: String { rawValue }
}

/// Hosts the proxy has carried and what their connections say about blocking (network-scanner
/// plan §7.3).
struct ScannerView: View {
    let initialFilter: ScannerFilter

    @EnvironmentObject private var proxyManager: ProxyManager
    @EnvironmentObject private var settings: SettingsStore

    var body: some View {
        ScannerScreen(model: ScannerModel(log: proxyManager.connectionLog, settings: settings), initialFilter: initialFilter)
    }
}

private struct ScannerScreen: View {
    @StateObject private var model: ScannerModel
    @EnvironmentObject private var settings: SettingsStore
    @State private var filter: ScannerFilter
    @State private var search = ""
    /// The initial Problems filter falls back to All once, when it would show nothing (§7.1 c).
    @State private var checkedInitialFilter = false
    @State private var editMode: EditMode = .inactive
    @State private var selection: Set<String> = []
    @State private var sheet: AddSheetRequest?
    @State private var confirmation: String?

    private struct AddSheetRequest: Identifiable {
        let id = UUID()
        let rows: [HostRow]
        let newProfile: Bool
    }

    init(model: @autoclosure @escaping () -> ScannerModel, initialFilter: ScannerFilter) {
        _model = StateObject(wrappedValue: model())
        _filter = State(initialValue: initialFilter)
    }

    var body: some View {
        // Selection only while editing: on the Mac a selected row stays highlighted after a click and
        // hides the profile badge.
        List(selection: editMode.isEditing ? $selection : nil) {
            if let snapshot = model.snapshot {
                content(snapshot)
            }
        }
        .environment(\.editMode, $editMode)
        .navigationTitle("Network Scanner")
        .navigationBarTitleDisplayMode(.inline)
        .searchable(text: $search, prompt: "Host, IP or SNI")
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                EditButton()
                    .environment(\.editMode, $editMode)
            }
            ToolbarItemGroup(placement: .bottomBar) {
                if editMode.isEditing {
                    Button("Add to Profile…") { addSelected(newProfile: false) }
                        .disabled(selection.isEmpty || settings.customProfiles.isEmpty)
                    Spacer()
                    Text("Paused")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Spacer()
                    Button("New Profile…") { addSelected(newProfile: true) }
                        .disabled(selection.isEmpty)
                }
            }
            ToolbarItem(placement: .topBarTrailing) {
                Menu {
                    Button(role: .destructive) {
                        model.clear()
                    } label: {
                        Label("Clear Log", systemImage: "trash")
                    }
                } label: {
                    Image(systemName: "ellipsis.circle")
                }
            }
        }
        .onAppear { model.start() }
        .onDisappear { model.stop() }
        // A list that reorders under the finger can't be selected from (§7.4).
        .onChange(of: editMode.isEditing) { editing in
            model.isPaused = editing
            if !editing { selection = [] }
        }
        .sheet(item: $sheet) { request in
            AddPatternsSheet(rows: request.rows, startWithNewProfile: request.newProfile,
                             customProfiles: settings.customProfiles, master: settings.master) { text in
                confirmation = text
                editMode = .inactive
                model.refresh()
            }
        }
        .overlay(alignment: .bottom) {
            if let confirmation {
                Text(confirmation)
                    .font(.callout)
                    .padding(.horizontal, 14)
                    .padding(.vertical, 8)
                    .background(.regularMaterial, in: Capsule())
                    .padding(.bottom, 16)
                    .transition(.opacity)
            }
        }
        .task(id: confirmation) {
            guard confirmation != nil else { return }
            try? await Task.sleep(nanoseconds: 3_000_000_000)
            withAnimation { confirmation = nil }
        }
        .onReceive(model.$snapshot) { snapshot in
            guard let snapshot, !checkedInitialFilter else { return }
            checkedInitialFilter = true
            if filter == .problems, !snapshot.rows.contains(where: { $0.verdict.status.isProblem }) {
                filter = .all
            }
        }
    }

    @ViewBuilder
    private func content(_ snapshot: ScannerSnapshot) -> some View {
        Section {
            Picker("Filter", selection: $filter) {
                ForEach(ScannerFilter.allCases) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.segmented)
            .listRowBackground(Color.clear)
            .listRowInsets(EdgeInsets())
        }

        if let banner = ScannerText.banner(for: snapshot.network) {
            Section {
                Label(banner, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
                    .font(.callout)
            }
        }

        let rows = visibleRows(snapshot.rows)
        Section {
            if snapshot.rows.isEmpty {
                Text("Start the proxy and use your apps. Hosts appear here.")
                    .foregroundStyle(.secondary)
            } else if rows.isEmpty {
                Text("No hosts match.")
                    .foregroundStyle(.secondary)
            }
            ForEach(rows) { row in
                NavigationLink {
                    HostDetailView(host: row.host, model: model)
                } label: {
                    HostRowView(row: row)
                }
                .contextMenu {
                    Button {
                        sheet = AddSheetRequest(rows: [row], newProfile: settings.customProfiles.isEmpty)
                    } label: {
                        Label("Add to Profile…", systemImage: "plus.circle")
                    }
                    Button {
                        UIPasteboard.general.string = row.host
                    } label: {
                        Label("Copy Host", systemImage: "doc.on.doc")
                    }
                    Button {
                        model.hide(row.host)
                    } label: {
                        Label("Hide", systemImage: "eye.slash")
                    }
                    if let wildcard = BaseDomain.suggestWildcard(for: row.host) {
                        Button {
                            model.hide(wildcard)
                        } label: {
                            Label("Hide \(wildcard)", systemImage: "eye.slash")
                        }
                    }
                }
            }
        } header: {
            if !snapshot.rows.isEmpty {
                Text("\(snapshot.rows.count) hosts · \(snapshot.activeCount) open now")
            }
        } footer: {
            if snapshot.hiddenCount > 0 || !settings.hiddenHosts.isEmpty {
                NavigationLink {
                    HiddenHostsView(model: model)
                } label: {
                    Text("Hidden (\(snapshot.hiddenCount))")
                        .font(.footnote)
                }
            }
        }

        Section {
            ForEach(snapshot.refusals, id: \.key) { group in
                RefusalRowView(group: group)
            }
        } header: {
            if !snapshot.refusals.isEmpty { Text("Couldn't carry") }
        } footer: {
            Text(ScannerText.notShownFooter)
        }
    }

    private func addSelected(newProfile: Bool) {
        let rows = model.snapshot?.rows.filter { selection.contains($0.id) } ?? []
        guard !rows.isEmpty else { return }
        sheet = AddSheetRequest(rows: rows, newProfile: newProfile)
    }

    private func visibleRows(_ rows: [HostRow]) -> [HostRow] {
        let query = search.trimmingCharacters(in: .whitespaces).lowercased()
        return rows.filter { row in
            switch filter {
            case .all: break
            case .problems: guard row.verdict.status.isProblem else { return false }
            case .noRule: guard row.isDefaultProfile else { return false }
            }
            guard !query.isEmpty else { return true }
            return row.host.contains(query) || row.ips.contains { $0.contains(query) } || row.snis.contains { $0.contains(query) }
        }
    }
}

struct HostRowView: View {
    let row: HostRow

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(alignment: .firstTextBaseline) {
                VStack(alignment: .leading, spacing: 1) {
                    Text(row.sni ?? row.host)
                        .font(.body)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    if row.sni != nil {
                        Text(row.host)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                Spacer()
                ProfileBadge(name: row.profileName, isDefault: row.isDefaultProfile)
            }
            HStack(spacing: 6) {
                Text(details)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                if let chip = protocolChip {
                    Text(chip)
                        .font(.caption2.weight(.semibold))
                        .padding(.horizontal, 5)
                        .padding(.vertical, 1)
                        .background(Color.secondary.opacity(0.15), in: Capsule())
                }
                Spacer()
                VerdictLabel(verdict: row.verdict)
            }
        }
        .accessibilityElement(children: .combine)
    }

    private var details: String {
        let ports = row.ports.prefix(3).map(String.init).joined(separator: ",")
        var parts = [ports]
        if row.connectionCount > 0 { parts.append("\(row.connectionCount) conn") }
        if row.openCount > 0 { parts.append("\(row.openCount) open") }
        parts.append(ScannerText.ago(row.lastSeen))
        return parts.joined(separator: " · ")
    }

    /// TLS is the default and gets no chip.
    private var protocolChip: String? {
        guard !row.kinds.isEmpty, !row.kinds.contains(.tls) else { return nil }
        return row.kinds.map(\.rawValue).sorted().joined(separator: "/")
    }
}

struct VerdictLabel: View {
    let verdict: HostVerdict

    var body: some View {
        if let copy = ScannerText.copy(for: verdict), verdict.status != .working {
            HStack(spacing: 4) {
                Circle()
                    .fill(ScannerText.color(for: verdict.status))
                    .frame(width: 7, height: 7)
                Text(copy.title)
                    .font(.caption)
                    .foregroundStyle(ScannerText.color(for: verdict.status))
                    .lineLimit(1)
                if verdict.echSeen, verdict.status.isProblem {
                    Text("ECH")
                        .font(.caption2.weight(.semibold))
                        .foregroundStyle(.secondary)
                }
            }
        }
    }
}

struct ProfileBadge: View {
    let name: String
    let isDefault: Bool

    var body: some View {
        Text(isDefault ? "Default" : (name.isEmpty ? "Unnamed" : name))
            .font(.caption2.weight(.medium))
            .lineLimit(1)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .foregroundStyle(isDefault ? Color.secondary : Color.accentColor)
            .background((isDefault ? Color.secondary : Color.accentColor).opacity(0.12), in: Capsule())
    }
}

private struct RefusalRowView: View {
    let group: RefusalGroup

    @EnvironmentObject private var settings: SettingsStore

    var body: some View {
        if case .routeRejected(let name) = group.key,
           let profile = settings.profiles.first(where: { $0.name == name }) {
            NavigationLink {
                ProfileEditView(profileID: profile.id)
            } label: {
                text
            }
        } else {
            text
        }
    }

    private var text: some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(ScannerText.refusal(group))
                .font(.callout)
            Text(detail)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    private var detail: String {
        var parts = ["\(group.count)×", ScannerText.ago(group.lastSeen)]
        if !group.targets.isEmpty {
            parts.append(group.targets.suffix(3).map { "\($0.host):\($0.port)" }.joined(separator: ", "))
        }
        if case .malformed = group.key, let reason = group.lastReason, case .handshake(let failure) = reason {
            parts.append(failure.description)
        }
        return parts.joined(separator: " · ")
    }
}

/// The patterns the scanner leaves out (§7.3), matched like profile patterns.
private struct HiddenHostsView: View {
    @ObservedObject var model: ScannerModel
    @EnvironmentObject private var settings: SettingsStore
    @State private var newPattern = ""

    var body: some View {
        List {
            Section {
                ForEach(settings.hiddenHosts, id: \.self) { Text($0) }
                    .onDelete { offsets in
                        var patterns = settings.hiddenHosts
                        patterns.remove(atOffsets: offsets)
                        settings.setHiddenHosts(patterns)
                        model.refresh()
                    }
                HStack {
                    TextField("example.com or *.example.com", text: $newPattern)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .onSubmit(add)
                    Button("Add", action: add)
                        .disabled(newPattern.trimmingCharacters(in: .whitespaces).isEmpty)
                }
            } footer: {
                Text("Hidden hosts are still carried and logged, just not listed. Same pattern syntax as profiles.")
            }
        }
        .navigationTitle("Hidden")
        .toolbar { EditButton() }
    }

    private func add() {
        let pattern = newPattern.trimmingCharacters(in: .whitespaces)
        guard !pattern.isEmpty else { return }
        model.hide(pattern)
        newPattern = ""
    }
}
