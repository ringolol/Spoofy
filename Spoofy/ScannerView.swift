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
    @State private var showHidden = false

    private struct AddSheetRequest: Identifiable {
        let id = UUID()
        let rows: [HostRow]
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
                    Text("Paused")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Spacer()
                    Button("Add to Profile…", action: addSelected)
                        .disabled(selection.isEmpty)
                }
            }
            ToolbarItem(placement: .topBarTrailing) {
                Menu {
                    Button {
                        showHidden = true
                    } label: {
                        Label(hiddenTitle, systemImage: "eye.slash")
                    }
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
        // Paused while the sheet is open too, so the list doesn't rebuild behind it.
        .onChange(of: editMode.isEditing) { editing in
            model.isPaused = editing || sheet != nil
            if !editing { selection = [] }
        }
        .onChange(of: sheet == nil) { closed in
            model.isPaused = !closed || editMode.isEditing
        }
        .sheet(item: $sheet) { request in
            AddPatternsSheet(rows: request.rows, master: settings.master) { text in
                confirmation = text
                editMode = .inactive
            } onClose: {
                sheet = nil
                // On the Mac, SwiftUI queues the dismissal as a run loop block during its update and
                // doesn't wake the run loop, so the sheet stayed up until the next mouse move or
                // timer (seconds, seen in `sample`). A main-queue dispatch wakes it.
                DispatchQueue.main.async { CFRunLoopWakeUp(CFRunLoopGetMain()) }
            }
        }
        .confirmationToast($confirmation)
        .navigationDestination(isPresented: $showHidden) {
            HiddenHostsView(model: model)
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
                        sheet = AddSheetRequest(rows: [row])
                    } label: {
                        Label("Add to Profile…", systemImage: "plus.circle")
                    }
                    Button {
                        UIPasteboard.general.string = row.host
                    } label: {
                        Label("Copy Host", systemImage: "doc.on.doc")
                    }
                    Button {
                        hide(row.host)
                    } label: {
                        Label("Hide", systemImage: "eye.slash")
                    }
                    if let wildcard = BaseDomain.suggestWildcard(for: row.host) {
                        Button {
                            hide(wildcard)
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
            if !settings.hiddenHosts.isEmpty {
                Button("\(hiddenTitle) ›") { showHidden = true }
                    .font(.footnote)
                    .padding(.vertical, 6)
                    .contentShape(Rectangle())
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

    /// "Hidden Hosts (3)": hosts in the log that the patterns leave out.
    private var hiddenTitle: String {
        let count = model.snapshot?.hiddenCount ?? 0
        return count > 0 ? "Hidden Hosts (\(count))" : "Hidden Hosts"
    }

    private func hide(_ pattern: String) {
        model.hide(pattern)
        confirmation = "Hid \(pattern). Unhide it from ⋯ › Hidden Hosts."
    }

    private func addSelected() {
        let rows = model.snapshot?.rows.filter { selection.contains($0.id) } ?? []
        guard !rows.isEmpty else { return }
        sheet = AddSheetRequest(rows: rows)
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

extension View {
    /// Shows `text` in a capsule at the bottom for three seconds, then clears it.
    func confirmationToast(_ text: Binding<String?>) -> some View {
        overlay(alignment: .bottom) {
            if let message = text.wrappedValue {
                Text(message)
                    .font(.callout)
                    .padding(.horizontal, 14)
                    .padding(.vertical, 8)
                    .background(.regularMaterial, in: Capsule())
                    .padding(.bottom, 16)
                    .transition(.opacity)
            }
        }
        .task(id: text.wrappedValue) {
            guard text.wrappedValue != nil else { return }
            try? await Task.sleep(nanoseconds: 3_000_000_000)
            withAnimation { text.wrappedValue = nil }
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
                if settings.hiddenHosts.isEmpty {
                    Text("Nothing hidden. Long-press a host in the scanner to hide it.")
                        .foregroundStyle(.secondary)
                }
                ForEach(settings.hiddenHosts, id: \.self) { pattern in
                    HStack {
                        Text(pattern)
                        Spacer()
                        Button("Unhide") { unhide([pattern]) }
                            .buttonStyle(.borderless)
                    }
                    .swipeActions {
                        Button("Unhide") { unhide([pattern]) }
                            .tint(.accentColor)
                    }
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
                Text("Hidden hosts are still carried and logged, just not listed in the scanner. Same pattern syntax as profiles.")
            }
        }
        .navigationTitle("Hidden Hosts")
    }

    private func unhide(_ patterns: [String]) {
        settings.setHiddenHosts(settings.hiddenHosts.filter { !patterns.contains($0) })
        model.refresh()
    }

    private func add() {
        let pattern = newPattern.trimmingCharacters(in: .whitespaces)
        guard !pattern.isEmpty else { return }
        model.hide(pattern)
        newPattern = ""
    }
}
