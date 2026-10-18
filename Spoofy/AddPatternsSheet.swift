import SwiftUI

/// Adds the selected hosts to an existing or a new profile (network-scanner plan §7.4).
struct AddPatternsSheet: View {
    let rows: [HostRow]
    /// Called after saving with the confirmation text.
    let onSave: (String) -> Void

    @EnvironmentObject private var settings: SettingsStore
    @Environment(\.dismiss) private var dismiss

    private enum Target: Hashable {
        case existing(UUID)
        case new
    }

    /// The pattern field of each host, starting at its first suggestion.
    @State private var patterns: [String: String]
    @State private var target: Target = .new
    @State private var draft: SpoofProfile
    private let note: AddPatternsPlan.Note?

    init(rows: [HostRow], master: SpoofProfile, onSave: @escaping (String) -> Void) {
        self.rows = rows
        self.onSave = onSave

        let kinds = rows.compactMap { row -> BlockKind? in
            switch row.verdict.status {
            case .blocked(let kind), .suspicious(let kind): return kind
            default: return nil
            }
        }
        let suggestion = AddPatternsPlan.suggestion(kinds: kinds, payloads: rows.reduce(into: []) { $0.formUnion($1.kinds) },
                                                    masterHasOutline: master.outlineConfig != nil)
        note = suggestion.note
        _draft = State(initialValue: .makeCustom(name: AddPatternsPlan.defaultName(hosts: rows.map(\.host)), domainPatterns: [],
                                                 routeMode: suggestion.routeMode, splitMode: suggestion.splitMode,
                                                 dohEnabled: suggestion.dohEnabled))
        _patterns = State(initialValue: Dictionary(rows.map { ($0.host, AddPatternsPlan.suggestions(for: $0.host)[0]) },
                                                   uniquingKeysWith: { first, _ in first }))
    }

    private var hosts: [String] { rows.map(\.host) }
    private var entries: [AddPatternsPlan.Entry] { AddPatternsPlan.entries(hosts: hosts, patterns: patterns) }

    private var targetProfile: SpoofProfile? {
        switch target {
        case .new: return draft
        case .existing(let id): return settings.customProfiles.first { $0.id == id }
        }
    }

    private var warnings: [AddPatternsPlan.Warning] {
        guard let targetProfile else { return [] }
        return AddPatternsPlan.warnings(entries: entries, target: targetProfile, isNew: target == .new, profiles: settings.profiles)
    }

    var body: some View {
        NavigationStack {
            Form {
                patternsSection
                targetSection
                if target == .new { newProfileSection }
                warningsSection
            }
            .navigationTitle(rows.count == 1 ? "Add Host" : "Add \(rows.count) Hosts")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save", action: save)
                        .disabled(!canSave)
                }
            }
        }
    }

    // MARK: - Sections

    private var patternsSection: some View {
        Section("Patterns") {
            ForEach(rows) { row in
                PatternField(row: row, pattern: patternBinding(row.host))
            }
        }
    }

    /// New profile first and in the accent colour, then the existing ones (§7.4).
    private var targetSection: some View {
        Section("Add to") {
            targetRow(.new) {
                Label("New profile", systemImage: "plus.circle.fill")
                    .foregroundStyle(Color.accentColor)
                    .fontWeight(.medium)
            }
            ForEach(settings.customProfiles) { profile in
                targetRow(.existing(profile.id)) {
                    Text(profile.name.isEmpty ? "Unnamed profile" : profile.name)
                        .foregroundStyle(profile.isEnabled ? Color.primary : Color.secondary)
                }
            }
        }
    }

    private func targetRow(_ value: Target, @ViewBuilder label: () -> some View) -> some View {
        Button {
            target = value
        } label: {
            HStack {
                label()
                Spacer()
                if target == value {
                    Image(systemName: "checkmark")
                        .fontWeight(.semibold)
                        .foregroundStyle(Color.accentColor)
                }
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    private var newProfileSection: some View {
        Section {
            TextField("Profile Name", text: $draft.name)
            Picker("Route", selection: $draft.routeMode) {
                ForEach(RouteMode.allCases) { Text($0.displayName).tag($0) }
            }
            if draft.routeMode == .split {
                Picker("Split Mode", selection: $draft.splitMode) {
                    ForEach(SplitMode.allCases) { Text($0.displayName).tag($0) }
                }
                Toggle("DoH", isOn: $draft.dohEnabled)
            }
        } header: {
            Text("New profile")
        } footer: {
            switch note {
            case .ipNeedsVPN:
                Text("IP blocks usually need VPN. Add an Outline server to Master to use it here.")
            case .splitOnlyChangesTLS:
                Text("Split modes only change TLS connections; these hosts carry other protocols.")
            case nil:
                if draft.routeMode == .vpn, settings.master.outlineConfig == nil {
                    Text("Master has no Outline server; set one in the profile before this route works.")
                }
            }
        }
    }

    @ViewBuilder
    private var warningsSection: some View {
        let warnings = warnings
        if !warnings.isEmpty {
            Section("Warnings") {
                ForEach(Array(warnings.enumerated()), id: \.offset) { _, warning in
                    Label(text(for: warning), systemImage: "exclamationmark.triangle")
                        .font(.callout)
                        .foregroundStyle(.orange)
                }
            }
        }
    }

    private func text(for warning: AddPatternsPlan.Warning) -> String {
        switch warning {
        case .alreadyInTarget(let pattern): return "\(pattern) is already in this profile; skipped."
        case .shadowed(let host, let name): return "\(host) will still match \(name) first (\(name) is above this profile)."
        case .targetDisabled: return "Profile is off; enable it to apply."
        }
    }

    // MARK: - Actions

    private func patternBinding(_ host: String) -> Binding<String> {
        Binding(get: { patterns[host] ?? "" }, set: { patterns[host] = $0 })
    }

    private var canSave: Bool {
        guard !entries.isEmpty, targetProfile != nil else { return false }
        guard !rows.contains(where: { AddPatternsPlan.check(patterns[$0.host] ?? "", host: $0.host) == .invalid }) else { return false }
        if target == .new { return !draft.name.trimmingCharacters(in: .whitespaces).isEmpty }
        return true
    }

    private func save() {
        let patterns = entries.map(\.pattern)
        switch target {
        case .new:
            var profile = draft
            profile.name = profile.name.trimmingCharacters(in: .whitespaces)
            profile.domainPatterns = patterns
            settings.addProfile(profile)
            onSave("Added \(count(patterns.count)) to new profile \(profile.name)")
        case .existing(let id):
            let name = settings.customProfiles.first { $0.id == id }?.name ?? "profile"
            let added = settings.addPatterns(patterns, to: id)
            onSave(added == 0 ? "\(name) already has these patterns" : "Added \(count(added)) to \(name)")
        }
        dismiss()
    }

    private func count(_ n: Int) -> String {
        n == 1 ? "1 pattern" : "\(n) patterns"
    }
}

/// One host's pattern: editable, with the suggestions in a menu and a live check below.
private struct PatternField: View {
    let row: HostRow
    @Binding var pattern: String

    var body: some View {
        let suggestions = AddPatternsPlan.suggestions(for: row.host)
        VStack(alignment: .leading, spacing: 4) {
            Text(row.host)
                .font(.caption)
                .foregroundStyle(.secondary)
            HStack {
                TextField("Pattern", text: $pattern)
                    .font(.body.monospaced())
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                Menu {
                    ForEach(suggestions, id: \.self) { suggestion in
                        Button(suggestion) { pattern = suggestion }
                    }
                } label: {
                    Image(systemName: "chevron.up.chevron.down")
                }
                .accessibilityLabel("Suggested patterns")
            }
            checkText
                .font(.caption)
            if let sni = row.sni {
                Text("The app asked for \(sni) but connected to the IP itself, so the rule has to be the IP. Set the app to resolve names through the proxy (SOCKS5h / remote DNS) to use domain rules.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 2)
    }

    @ViewBuilder
    private var checkText: some View {
        switch AddPatternsPlan.check(pattern, host: row.host) {
        case .exact:
            Text("Matches only \(row.host)").foregroundStyle(.secondary)
        case .wider:
            let normalized = AddPatternsPlan.normalized(pattern)
            let rest = normalized.dropFirst(2)
            if normalized.hasPrefix("*."), !rest.contains("*") {
                Text("Covers \(String(rest)) and its subdomains").foregroundStyle(.secondary)
            } else {
                Text("Matches \(row.host) and other hosts").foregroundStyle(.secondary)
            }
        case .noMatch:
            Text("Doesn't match \(row.host)").foregroundStyle(.orange)
        case .invalid:
            Text("Not a valid pattern").foregroundStyle(.red)
        }
    }
}
