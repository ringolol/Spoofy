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

    @State private var wildcard: [String: Bool] = [:]
    @State private var target: Target
    @State private var draft: SpoofProfile
    private let note: AddPatternsPlan.Note?

    init(rows: [HostRow], startWithNewProfile: Bool, customProfiles: [SpoofProfile], master: SpoofProfile,
         onSave: @escaping (String) -> Void) {
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

        // The profile the hosts already share, else the first one.
        let shared = Set(rows.map(\.profileID))
        let initial = customProfiles.first { shared.count == 1 && shared.contains($0.id) } ?? customProfiles.first
        _target = State(initialValue: startWithNewProfile ? .new : initial.map { .existing($0.id) } ?? .new)
    }

    private var hosts: [String] { rows.map(\.host) }
    private var entries: [AddPatternsPlan.Entry] { AddPatternsPlan.entries(hosts: hosts, wildcard: wildcard) }

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
        Section {
            ForEach(rows) { row in
                VStack(alignment: .leading, spacing: 4) {
                    if AddPatternsPlan.canWildcard(row.host) {
                        Picker(row.host, selection: wildcardBinding(row.host)) {
                            Text(row.host).tag(false)
                            Text(AddPatternsPlan.pattern(for: row.host, wildcard: true)).tag(true)
                        }
                        .pickerStyle(.menu)
                    } else {
                        Text(row.host)
                    }
                    if let sni = row.sni {
                        Text("The app asked for \(sni) but connected to the IP itself, so the rule has to be the IP. Set the app to resolve names through the proxy (SOCKS5h / remote DNS) to use domain rules.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            }
        } header: {
            Text("Patterns")
        } footer: {
            let patterns = entries.map(\.pattern)
            Text(patterns.joined(separator: ", "))
        }
    }

    private var targetSection: some View {
        Section("Profile") {
            Picker("Add to", selection: $target) {
                ForEach(settings.customProfiles) { profile in
                    Text(profile.name.isEmpty ? "Unnamed profile" : profile.name).tag(Target.existing(profile.id))
                }
                Text("New profile").tag(Target.new)
            }
        }
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

    private func wildcardBinding(_ host: String) -> Binding<Bool> {
        Binding(get: { wildcard[host] ?? true }, set: { wildcard[host] = $0 })
    }

    private var canSave: Bool {
        guard !entries.isEmpty, targetProfile != nil else { return false }
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
