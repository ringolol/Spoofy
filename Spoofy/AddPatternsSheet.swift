import SwiftUI

/// Adds the selected hosts to an existing or a new profile (network-scanner plan §7.4).
struct AddPatternsSheet: View {
    let rows: [HostRow]
    /// Called after saving with the confirmation text.
    let onSave: (String) -> Void
    /// Closes the sheet. The presenter clears its own state instead of relying on
    /// `@Environment(\.dismiss)`, which didn't close it on the Mac while the list behind refreshed.
    let onClose: () -> Void

    @EnvironmentObject private var settings: SettingsStore

    private enum Target: Hashable {
        case existing(UUID)
        case new
    }

    /// The pattern field of each host, starting at its first suggestion.
    @State private var patterns: [String: String]
    @State private var target: Target = .new
    @State private var draft: SpoofProfile
    private let suggestion: AddPatternsPlan.Suggestion
    /// The distinct problems among the selected hosts; more than one means the suggestion follows the most common.
    private let kindCount: Int

    init(rows: [HostRow], master: SpoofProfile, onSave: @escaping (String) -> Void, onClose: @escaping () -> Void) {
        self.rows = rows
        self.onSave = onSave
        self.onClose = onClose

        let kinds = rows.compactMap { row -> BlockKind? in
            switch row.verdict.status {
            case .blocked(let kind), .suspicious(let kind): return kind
            default: return nil
            }
        }
        let suggestion = AddPatternsPlan.suggestion(kinds: kinds, payloads: rows.reduce(into: []) { $0.formUnion($1.kinds) },
                                                    masterHasOutline: master.outlineConfig != nil)
        self.suggestion = suggestion
        kindCount = Set(kinds).count
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

    /// Based on how the hosts were blocked, rather than the defaults.
    private var isRecommended: Bool { suggestion.reason != .noEvidence }

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
                    Button("Cancel", action: onClose)
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

    /// New profile is the default and comes first; its settings follow in their own section (§7.4).
    private var targetSection: some View {
        Section {
            Picker("Add to", selection: $target) {
                Label("New Profile", systemImage: "plus.circle").tag(Target.new)
                if !settings.customProfiles.isEmpty {
                    Divider()
                }
                ForEach(settings.customProfiles) { profile in
                    Text(profileTitle(profile)).tag(Target.existing(profile.id))
                }
            }
        } footer: {
            if isRecommended, case .existing = target, let profile = targetProfile {
                if suggestion.matches(profile) {
                    Text("This profile already has the recommended settings.")
                } else {
                    Text("This profile keeps its own settings. Recommended for these hosts: \(summary).")
                }
            }
        }
    }

    private func profileTitle(_ profile: SpoofProfile) -> String {
        let name = profile.name.isEmpty ? "Unnamed profile" : profile.name
        return profile.isEnabled ? name : "\(name) (off)"
    }

    private var newProfileSection: some View {
        Section {
            reasonRow
            TextField("Profile Name", text: $draft.name)
            Picker("Route", selection: $draft.routeMode) {
                ForEach(RouteMode.allCases) { Text(option($0.displayName, recommended: $0 == suggestion.routeMode)).tag($0) }
            }
            if draft.routeMode == .split {
                Picker("Split Mode", selection: $draft.splitMode) {
                    ForEach(SplitMode.allCases) {
                        Text(option($0.displayName, recommended: suggestion.routeMode == .split && $0 == suggestion.splitMode)).tag($0)
                    }
                }
            }
            // Both routes use it: VPN resolves locally and sends the address to the Outline server.
            Toggle(isOn: $draft.dohEnabled) {
                Text("DoH")
                if isRecommended {
                    Text(suggestion.dohEnabled ? "Recommended: on" : "Recommended: off")
                }
            }
        } header: {
            HStack {
                Text("New profile")
                Spacer()
                recommendedBadge
            }
        } footer: {
            switch suggestion.note {
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

    /// Why these settings: the problem as the scanner shows it, then what the settings do about it.
    @ViewBuilder
    private var reasonRow: some View {
        if let verdict = reasonVerdict {
            VStack(alignment: .leading, spacing: 4) {
                VerdictLabel(verdict: verdict)
                Text(reasonText)
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
        } else {
            Label {
                Text(reasonText)
                    .font(.callout)
                    .foregroundStyle(.secondary)
            } icon: {
                Image(systemName: "info.circle")
                    .foregroundStyle(.secondary)
            }
        }
    }

    /// A selected host's verdict of the kind the suggestion answers; a blocked one over a suspicious one.
    private var reasonVerdict: HostVerdict? {
        guard case .blocked(let kind) = suggestion.reason else { return nil }
        let verdicts = rows.map(\.verdict).filter {
            switch $0.status {
            case .blocked(let k), .suspicious(let k): return k == kind
            default: return false
            }
        }
        return verdicts.first { if case .blocked = $0.status { return true } else { return false } } ?? verdicts.first
    }

    /// "Recommended" while the draft has the suggested settings; a way back once it doesn't.
    @ViewBuilder
    private var recommendedBadge: some View {
        if isRecommended {
            if suggestion.matches(draft) {
                Label("Recommended", systemImage: "checkmark.seal.fill")
                    .labelStyle(.titleAndIcon)
                    .foregroundStyle(.green)
                    .textCase(nil)
            } else {
                Button("Use Recommended") {
                    draft.routeMode = suggestion.routeMode
                    draft.splitMode = suggestion.splitMode
                    draft.dohEnabled = suggestion.dohEnabled
                }
                .font(.footnote)
                .textCase(nil)
                .padding(.vertical, 6)
                .contentShape(Rectangle())
            }
        }
    }

    private func option(_ name: String, recommended: Bool) -> String {
        isRecommended && recommended ? "\(name) (recommended)" : name
    }

    /// "Split · SNI · DoH on".
    private var summary: String {
        var parts = [suggestion.routeMode.displayName]
        if suggestion.routeMode == .split { parts.append(suggestion.splitMode.displayName) }
        parts.append(suggestion.dohEnabled ? "DoH on" : "DoH off")
        return parts.joined(separator: " · ")
    }

    private var reasonText: String {
        let vpn = suggestion.routeMode == .vpn
        let cause: String
        switch suggestion.reason {
        case .noEvidence:
            return "No block seen for these hosts yet, so these are the default settings."
        case .nonTLS:
            return vpn ? "These hosts don't use TLS, so splitting can't help. VPN carries them through your Outline server."
                       : "These hosts don't use TLS, so splitting can't help."
        case .blocked(let kind):
            // The verdict label above names the problem; this says what the settings do about it.
            switch kind {
            case .sni, .injected:
                cause = "SNI split hides the site name from DPI."
            case .dns:
                cause = "DoH gets the real address."
            case .ip, .freeze, .whitelist:
                cause = vpn ? "Splitting can't help with this. VPN goes through your Outline server."
                            : "Splitting rarely helps with this; it needs a VPN."
            case .httpBlockPage:
                cause = vpn ? "VPN carries the request past the filter."
                            : "DoH avoids a spoofed address; use HTTPS where you can."
            case .outline:
                cause = "SNI split tries without the Outline server."
            }
        }
        return kindCount > 1 ? cause + " The most common problem among the selected hosts." : cause
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
        onClose()
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
                        .frame(width: 44, height: 44)
                        .contentShape(Rectangle())
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
