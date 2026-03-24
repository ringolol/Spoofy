import SwiftUI

struct SettingsView: View {
    @State private var profiles: [SpoofProfile] = []
    @State private var portText: String = "8090"
    @State private var allowLANAccess: Bool = false
    @State private var showExportedAlert = false
    @State private var showImportConfirm = false
    @State private var showImportError = false
    @State private var pendingImportJSON: String?

    private let settings = AppSettings.shared

    var body: some View {
        Form {
            Section("Profiles") {
                ForEach(customProfiles) { profile in
                    profileRow(profile)
                }
                .onDelete(perform: deleteCustomProfiles)
                .onMove(perform: moveCustomProfiles)

                if let def = defaultProfile {
                    NavigationLink {
                        ProfileEditView(profileID: def.id)
                    } label: {
                        HStack {
                            VStack(alignment: .leading) {
                                Text(def.name)
                                    .font(.body)
                                Text("All traffic")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                            Spacer()
                            Text(def.routeMode == .vpn ? def.vpnType.displayName : def.splitMode.displayName)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                }

                Button {
                    addProfile()
                } label: {
                    Label("Add Profile", systemImage: "plus")
                }
            }

            Section("Export / Import") {
                Button {
                    if let json = settings.exportJSON() {
                        UIPasteboard.general.string = json
                        showExportedAlert = true
                    }
                } label: {
                    Label("Export Settings", systemImage: "doc.on.clipboard")
                }

                Button {
                    guard let json = UIPasteboard.general.string else {
                        showImportError = true
                        return
                    }
                    pendingImportJSON = json
                    showImportConfirm = true
                } label: {
                    Label("Import Settings", systemImage: "clipboard")
                }
            }

            Section("Advanced") {
                HStack {
                    Text("Proxy Port")
                    Spacer()
                    TextField("Port", text: $portText)
                        .keyboardType(.numberPad)
                        .multilineTextAlignment(.trailing)
                        .frame(width: 80)
                        .onChange(of: portText) { newValue in
                            let filtered = String(newValue.filter { $0.isNumber }.prefix(5))
                            if filtered != newValue { portText = filtered }
                            if let port = UInt16(filtered), port >= 1024 {
                                settings.proxyPort = port
                            }
                        }
                }

                Toggle("Allow LAN Access", isOn: $allowLANAccess)
                    .onChange(of: allowLANAccess) { newValue in
                        settings.allowLANAccess = newValue
                    }
            }
        }
        .navigationTitle("Settings")
        .toolbar {
            EditButton()
        }
        .onAppear { reload() }
        .alert("Settings Exported", isPresented: $showExportedAlert) {
            Button("OK", role: .cancel) {}
        } message: {
            Text("Settings have been copied to clipboard.")
        }
        .alert("Import Settings?", isPresented: $showImportConfirm) {
            Button("Cancel", role: .cancel) { pendingImportJSON = nil }
            Button("Import", role: .destructive) {
                if let json = pendingImportJSON {
                    do {
                        try settings.importJSON(json)
                        reload()
                    } catch {
                        showImportError = true
                    }
                }
                pendingImportJSON = nil
            }
        } message: {
            Text("This will replace all current settings with the imported ones.")
        }
        .alert("Import Failed", isPresented: $showImportError) {
            Button("OK", role: .cancel) {}
        } message: {
            Text("Clipboard does not contain valid settings data.")
        }
    }

    private var customProfiles: [SpoofProfile] {
        profiles.filter { !$0.isDefault }
    }

    private var defaultProfile: SpoofProfile? {
        profiles.first { $0.isDefault }
    }

    private func reload() {
        profiles = settings.profiles
        portText = "\(settings.proxyPort)"
        allowLANAccess = settings.allowLANAccess
    }

    private func profileRow(_ profile: SpoofProfile) -> some View {
        NavigationLink {
            ProfileEditView(profileID: profile.id)
        } label: {
            HStack {
                Toggle("", isOn: toggleBinding(for: profile))
                    .labelsHidden()
                    .fixedSize()

                VStack(alignment: .leading) {
                    Text(profile.name.isEmpty ? "New Profile" : profile.name)
                        .font(.body)
                        .foregroundStyle(profile.name.isEmpty ? .secondary : .primary)
                    let count = profile.domainPatterns.count
                    Text("\(count) domain\(count == 1 ? "" : "s")")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .opacity(profile.isEnabled ? 1 : 0.5)

                Spacer()

                Text(profile.routeMode == .vpn ? profile.vpnType.displayName : profile.splitMode.displayName)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .opacity(profile.isEnabled ? 1 : 0.5)
            }
        }
    }

    private func toggleBinding(for profile: SpoofProfile) -> Binding<Bool> {
        Binding(
            get: { profiles.first { $0.id == profile.id }?.isEnabled ?? false },
            set: { newValue in
                if let idx = profiles.firstIndex(where: { $0.id == profile.id }) {
                    profiles[idx].isEnabled = newValue
                    saveProfiles()
                }
            }
        )
    }

    private func addProfile() {
        let newProfile = SpoofProfile(
            id: UUID(),
            name: "",
            isEnabled: true,
            domainPatterns: [],
            routeMode: .split,
            vpnType: .outline,
            outlineConfig: nil,
            splitMode: .none,
            chunkSize: 5,
            tlsRecordFragmentation: false,
            dohEnabled: false,
            dohServerURL: "https://1.1.1.1/dns-query",
            isDefault: false
        )
        let defaultIndex = profiles.firstIndex { $0.isDefault } ?? profiles.endIndex
        profiles.insert(newProfile, at: defaultIndex)
        saveProfiles()
    }

    private func deleteCustomProfiles(at offsets: IndexSet) {
        let custom = customProfiles
        let idsToDelete = offsets.map { custom[$0].id }
        profiles.removeAll { idsToDelete.contains($0.id) }
        saveProfiles()
    }

    private func moveCustomProfiles(from source: IndexSet, to destination: Int) {
        var custom = customProfiles
        custom.move(fromOffsets: source, toOffset: destination)
        let def = profiles.filter { $0.isDefault }
        profiles = custom + def
        saveProfiles()
    }

    private func saveProfiles() {
        settings.profiles = profiles
    }
}

// MARK: - Profile Edit

struct ProfileEditView: View {
    let profileID: UUID

    @State private var profile: SpoofProfile = SpoofProfile.makeDefault()
    @State private var domainText: String = ""
    @State private var accessKeyText: String = ""
    @State private var accessKeyError: String?

    private let settings = AppSettings.shared

    var body: some View {
        Form {
            if !profile.isDefault {
                Section("Name") {
                    TextField("Profile Name", text: $profile.name)
                }
            }

            Section("Route Mode") {
                Picker("Mode", selection: $profile.routeMode) {
                    ForEach(RouteMode.allCases) { mode in
                        Text(mode.displayName).tag(mode)
                    }
                }
                .pickerStyle(.segmented)
            }

            if profile.routeMode == .vpn {
                Section {
                    Picker("VPN Type", selection: $profile.vpnType) {
                        ForEach(VPNType.allCases) { type in
                            Text(type.displayName).tag(type)
                        }
                    }
                } header: {
                    Text("VPN")
                }

                Section {
                    TextField("ss:// access key", text: $accessKeyText, axis: .vertical)
                        .font(.system(.body, design: .monospaced))
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .lineLimit(3)
                        .onChange(of: accessKeyText) { newValue in
                            parseAccessKey(newValue)
                        }

                    if let error = accessKeyError {
                        Text(error)
                            .foregroundColor(.red)
                            .font(.caption)
                    }

                    if let config = profile.outlineConfig {
                        VStack(alignment: .leading, spacing: 4) {
                            Label("\(config.host):\(config.port)", systemImage: "server.rack")
                            Label(config.cipher.displayName, systemImage: "lock.shield")
                            if config.prefix != nil {
                                Label("Prefix enabled", systemImage: "eye.slash")
                            }
                        }
                        .font(.caption)
                        .foregroundColor(.secondary)
                    }
                } header: {
                    Text("Outline Server")
                } footer: {
                    Text("Paste your Outline access key (ss:// URI)")
                }
            }

            if profile.routeMode == .split {
                Section("TLS Fragmentation") {
                    Picker("Split Mode", selection: $profile.splitMode) {
                        ForEach(SplitMode.allCases) { mode in
                            Text(mode.displayName).tag(mode)
                        }
                    }

                    if profile.splitMode == .chunk {
                        Stepper("Chunk Size: \(profile.chunkSize)", value: $profile.chunkSize, in: 1...1000)
                    }

                    Toggle("TLS Record Fragmentation", isOn: $profile.tlsRecordFragmentation)
                }

                Section("DNS over HTTPS") {
                    Toggle("Enable DoH", isOn: $profile.dohEnabled)

                    if profile.dohEnabled {
                        TextField("DoH Server URL", text: $profile.dohServerURL)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                    }
                }
            }

            if !profile.isDefault {
                Section {
                    TextEditor(text: $domainText)
                        .font(.system(.body, design: .monospaced))
                        .frame(minHeight: 100)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                } header: {
                    Text("Domains")
                } footer: {
                    Text("One pattern per line. Examples: *.example.com, example.*, *.youtube.*")
                }
            }
        }
        .navigationTitle(profile.isDefault ? "Master" : profile.name)
        .onAppear {
            if let found = settings.profiles.first(where: { $0.id == profileID }) {
                profile = found
                domainText = found.domainPatterns.joined(separator: "\n")
            }
        }
        .onChange(of: profile) { _ in save() }
        .onChange(of: domainText) { newValue in
            profile.domainPatterns = newValue
                .components(separatedBy: "\n")
                .map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty }
        }
    }

    private func save() {
        var all = settings.profiles
        if let idx = all.firstIndex(where: { $0.id == profileID }) {
            all[idx] = profile
            settings.profiles = all
        }
    }

    private func parseAccessKey(_ text: String) {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            profile.outlineConfig = nil
            accessKeyError = nil
            return
        }
        if let config = OutlineAccessKey.parse(trimmed) {
            profile.outlineConfig = config
            accessKeyError = nil
        } else {
            accessKeyError = "Invalid access key"
        }
    }
}
