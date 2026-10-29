//
//  PassportSimReadView.swift
//  NFCPassportReaderApp
//
//  Reads a passport from PassportSim's APDU server instead of NFC, so the reader (and the Trace
//  view) can be used in the iOS simulator. Start the server with `./gradlew :tools:apduServer`.
//

import SwiftUI
import NFCPassportReader

struct PassportSimReadView: View {
    @Environment(\.presentationMode) var presentationMode
    @EnvironmentObject var settings: SettingsStore

    @AppStorage("passportSim.host") private var host = "127.0.0.1"
    @AppStorage("passportSim.port") private var port = "9077"
    @AppStorage("passportSim.preset") private var preset = "pace-im"
    @State private var reading = false
    @State private var error: String?

    let passportReader: PassportReader
    let onRead: (NFCPassportModel) -> Void

    private let presets = [
        "pace-im", "pace-im-3des", "pace-im-aes256", "pace-gm", "pace-gm-3des", "pace-gm-aes256",
        "pace-only", "pace-full", "full", "bac-photo", "bac-ca-aes", "neg-pace-bad-token",
    ]

    var body: some View {
        NavigationView {
            Form {
                Section(header: Text("PassportSim APDU server"),
                        footer: Text("Run `./gradlew :tools:apduServer` in PassportSim. The MRZ key comes from the chosen profile.")) {
                    TextField("Host", text: $host)
                        .autocapitalization(.none)
                        .disableAutocorrection(true)
                    TextField("Port", text: $port)
                        .keyboardType(.numberPad)
                }
                Section(header: Text("Profile")) {
                    Picker("Preset", selection: $preset) {
                        ForEach(presets, id: \.self) { Text($0) }
                    }
                    TextField("Or type a preset id", text: $preset)
                        .autocapitalization(.none)
                        .disableAutocorrection(true)
                }
                if let error = error {
                    Section { Text(error).foregroundColor(.red).font(.footnote) }
                }
                Section {
                    Button(action: read) {
                        HStack {
                            Text(reading ? "Reading…" : "Read passport")
                            if reading { Spacer(); ProgressView() }
                        }
                    }
                    .disabled(reading || UInt16(port) == nil)
                }
            }
            .navigationTitle("Read from PassportSim")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Close") { presentationMode.wrappedValue.dismiss() }
                }
            }
        }
    }

    private func read() {
        guard let portNumber = UInt16(port) else { return }
        reading = true
        error = nil
        let preset = self.preset
        let host = self.host
        let skipPACE = settings.skipPACE
        let skipCA = settings.skipCA
        Task {
            do {
                let tag = try PassportSimTag(host: host, port: portNumber)
                let mrzKey = try tag.selectProfile(preset)
                let passport = try await passportReader.readPassport(tag: tag, mrzKey: mrzKey, skipCA: skipCA, skipPACE: skipPACE)
                await MainActor.run {
                    reading = false
                    presentationMode.wrappedValue.dismiss()
                    onRead(passport)
                }
            } catch {
                await MainActor.run {
                    reading = false
                    self.error = error.localizedDescription
                }
            }
        }
    }
}
