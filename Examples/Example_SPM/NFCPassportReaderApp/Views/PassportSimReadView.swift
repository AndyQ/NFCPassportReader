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
    @EnvironmentObject var trace: TraceStore

    @AppStorage("passportSim.host") private var host = "127.0.0.1"
    @AppStorage("passportSim.port") private var port = "9077"
    @AppStorage("passportSim.preset") private var preset = "pace-im"
    @AppStorage("passportSim.useCAN") private var useCAN = false
    @State private var reading = false
    @State private var error: String?

    let passportReader: PassportReader
    let onRead: (NFCPassportModel) -> Void

    private let presets = [
        "pace-im", "pace-im-3des", "pace-im-aes256", "pace-gm", "pace-gm-3des", "pace-gm-aes256",
        "pace-dh-3des", "pace-dh", "pace-only", "pace-full", "full", "bac-photo", "bac-ca-aes",
        "sod-rsa-pss-sha512", "sod-rsaencryption-sha512", "sod-ecdsa-ecpublickey-sha384", "sod-sha256-signature-sha512-digest",
        "pa-link-certificate", "neg-bad-sod-signature", "neg-dg-hash-mismatch", "neg-pace-bad-token", "pace-can-unsupported",
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
                Section(footer: Text("PACE only, no BAC fallback. PassportSim presets print the CAN 123456; pace-can-unsupported rejects it.")) {
                    Toggle("Unlock with the profile's CAN", isOn: $useCAN)
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
        trace.clear()
        reading = true
        error = nil
        let preset = self.preset
        let host = self.host
        let skipPACE = settings.skipPACE
        let skipCA = settings.skipCA
        let useCAN = self.useCAN
        Task {
            do {
                // Passive Authentication against the bundled master list plus PassportSim's CSCA and link certificate
                if let simMasterList = try PassportSimTag(host: host, port: portNumber).masterList() {
                    passportReader.setMasterListURL(try Self.masterList(adding: simMasterList))
                }
                let tag = try PassportSimTag(host: host, port: portNumber)
                let (mrzKey, can) = try tag.selectProfile(preset)
                let accessKey: PassportAccessKey
                if useCAN {
                    guard let can else { throw NFCPassportReaderError.InvalidDataPassed("Profile \(preset) has no CAN") }
                    accessKey = .can(can)
                } else {
                    accessKey = .mrz(mrzKey)
                }
                let passport = try await passportReader.readPassport(tag: tag, accessKey: accessKey, skipCA: skipCA, skipPACE: skipPACE)
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

    /// The bundled masterList.pem with PassportSim's certificates appended, so real documents still verify too.
    private static func masterList(adding pem: String) throws -> URL {
        let bundled = Bundle.main.url(forResource: "masterList", withExtension: "pem").flatMap { try? String(contentsOf: $0, encoding: .utf8) } ?? ""
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("masterList-with-passportsim.pem")
        try (bundled + "\n" + pem).write(to: url, atomically: true, encoding: .utf8)
        return url
    }
}
