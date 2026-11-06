//
//  SettingsView.swift
//  NFCPassportReaderApp
//
//  Created by Andy Qua on 10/02/2021.
//  Copyright © 2021 Andy Qua. All rights reserved.
//

import SwiftUI
import NFCPassportReader

struct SettingsView: View {
    @EnvironmentObject var settings: SettingsStore

    var body: some View {
        Form {
            Section(header: Text("Passport reading settings")) {
                Toggle(isOn: $settings.useNewVerificationMethod) {
                    Text("Use new Passive Authentication")
                }
                Toggle(isOn: $settings.useExtendedMode) {
                    Text("Use new Extended mode for reading")
                }
                Toggle(isOn: $settings.skipPACE) {
                    Text("Skip PACE authentication - use BAC only")
                }
                Toggle(isOn: $settings.skipCA) {
                    Text("Skip CA Authentication")
                }
                VStack {
                    Toggle(isOn: $settings.savePassportOnScan) {
                        Text("Save passport on scan & import")
                    }
                    HStack {
                        Text( "Note - currently stored as JSON on device\nWill not be backed up to iCloud" )
                            .font(.footnote)
                        Spacer()
                    }
                }
            }
            Section(header: Text("Diagnostics")) {
                Picker("Minimum log level", selection: $settings.logLevel) {
                    ForEach(PassportLogLevel.allCases, id: \.rawValue) { level in
                        Text(title(for: level)).tag(level.rawValue)
                    }
                }
                Toggle(isOn: $settings.includeSensitiveTraceData) {
                    Text("Include sensitive trace data")
                }
                Text("May include passport data and authentication details in the trace and exported file. Off by default.")
                    .font(.footnote)
                    .foregroundColor(.secondary)
            }
        }
        .navigationBarTitle(Text("Settings"))
    }

    private func title(for level: PassportLogLevel) -> LocalizedStringKey {
        switch level {
            case .debug: return "Debug"
            case .info: return "Info"
            case .warning: return "Warning"
            case .error: return "Error"
            case .fault: return "Fault"
        }
    }
}

struct SettingsView_Previews: PreviewProvider {
    static var previews: some View {
        let settings = SettingsStore()
        SettingsView()
            .environmentObject(settings)
    }
}
