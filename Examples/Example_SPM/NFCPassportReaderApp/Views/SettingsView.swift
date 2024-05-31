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
    
    private var logLevels = ["Verbose", "Debug", "Info", "Warning", "Error", "None"]

    var body: some View {
        Form {
            Section(header: Text("Passport reading settings")) {
                Toggle(isOn: $settings.useNewVerificationMethod) {
                    Text("Use new Passive Authentication (RFS5652 instead of OpenSSL CMS")
                }
                .padding(.bottom)
                Toggle(isOn: $settings.skipSecureElements) {
                    Text("Skip Secure Elements")
                }
                .padding(.bottom)
                Toggle(isOn: $settings.skipCA) {
                    Text("Skip CA Authentication")
                }
                .padding(.bottom)
                Toggle(isOn: $settings.skipPACE) {
                    Text("Skip PACE Authentication")
                }
                .padding(.bottom)
                Toggle(isOn: $settings.usePACEPolling) {
                    Text("Use PACE Polling rather than ISO14443")
                }
                .padding(.bottom)
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

        }
        .navigationBarTitle(Text("Settings"))
    }
}

struct SettingsView_Previews: PreviewProvider {
    static var previews: some View {
        let settings = SettingsStore()
        SettingsView()
            .environmentObject(settings)
    }
}
