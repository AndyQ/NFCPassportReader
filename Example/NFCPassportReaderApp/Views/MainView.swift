//
//  MainView.swift
//  NFCPassportReaderApp
//
//  Created by Andy Qua on 04/06/2019.
//  Copyright © 2019 Andy Qua. All rights reserved.
//

import SwiftUI
import Combine
import NFCPassportReader
import UniformTypeIdentifiers


struct MainView : View {
    @EnvironmentObject var settings: SettingsStore
    @Environment(\.colorScheme) var colorScheme

    @State private var showingAlert = false
    @State private var showingSheet = false
    @State private var showDetails = false
    @State private var alertTitle : String = ""
    @State private var alertMessage : String = ""
    @State private var showSettings : Bool = false
    @State private var showScanMRZ : Bool = false
    @State private var showSavedPassports : Bool = false

    @State var page = 0
    
    @State var bgColor = Color( UIColor.systemBackground )
    
    private let passportReader = PassportReader()

    var body: some View {
        NavigationView {
            ZStack {
                NavigationLink( destination: SettingsView(), isActive: $showSettings) { Text("") }
                NavigationLink( destination: PassportView(), isActive: $showDetails) { Text("") }
                NavigationLink( destination: StoredPassportView(), isActive: $showSavedPassports) { Text("") }
                NavigationLink( destination: MRZScanner(completionHandler:{ (nr,dob,doe) in
                    settings.passportNumber = nr
                    settings.dateOfBirth = dob
                    settings.dateOfExpiry = doe
                    showScanMRZ = false
                }).navigationTitle("Scan MRZ"), isActive: $showScanMRZ){ Text("") }

                VStack {
                    HStack {
                        Spacer()
                        Button(action: {self.showScanMRZ.toggle()}) {
                            Label("Scan MRZ", systemImage:"camera")
                        }.padding([.top, .trailing])
                    }
                    MRZEntryView()
                    Divider()
                    CANEntryView()
                    
                    Button(action: {
                        self.scanPassport()
                    }) {
                        Text("Scan Passport")
                            .font(.largeTitle)
                            .foregroundColor(isValid ? .secondary : Color.secondary.opacity(0.25))
                    }
                    .disabled( !isValid )

                    Spacer()
                    HStack(alignment:.firstTextBaseline) {
                        Text( "Version - \(UIApplication.version)" )
                            .font(.footnote)
                            .padding(.leading)
                        Spacer()
                        Button(action: {
                            shareLogs()
                        }) {
                            Text("Share logs")
                                .foregroundColor(.secondary)
                        }.padding(.trailing)
                        .disabled( !isValid )
                    }
                }
            }
            .navigationBarTitle("Passport details", displayMode: .automatic)
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Menu {
                        Button(action: {showSettings.toggle()}) {
                            Label("Settings", systemImage: "gear")
                        }
                        Button(action: {self.showSavedPassports.toggle()}) {
                            Label("Show saved passports", systemImage: "doc")
                        }
                    } label: {
                        Image(systemName: "gear")
                            .foregroundColor(Color.secondary)
                    }
                }
            }
            .alert(isPresented: $showingAlert) {
                    Alert(title: Text(alertTitle), message:
                        Text(alertMessage), dismissButton: .default(Text("Got it!")))
            }
            .background(colorScheme == .dark ? Color.black : Color.white)
        }
    }
}

// MARK: View functions - functions that affect the view
extension MainView {
    
    var isValid : Bool {
        return settings.passportNumber.count >= 8
    }

}

// MARK: Action Functions
extension MainView {

    func shareLogs() {
        hideKeyboard()
        PassportUtils.shareLogs()
    }

    func scanPassport( ) {
        hideKeyboard()
        self.showDetails = false
        
        let df = DateFormatter()
        df.timeZone = TimeZone(secondsFromGMT: 0)
        df.dateFormat = "YYMMdd"
        
        let pptNr = settings.passportNumber
        let dob = df.string(from:settings.dateOfBirth)
        let doe = df.string(from:settings.dateOfExpiry)

        let can = settings.cardAccessNumber

        let passportUtils = PassportUtils()
        let mrzKey = passportUtils.getMRZKey( passportNumber: pptNr, dateOfBirth: dob, dateOfExpiry: doe)

        // Set the masterListURL on the Passport Reader to allow auto passport verification
        let masterListURL = Bundle.main.url(forResource: "masterList", withExtension: ".pem")!
        passportReader.setMasterListURL( masterListURL )
        
        // Set whether to use the new Passive Authentication verification method (default true) or the old OpenSSL CMS verifiction
        passportReader.passiveAuthenticationUsesOpenSSL = !settings.useNewVerificationMethod

        // If we want to read only specific data groups we can using:
//        let dataGroups : [DataGroupId] = [.COM, .SOD, .DG1, .DG2, .DG7, .DG11, .DG12, .DG14, .DG15]
//        passportReader.readPassport(mrzKey: mrzKey, tags:dataGroups, completed: { (passport, error) in
        
        Log.logLevel = settings.logLevel
        Log.storeLogs = settings.shouldCaptureLogs
        Log.clearStoredLogs()

        var accessKey = mrzKey
        var paceKeyReference : UInt8 = PACEHandler.MRZ_PACE_KEY_REFERENCE
        if (can != "") {
            accessKey = can
            paceKeyReference = PACEHandler.CAN_PACE_KEY_REFERENCE
        }

        // This is also how you can override the default messages displayed by the NFC View Controller
        passportReader.readPassport(accessKey: accessKey, paceKeyReference: paceKeyReference, customDisplayMessage: { (displayMessage) in
            switch displayMessage {
                case .requestPresentPassport:
                    return "Hold your iPhone near an NFC enabled passport."
                default:
                    // Return nil for all other messages so we use the provided default
                    return nil
            }
        }, completed: { (passport, error) in
            if let passport = passport {
                // All good, we got a passport
                
                if settings.savePassportOnScan {
                    // Save passport
                    let dict = passport.dumpPassportData(selectedDataGroups: DataGroupId.allCases, includeActiveAuthenticationData: true)
                    if let data = try? JSONSerialization.data(withJSONObject: dict, options: .prettyPrinted) {
            
                        let savedPath = FileManager.cachesFolder.appendingPathComponent("\(passport.documentNumber).json")
                                            
                        try? data.write(to: savedPath, options: .completeFileProtection)
                    }
                }
                
                DispatchQueue.main.async {
                    self.settings.passport = passport
                    self.showDetails = true
                }

            } else {
                self.alertTitle = "Oops"
                self.alertTitle = "\(error?.localizedDescription ?? "Unknown error")"
                self.showingAlert = true
            }
        })
    }
}

//MARK: PreviewProvider
#if DEBUG
struct ContentView_Previews : PreviewProvider {

    static var previews: some View {
        let settings = SettingsStore()
        
        return Group {
            MainView()
                .environmentObject(settings)
                .environment( \.colorScheme, .light)
            MainView()
                .environmentObject(settings)
                .environment( \.colorScheme, .dark)
        }
    }
}
#endif



