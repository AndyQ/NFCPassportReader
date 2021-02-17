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
    @State private var showImport : Bool = false

    @State var page = 0
    
    @State var bgColor = Color( UIColor.systemBackground )
    
    private let passportReader = PassportReader()

    var body: some View {
        NavigationView {
            ZStack {
                NavigationLink( destination: SettingsView(), isActive: $showSettings) { Text("") }
                NavigationLink( destination: PassportView(), isActive: $showDetails) { Text("") }

                VStack {
                    MRZEntryView()
                    
                    Button(action: {
                        self.showImport.toggle()
                    }) {
                        Text("Import Passport")
                            .font(.largeTitle)
                            .foregroundColor(.secondary)
                    }
                    .padding(.bottom, 20)

                    Button(action: {
                        self.scanPassport()
                    }) {
                        Text("Scan Passport")
                            .font(.largeTitle)
                            .foregroundColor(isValid ? .secondary : Color.secondary.opacity(0.25))
                    }
                    .disabled( !isValid )

                    Spacer()
                    HStack {
                        Text( "Version - \(UIApplication.version)" )
                            .font(.footnote)
                            .padding(.leading)
                        Spacer()
                    }
                }
            }
            .navigationBarTitle("Passport details", displayMode: .automatic)
            .navigationBarItems(trailing:
                Button(action: {showSettings.toggle()}) {
                    Label("", systemImage: "gear")
                        .foregroundColor(Color.secondary)
                        .font(.title2)
            })
            .alert(isPresented: $showingAlert) {
                    Alert(title: Text(alertTitle), message:
                        Text(alertMessage), dismissButton: .default(Text("Got it!")))
            }
            .background(colorScheme == .dark ? Color.black : Color.white)
        }
        .fileImporter(
            isPresented: $showImport, allowedContentTypes: [.json],
            allowsMultipleSelection: false
        ) { result in
            do {
                guard let selectedFile: URL = try result.get().first else { return }
                if selectedFile.startAccessingSecurityScopedResource() {
                    let data = try Data(contentsOf: selectedFile)
                    defer { selectedFile.stopAccessingSecurityScopedResource() }
                    
                    let json = try JSONSerialization.jsonObject(with: data, options: [])
                    if let arr = json as? [String:String] {
                        hideKeyboard()
                        Log.logLevel = settings.logLevel
                        Log.storeLogs = settings.shouldCaptureLogs
                        Log.clearStoredLogs()
                        

                        let passport = NFCPassportModel(from: arr)
                        
                        let masterListURL = Bundle.main.url(forResource: "masterList", withExtension: ".pem")!
                        
                        passport.verifyPassport(masterListURL: masterListURL)
                        
                        self.settings.passport = passport
                        self.showDetails = true
                    }

                } else {
                    print("Unable to read file contents - denied")
                }
            } catch {
                // Handle failure.
                print("Unable to read file contents")
                print(error.localizedDescription)
            }
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

    func scanPassport( ) {
        hideKeyboard()
        self.showDetails = false
        
        let df = DateFormatter()
        df.dateFormat = "YYMMdd"
        
        let pptNr = settings.passportNumber
        let dob = df.string(from:settings.dateOfBirth)
        let doe = df.string(from:settings.dateOfExpiry)

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
        
        // This is also how you can override the default messages displayed by the NFC View Controller
        passportReader.readPassport(mrzKey: mrzKey, customDisplayMessage: { (displayMessage) in
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



