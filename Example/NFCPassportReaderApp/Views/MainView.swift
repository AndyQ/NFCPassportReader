//
//  ContentView.swift
//  SwiftUITest
//
//  Created by Andy Qua on 04/06/2019.
//  Copyright © 2019 Andy Qua. All rights reserved.
//

import SwiftUI
import Combine
import NFCPassportReader


struct MainView : View {
    @EnvironmentObject var settings: SettingsStore
    @Environment(\.colorScheme) var colorScheme

    @State private var showingAlert = false
    @State private var showingSheet = false
    @State private var showDetails = false
    @State private var alertTitle : String = ""
    @State private var alertMessage : String = ""
    @State private var showSettings : Bool = false
    @State private var showExportPassport : Bool = false
    
    @State var page = 0
    
    @State var bgColor = Color( UIColor.systemBackground )
    
    private let passportReader = PassportReader()

    var body: some View {
        NavigationView {
            ZStack {
                NavigationLink( destination: SettingsView(), isActive: $showSettings) { Text("") }
                NavigationLink( destination: ExportPassportView(), isActive: $showExportPassport) { Text("") }

                VStack {
                    MRZEntryView()

                    Button(action: {
                        self.scanPassport()
                    }) {
                        Text("Scan Passport")
                            .font(.largeTitle)
                        .foregroundColor(isValid ? .secondary : Color.secondary.opacity(0.25))
                    }
                    .disabled( !isValid )
                    
                    Picker(selection: $page, label: Text("View?")) {
                        Text("Passport").tag(0)
                        Text("Details").tag(1)
                    }
                    .pickerStyle(SegmentedPickerStyle())
                    .padding(.bottom,20)
                    .padding([.leading, .trailing])

                    if showDetails {
                        if page == 0 {
                            PassportView(passport:settings.passport!)
                                .frame(width: UIScreen.main.bounds.width-20, height: 220)
                        } else if page == 1 {
                            DetailsView(passport:settings.passport!)
                        }
                    }
                    
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
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Menu {
                        Button(action: {showSettings.toggle()}) {
                            Label("Settings", systemImage: "gear")
                        }
                        if shouldShowImport() {
                            Button(action: {self.importPassport()}) {
                                Label("Import passport", systemImage: "square.and.arrow.down")
                            }
                        }
                        if settings.passport != nil {
                            Button(action: {showExportPassport.toggle()}) {
                                Label("Export passport", systemImage: "square.and.arrow.up")
                            }
                        }
                        Button(action: {shareLogs()}) {
                            Label("Share logs", systemImage: "square.and.arrow.up")
                        }
                    } label: {
                        Image(systemName: "ellipsis.circle")
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
    func shouldShowImport() -> Bool {
        return Bundle.main.path(forResource: "passport", ofType: "json") != nil
    }
    
    var isValid : Bool {
        return settings.passportNumber.count >= 8
    }

}

// MARK: Action Functions
extension MainView {
    func shareLogs() {
        hideKeyboard()
        do {
            let arr = Log.logData
            let data = try JSONSerialization.data(withJSONObject: arr, options: .prettyPrinted)
            
            let temporaryURL = URL(fileURLWithPath: NSTemporaryDirectory() + "passportreader.log")
            try data.write(to: temporaryURL)
            
            let av = UIActivityViewController(activityItems: [temporaryURL], applicationActivities: nil)
            UIApplication.shared.windows.first?.rootViewController?.present(av, animated: true, completion: nil)
        } catch {
            print( "ERROR - \(error)" )
        }

    }
    
    func importPassport() {
        hideKeyboard()
        Log.logLevel = settings.logLevel
        Log.storeLogs = settings.shouldCaptureLogs
        Log.clearStoredLogs()

        do {
            guard let file = Bundle.main.url(forResource: "passport", withExtension: "json"),
                  let data = try? Data(contentsOf: file) else { return }
        
            let json = try JSONSerialization.jsonObject(with: data, options: [])
            if let arr = json as? [String:String] {
                let passport = NFCPassportModel(from: arr)
                
                let masterListURL = Bundle.main.url(forResource: "masterList", withExtension: ".pem")!

                OpenSSLUtils.loadOpenSSL()

                passport.verifyPassport(masterListURL: masterListURL)

                OpenSSLUtils.cleanupOpenSSL()

                self.settings.passport = passport
                self.showDetails = true
            }
        } catch {
            print( "Failed to import passport" )
        }
    }
    
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



