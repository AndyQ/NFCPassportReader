//
//  MainView.swift
//  NFCPassportReaderApp
//
//  Created by Andy Qua on 04/06/2019.
//  Copyright © 2019 Andy Qua. All rights reserved.
//

import SwiftUI
import OSLog
import Combine
import NFCPassportReader
import UniformTypeIdentifiers
import MRZParser

let appLogging = Logger(subsystem: Bundle.main.bundleIdentifier!, category: "app")


struct MainView : View {
    @EnvironmentObject var settings: SettingsStore
    @EnvironmentObject var trace: TraceStore
    @Environment(\.colorScheme) var colorScheme

    @State private var showingAlert = false
    @State private var showingSheet = false
    @State private var showDetails = false
    @State private var alertTitle : String = ""
    @State private var alertMessage : String = ""
    @State private var showSettings : Bool = false
    @State private var showScanMRZ : Bool = false
    @State private var showSavedPassports : Bool = false
    @State private var gettingLogs : Bool = false
    @State private var showTrace : Bool = false
    @State private var showPassportSim : Bool = false

    @State var page = 0
    
    @State var bgColor = Color( UIColor.systemBackground )
    
    private let passportReader = PassportReader()

    var body: some View {
        NavigationView {
            ZStack {
                NavigationLink( destination: SettingsView(), isActive: $showSettings) { Text("") }
                NavigationLink( destination: PassportView(), isActive: $showDetails) { Text("") }
                NavigationLink( destination: StoredPassportView(), isActive: $showSavedPassports) { Text("") }
                NavigationLink( destination: TraceView(), isActive: $showTrace) { Text("") }
                NavigationLink( destination: MRZScanner(completionHandler: { mrz in
                    
                    if let (docNr, dob, doe) = parse( mrz:mrz ) {
                        settings.passportNumber = docNr
                        settings.dateOfBirth = dob
                        settings.dateOfExpiry = doe
                    }
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
                
                if gettingLogs {
                    VStack {
                        VStack(alignment:.center) {
                            Text( "Retrieving logs....." )
                                .font(.title)
                                .frame(maxWidth:.infinity, maxHeight:150)
                        }
                        .shadow(radius: 10)
                        .background(.white)
                        .cornerRadius(20) /// make the background rounded
                        .overlay( /// apply a rounded border
                            RoundedRectangle(cornerRadius: 20)
                                .stroke(.gray, lineWidth: 2)
                        )
                        .padding()
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
                        Button(action: {self.showSavedPassports.toggle()}) {
                            Label("Show saved passports", systemImage: "doc")
                        }
                        #if targetEnvironment(simulator)
                        Button(action: { showPassportSim = true }) {
                            Label("Read from PassportSim", systemImage: "network")
                        }
                        #endif
                    } label: {
                        Image(systemName: "gear")
                            .foregroundColor(Color.secondary)
                    }
                }
            }
            .sheet(isPresented: $showPassportSim) {
                PassportSimReadView(passportReader: passportReader) { passport in
                    self.settings.passport = passport
                    self.showDetails = true
                }
                .environmentObject(settings)
                .environmentObject(trace)
                .onAppear {
                    configureLogging()
                    if let masterListURL = Bundle.main.url(forResource: "masterList", withExtension: ".pem") {
                        passportReader.setMasterListURL(masterListURL)
                    }
                }
            }
            .onAppear(perform: autoReadFromPassportSim)
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
    func configureLogging() {
        var configuration = passportReader.logConfiguration
        configuration.minimumLevel = PassportLogLevel(rawValue: settings.logLevel) ?? .debug
        configuration.includeSensitiveDataInHandler = settings.includeSensitiveTraceData
        passportReader.logConfiguration = configuration
        passportReader.logHandler = PassportLogHandlers.combine(PassportLogHandlers.osLog(), trace.handler)
    }

    
    var isValid : Bool {
        return settings.passportNumber.count >= 8
    }

    func parse( mrz:String ) -> (String, Date, Date)? {
        print( "mrz = \(mrz)")
        
        let parser = MRZParser(isOCRCorrectionEnabled: true)
        if let result = parser.parse(mrzString: mrz),
           let docNr = result.documentNumber,
           let dob = result.birthdate,
           let doe = result.expiryDate {
            
            return (docNr, dob, doe)
        }
        return nil
    }
}

// MARK: Action Functions
extension MainView {

    /// Simulator only: launch with `-passportSimAutoRead <preset>` to read that PassportSim preset from
    /// the APDU server on 127.0.0.1:9077 at start-up and open the Trace view.
    func autoReadFromPassportSim() {
        #if targetEnvironment(simulator)
        guard let preset = UserDefaults.standard.string(forKey: "passportSimAutoRead"), !preset.isEmpty else { return }
        UserDefaults.standard.removeObject(forKey: "passportSimAutoRead")
        trace.clear()
        configureLogging()
        if let masterListURL = Bundle.main.url(forResource: "masterList", withExtension: ".pem") {
            passportReader.setMasterListURL(masterListURL)
        }
        Task {
            do {
                let tag = try PassportSimTag(host: "127.0.0.1", port: 9077)
                let mrzKey = try tag.selectProfile(preset)
                let passport = try await passportReader.readPassport(tag: tag, mrzKey: mrzKey)
                await MainActor.run { self.settings.passport = passport }
            } catch {
                appLogging.error("PassportSim auto read failed: \(error.localizedDescription)")
            }
            await MainActor.run { self.showTrace = true }
        }
        #endif
    }

    func shareLogs() {
        gettingLogs = true
        Task {
            hideKeyboard()
            PassportUtils.shareLogs()
            gettingLogs = false
        }
    }

    func scanPassport( ) {
        lastPassportScanTime = Date.now

        hideKeyboard()
        self.showDetails = false
        trace.clear()
        
        let df = DateFormatter()
        df.timeZone = TimeZone(secondsFromGMT: 0)
        df.dateFormat = "yyMMdd"
        
        let pptNr = settings.passportNumber
        let dob = df.string(from:settings.dateOfBirth)
        let doe = df.string(from:settings.dateOfExpiry)
        let useExtendedMode = settings.useExtendedMode
        let skipPACE = settings.skipPACE
        let skipCA = settings.skipCA

        let passportUtils = PassportUtils()
        let mrzKey = passportUtils.getMRZKey( passportNumber: pptNr, dateOfBirth: dob, dateOfExpiry: doe)

        // Record an APDU trace for the Trace view
        configureLogging()

        // Set the masterListURL on the Passport Reader to allow auto passport verification
        let masterListURL = Bundle.main.url(forResource: "masterList", withExtension: ".pem")!
        passportReader.setMasterListURL( masterListURL )
        
        // Set whether to use the new Passive Authentication verification method (default true) or the old OpenSSL CMS verifiction
        passportReader.passiveAuthenticationUsesOpenSSL = !settings.useNewVerificationMethod
        
        // If we want to read only specific data groups we can using:
//        let dataGroups : [DataGroupId] = [.COM, .SOD, .DG1, .DG2, .DG7, .DG11, .DG12, .DG14, .DG15]
//        passportReader.readPassport(mrzKey: mrzKey, tags:dataGroups, completed: { (passport, error) in
        
        appLogging.error( "Using version \(UIApplication.version)" )
        
        Task {
            let customMessageHandler : (NFCViewDisplayMessage)->String? = { (displayMessage) in
                switch displayMessage {
                    case .requestPresentPassport:
                        return "Hold your iPhone near an NFC enabled passport."
                    default:
                        // Return nil for all other messages so we use the provided default
                        return nil
                }
            }
            
            do {
                let passport = try await passportReader.readPassport( mrzKey: mrzKey, skipCA: skipCA, skipPACE: skipPACE, useExtendedMode: useExtendedMode, customDisplayMessage:customMessageHandler)
                
                if let _ = passport.faceImageInfo {
                    print( "Got face Image details")
                }
                
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
            } catch {
                self.alertTitle = "Oops"
                self.alertTitle = error.localizedDescription
                self.showingAlert = true

            }
        }
    }
}

//MARK: PreviewProvider
#if DEBUG
struct ContentView_Previews : PreviewProvider {

    static var previews: some View {
        let settings = SettingsStore()
        let trace = TraceStore()

        return Group {
            MainView()
                .environmentObject(settings)
                .environmentObject(trace)
                .environment( \.colorScheme, .light)
            MainView()
                .environmentObject(settings)
                .environmentObject(trace)
                .environment( \.colorScheme, .dark)
        }
    }
}
#endif
