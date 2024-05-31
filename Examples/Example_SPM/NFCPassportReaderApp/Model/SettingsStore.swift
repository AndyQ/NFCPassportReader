//
//  SettingsStore.swift
//  NFCPassportReaderApp
//
//  Created by Andy Qua on 10/02/2021.
//  Copyright © 2021 Andy Qua. All rights reserved.
//

import SwiftUI
import NFCPassportReader

final class SettingsStore: ObservableObject {

    private enum Keys : CaseIterable {
        static let captureLog = "captureLog"
        static let logLevel = "logLevel"
        static let useNewVerification = "useNewVerification"
        static let savePassportOnScan = "savePassportOnScan"
        static let passportNumber = "passportNumber"
        static let dateOfBirth = "dateOfBirth"
        static let dateOfExpiry = "dateOfExpiry"
        
        static let skipSecureElements = "skipSecureElements"
        static let skipCA = "skipCA"
        static let skipPACE = "skipPACE"
        static let useExtendedReads = "useExtendedReads"
        static let usePACEPolling = "usePACEPolling"
        
    }
    
//    private let cancellable: Cancellable
//    private let defaults: UserDefaults
//    
//    let objectWillChange = PassthroughSubject<Void, Never>()
    
    

/*
    init(defaults: UserDefaults = .standard) {
//        self.defaults = defaults
        

        defaults.register(defaults: [
            Keys.captureLog: true,
            Keys.logLevel: 1,
            Keys.useNewVerification: true,
            Keys.skipSecureElements: false  ,
            Keys.skipCA: false,
            Keys.skipPACE: false,
            Keys.useExtendedReads: false,
            Keys.usePACEPolling: false,
            Keys.savePassportOnScan: false,
            Keys.passportNumber: "",
            Keys.dateOfBirth: Date().timeIntervalSince1970,
            Keys.dateOfExpiry: Date().timeIntervalSince1970,
        ])
        
//        cancellable = NotificationCenter.default
//            .publisher(for: UserDefaults.didChangeNotification)
//            .map { _ in () }
//            .subscribe(objectWillChange)
    }
*/
    func reset() {
        if let bundleID = Bundle.main.bundleIdentifier {
            UserDefaults.standard.removePersistentDomain(forName: bundleID)
        }
    }
    
    @AppStorage(Keys.captureLog) var shouldCaptureLogs: Bool = true
    @AppStorage(Keys.useNewVerification) var useNewVerificationMethod: Bool = true
    @AppStorage(Keys.savePassportOnScan) var savePassportOnScan: Bool = true
    @AppStorage(Keys.passportNumber) var passportNumber: String = ""

    @AppStorage(Keys.skipSecureElements) var skipSecureElements: Bool = true
    @AppStorage(Keys.skipCA) var skipCA: Bool = false
    @AppStorage(Keys.skipPACE) var skipPACE: Bool = false
    @AppStorage(Keys.useExtendedReads) var useExtendedReads: Bool = false
    @AppStorage(Keys.usePACEPolling) var usePACEPolling: Bool = false

/*
    var shouldCaptureLogs: Bool {
        set { defaults.set(newValue, forKey: Keys.captureLog) }
        get { defaults.bool(forKey: Keys.captureLog) }
    }
    
    var useNewVerificationMethod: Bool {
        set { defaults.set(newValue, forKey: Keys.useNewVerification) }
        get { defaults.bool(forKey: Keys.useNewVerification) }
    }
    
    var savePassportOnScan: Bool {
        set { defaults.set(newValue, forKey: Keys.savePassportOnScan) }
        get { defaults.bool(forKey: Keys.savePassportOnScan) }
    }
    
    var passportNumber: String {
        set { defaults.set(newValue, forKey: Keys.passportNumber) }
        get { defaults.string(forKey: Keys.passportNumber) ?? "" }
    }
*/
    @AppStorage(Keys.dateOfBirth) var storedDateOfBirth = Date.now.timeIntervalSinceReferenceDate
    var dateOfBirth: Date {
        set {storedDateOfBirth = newValue.timeIntervalSinceReferenceDate}
        get {return Date(timeIntervalSinceReferenceDate: storedDateOfBirth)}
    }
    
    @AppStorage("dateOfExpiry") var storedDateOfExpiry = Date.now.timeIntervalSinceReferenceDate
    var dateOfExpiry: Date {
        set {storedDateOfExpiry = newValue.timeIntervalSinceReferenceDate}
        get {return Date(timeIntervalSinceReferenceDate: storedDateOfExpiry)}
    }
    

//    var dateOfBirth: Date {
//        set {
//            defaults.set(newValue.timeIntervalSince1970, forKey: Keys.dateOfBirth)
//        }
//        get {
//            let d = Date(timeIntervalSince1970: defaults.double(forKey: Keys.dateOfBirth))
//            return d
//        }
//    }
//    
//    var dateOfExpiry: Date {
//        set {
//            defaults.set(newValue.timeIntervalSince1970, forKey: Keys.dateOfExpiry) }
//        get {
//            let d = Date(timeIntervalSince1970: defaults.double(forKey: Keys.dateOfExpiry))
//            return d
//        }
//    }
    
    @Published var passport : NFCPassportModel?
}
