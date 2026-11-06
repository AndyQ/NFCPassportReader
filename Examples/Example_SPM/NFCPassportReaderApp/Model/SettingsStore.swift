//
//  SettingsStore.swift
//  NFCPassportReaderApp
//
//  Created by Andy Qua on 10/02/2021.
//  Copyright © 2021 Andy Qua. All rights reserved.
//

import SwiftUI
import Combine
import NFCPassportReader

final class SettingsStore: ObservableObject {

    private enum Keys {
        static let captureLog = "captureLog"
        static let logLevel = "logLevel"
        static let includeSensitiveTraceData = "includeSensitiveTraceData"
        static let useNewVerification = "useNewVerification"
        static let savePassportOnScan = "savePassportOnScan"
        static let useExtendedMode = "useExtendedMode"
        static let skipPACE = "skipPACE"
        static let skipCA = "skipCA"
        static let passportNumber = "passportNumber"
        static let dateOfBirth = "dateOfBirth"
        static let dateOfExpiry = "dateOfExpiry"
    }
    
    private var cancellable: Cancellable?
    private let defaults: UserDefaults
    private var observedSettings: [String: AnyHashable] = [:]

    private static let observedSettingKeys = [
        Keys.captureLog,
        Keys.logLevel,
        Keys.includeSensitiveTraceData,
        Keys.useNewVerification,
        Keys.savePassportOnScan,
        Keys.useExtendedMode,
        Keys.skipPACE,
        Keys.skipCA,
        Keys.passportNumber,
        Keys.dateOfBirth,
        Keys.dateOfExpiry
    ]
    
    let objectWillChange = PassthroughSubject<Void, Never>()
    
    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        

        defaults.register(defaults: [
            Keys.captureLog: true,
            Keys.logLevel: PassportLogLevel.debug.rawValue,
            Keys.includeSensitiveTraceData: false,
            Keys.useNewVerification: true,
            Keys.savePassportOnScan: false,
            Keys.useExtendedMode: false,
            Keys.skipPACE: false,
            Keys.skipCA: false,
            Keys.passportNumber: "",
            Keys.dateOfBirth: Date().timeIntervalSince1970,
            Keys.dateOfExpiry: Date().timeIntervalSince1970,
        ])

        // Ignore unrelated UserDefaults changes, such as the trace view's AppStorage filters.
        observedSettings = Self.settingsValues(from: defaults)
        cancellable = NotificationCenter.default
            .publisher(for: UserDefaults.didChangeNotification)
            .receive(on: DispatchQueue.main)
            .sink { [weak self] _ in
                self?.publishChangesIfSettingsChanged()
            }
    }
    
    func reset() {
        if let bundleID = Bundle.main.bundleIdentifier {
            UserDefaults.standard.removePersistentDomain(forName: bundleID)
        }
    }
    
    var shouldCaptureLogs: Bool {
        set { defaults.set(newValue, forKey: Keys.captureLog) }
        get { defaults.bool(forKey: Keys.captureLog) }
    }

    var logLevel: Int {
        set { defaults.set(newValue, forKey: Keys.logLevel) }
        get { defaults.integer(forKey: Keys.logLevel) }
    }

    var includeSensitiveTraceData: Bool {
        set { defaults.set(newValue, forKey: Keys.includeSensitiveTraceData) }
        get { defaults.bool(forKey: Keys.includeSensitiveTraceData) }
    }
    
    var useNewVerificationMethod: Bool {
        set { defaults.set(newValue, forKey: Keys.useNewVerification) }
        get { defaults.bool(forKey: Keys.useNewVerification) }
    }
    
    var savePassportOnScan: Bool {
        set { defaults.set(newValue, forKey: Keys.savePassportOnScan) }
        get { defaults.bool(forKey: Keys.savePassportOnScan) }
    }

    var useExtendedMode: Bool {
        set { defaults.set(newValue, forKey: Keys.useExtendedMode) }
        get { defaults.bool(forKey: Keys.useExtendedMode) }
    }

    var skipPACE: Bool {
        set { defaults.set(newValue, forKey: Keys.skipPACE) }
        get { defaults.bool(forKey: Keys.skipPACE) }
    }

    var skipCA: Bool {
        set { defaults.set(newValue, forKey: Keys.skipCA) }
        get { defaults.bool(forKey: Keys.skipCA) }
    }
    
    var passportNumber: String {
        set { defaults.set(newValue, forKey: Keys.passportNumber) }
        get { defaults.string(forKey: Keys.passportNumber) ?? "" }
    }
    
    var dateOfBirth: Date {
        set {
            defaults.set(newValue.timeIntervalSince1970, forKey: Keys.dateOfBirth)
        }
        get {
            let d = Date(timeIntervalSince1970: defaults.double(forKey: Keys.dateOfBirth))
            return d
        }
    }
    
    var dateOfExpiry: Date {
        set {
            defaults.set(newValue.timeIntervalSince1970, forKey: Keys.dateOfExpiry) }
        get {
            let d = Date(timeIntervalSince1970: defaults.double(forKey: Keys.dateOfExpiry))
            return d
        }
    }

    private func publishChangesIfSettingsChanged() {
        let currentSettings = Self.settingsValues(from: defaults)
        guard currentSettings != observedSettings else { return }
        observedSettings = currentSettings
        objectWillChange.send()
    }

    private static func settingsValues(from defaults: UserDefaults) -> [String: AnyHashable] {
        var values: [String: AnyHashable] = [:]
        for key in observedSettingKeys {
            if let value = defaults.object(forKey: key) as? AnyHashable {
                values[key] = value
            }
        }
        return values
    }
    
    @Published var passport : NFCPassportModel?
}
