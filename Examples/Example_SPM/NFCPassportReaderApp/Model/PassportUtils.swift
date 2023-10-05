//
//  PassportUtils.swift
//  NFCPassportReaderApp
//
//  Created by Andy Qua on 30/06/2019.
//  Copyright © 2019 Andy Qua. All rights reserved.
//

import UIKit
import NFCPassportReader
import OSLog

var lastPassportScanTime : Date = Date().addingTimeInterval(-3600)

class PassportUtils {
    
    func getMRZKey(passportNumber: String, dateOfBirth: String, dateOfExpiry: String ) -> String {
        
        // Pad fields if necessary
        let pptNr = pad( passportNumber, fieldLength:9)
        let dob = pad( dateOfBirth, fieldLength:6)
        let exp = pad( dateOfExpiry, fieldLength:6)
        
        // Calculate checksums
        let passportNrChksum = calcCheckSum(pptNr)
        let dateOfBirthChksum = calcCheckSum(dob)
        let expiryDateChksum = calcCheckSum(exp)

        let mrzKey = "\(pptNr)\(passportNrChksum)\(dob)\(dateOfBirthChksum)\(exp)\(expiryDateChksum)"
        
        return mrzKey
    }
    
    func pad( _ value : String, fieldLength:Int ) -> String {
        // Pad out field lengths with < if they are too short
        let paddedValue = (value + String(repeating: "<", count: fieldLength)).prefix(fieldLength)
        return String(paddedValue)
    }
    
    func calcCheckSum( _ checkString : String ) -> Int {
        let characterDict  = ["0" : "0", "1" : "1", "2" : "2", "3" : "3", "4" : "4", "5" : "5", "6" : "6", "7" : "7", "8" : "8", "9" : "9", "<" : "0", " " : "0", "A" : "10", "B" : "11", "C" : "12", "D" : "13", "E" : "14", "F" : "15", "G" : "16", "H" : "17", "I" : "18", "J" : "19", "K" : "20", "L" : "21", "M" : "22", "N" : "23", "O" : "24", "P" : "25", "Q" : "26", "R" : "27", "S" : "28","T" : "29", "U" : "30", "V" : "31", "W" : "32", "X" : "33", "Y" : "34", "Z" : "35"]
        
        var sum = 0
        var m = 0
        let multipliers : [Int] = [7, 3, 1]
        for c in checkString {
            guard let lookup = characterDict["\(c)"],
                let number = Int(lookup) else { return 0 }
            let product = number * multipliers[m]
            sum += product
            m = (m+1) % 3
        }
        
        return (sum % 10)
    }
    
    static  func shareLogs() {
        do {
            var arr = (try? getLogEntries()) ?? []
            arr.insert("LogLevel,Date,Subsystem,Category,Message", at: 0)

            let csv = arr.joined(separator:"\n")
            if let data = csv.data(using: .utf8) {
                
                let temporaryURL = URL(fileURLWithPath: NSTemporaryDirectory() + "passportreader_log.csv")
                try data.write(to: temporaryURL)
                
                let av = UIActivityViewController(activityItems: [temporaryURL], applicationActivities: nil)
                let keyWindow = UIApplication.shared.connectedScenes
                    .filter({$0.activationState == .foregroundActive})
                    .map({$0 as? UIWindowScene})
                    .compactMap({$0})
                    .first?.windows
                    .filter({$0.isKeyWindow}).first
                
                keyWindow?.rootViewController?.present(av, animated: true, completion: nil)
            }
        } catch {
            print( "ERROR - \(error)" )
        }
    }

    static func getLogEntries() throws -> [String] {
        let subsystem = Bundle.main.bundleIdentifier!
        
        print( "Getting logs since \(lastPassportScanTime)")
        
        let logStore = try OSLogStore(scope: .currentProcessIdentifier)
        let lastScanTime = logStore.position(date: lastPassportScanTime)
        let allEntries = try logStore.getEntries(at: lastScanTime)
        
        // FB8518539: Using NSPredicate to filter the subsystem doesn't seem to work.
        return allEntries
            .compactMap { $0 as? OSLogEntryLog }
            .filter { $0.subsystem == subsystem && $0.date > lastPassportScanTime }
            .map { "\($0.level.rawValue),\($0.date),\($0.subsystem),\($0.category),\"\($0.composedMessage)\"" }
    }
}

