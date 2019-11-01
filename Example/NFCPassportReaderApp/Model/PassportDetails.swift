//
//  PassportDetails.swift
//  SwiftUITest
//
//  Created by Andy Qua on 30/06/2019.
//  Copyright © 2019 Andy Qua. All rights reserved.
//

import SwiftUI
import Combine
import NFCPassportReader

class PassportDetails : ObservableObject {
    @Published var passportNumber : String = UserDefaults.standard.string(forKey:"passportNumber" ) ?? ""
    @Published var dateOfBirth: String = UserDefaults.standard.string(forKey:"dateOfBirth" ) ?? ""
    @Published var expiryDate: String = UserDefaults.standard.string(forKey:"expiryDate" ) ?? ""
    @Published var passport : NFCPassportModel?
    
    var isValid : Bool {
        return passportNumber.count >= 8 && dateOfBirth.count == 6 && expiryDate.count == 6
    }
    
    func getMRZKey() -> String {
        let d = UserDefaults.standard
        d.set(passportNumber, forKey: "passportNumber")
        d.set(dateOfBirth, forKey: "dateOfBirth")
        d.set(expiryDate, forKey: "expiryDate")
        
        // Calculate checksums
        let passportNrChksum = calcCheckSum(passportNumber)
        let dateOfBirthChksum = calcCheckSum(dateOfBirth)
        let expiryDateChksum = calcCheckSum(expiryDate)
        
        let mrzKey = "\(passportNumber)\(passportNrChksum)\(dateOfBirth)\(dateOfBirthChksum)\(expiryDate)\(expiryDateChksum)"
        
        return mrzKey
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
}

