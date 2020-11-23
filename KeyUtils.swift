//
//  KeyUtils.swift
//  NFCPassportReader
//
//  Created by 111542 on 11/23/20.
//

import Foundation


public class NFCKeyUtils {

    private static var _instance: NFCKeyUtils?

    public static var instance: NFCKeyUtils {
        get {
            if let instance = _instance {
                return instance
            } else {
                let _instance = NFCKeyUtils()
                self._instance = _instance
                return _instance
            }
        }
    }
    
    private init() { }


    /// This function create mrz key
    /// @param idNumber,birhData,cardExpriyDate: a string of data
    /// @return: A String MRZ key
    public func getMRZKey(idNumber: String, birthDate: String, cardExpiryDate: String) -> String {

        // Calculate checksums
        let passportNrChksum = calcCheckSum(idNumber)
        let dateOfBirthChksum = calcCheckSum(birthDate)
        let expiryDateChksum = calcCheckSum(cardExpiryDate)

        let mrzKey = "\(idNumber)\(passportNrChksum)\(birthDate)\(dateOfBirthChksum)\(cardExpiryDate)\(expiryDateChksum)"

        return mrzKey
    }


    private func calcCheckSum(_ checkString: String) -> Int {
        let characterDict = ["0": "0", "1": "1", "2": "2", "3": "3", "4": "4", "5": "5", "6": "6", "7": "7", "8": "8", "9": "9", "<": "0", " ": "0", "A": "10", "B": "11", "C": "12", "D": "13", "E": "14", "F": "15", "G": "16", "H": "17", "I": "18", "J": "19", "K": "20", "L": "21", "M": "22", "N": "23", "O": "24", "P": "25", "Q": "26", "R": "27", "S": "28", "T": "29", "U": "30", "V": "31", "W": "32", "X": "33", "Y": "34", "Z": "35"]

        var sum = 0
        var m = 0
        let multipliers: [Int] = [7, 3, 1]
        for c in checkString {
            guard let lookup = characterDict["\(c)"],
                let number = Int(lookup) else { return 0 }
            let product = number * multipliers[m]
            sum += product
            m = (m + 1) % 3
        }

        return (sum % 10)
    }
}
