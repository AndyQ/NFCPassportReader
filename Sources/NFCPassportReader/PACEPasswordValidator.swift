//
//  PACEPasswordValidator.swift
//  NFCPassportReader
//
//  Created by Manwel Bugeja Personal on 24/04/2025.
//


class PACEPasswordValidator {
    static func validate(password: String, type: PACEPasswordType) throws {
        switch type {
            case .mrz:
                // MRZ validation logic if needed
                break
            case .can:
                guard password.count == 6 && password.allSatisfy({ $0.isNumber }) else {
                    throw NFCPassportReaderError.InvalidDataPassed("CAN must be 6 digits")
                }
        }
    }
}
