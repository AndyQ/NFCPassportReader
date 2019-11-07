//
//  PassiveAuthentication.swift
//  NFCPassportReaderApp
//
//  Created by Andy Qua on 27/06/2019.
//  Copyright © 2019 Andy Qua. All rights reserved.
//

import Foundation
import OpenSSL


public enum PassiveAuthenticationError: Error {
    case UnableToParseSODHashes(String)
    case InvalidDataGroupHash(String)
    case SODMissing(String)
}


extension PassiveAuthenticationError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .UnableToParseSODHashes(let reason):
            return NSLocalizedString("Unable to parse the SOD Datagroup hashes. \(reason)", comment: "UnableToParseSODHashes")
        case .InvalidDataGroupHash(let reason):
            return NSLocalizedString("DataGroup hash not present or didn't match  \(reason)!", comment: "InvalidDataGroupHash")
        case .SODMissing(let reason):
            return NSLocalizedString("DataGroup SOD not present or not read  \(reason)!", comment: "SODMissing")

        }
    }
}
