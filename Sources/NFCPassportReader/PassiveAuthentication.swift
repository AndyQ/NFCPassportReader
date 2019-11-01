//
//  PassiveAuthentication.swift
//  NFCPassportReaderApp
//
//  Created by Andy Qua on 27/06/2019.
//  Copyright © 2019 Andy Qua. All rights reserved.
//

import Foundation
import OpenSSL

private extension UInt8 {
    var hexString: String {
        let string = String(self, radix: 16)
        return (self < 16 ? "0" + string : string)
    }
}


public enum PassiveAuthenticationError: Error {
    case UnableToGetX509CertificateFromPKCS7(String)
    case UnableToVerifyX509CertificateForSOD(String)
    case UnableToParseSODHashes(String)
    case UnableToGetSignedDataFromPKCS7(String)
    case InvalidDataGroupHash(String)
    case SODMissing(String)
}

extension PassiveAuthenticationError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .UnableToGetX509CertificateFromPKCS7(let reason):
            return NSLocalizedString("Unable to read the SOD PKCS7 Certificate. \(reason)", comment: "UnableToGetPKCS7CertificateForSOD")
        case .UnableToVerifyX509CertificateForSOD(let reason):
            return NSLocalizedString("Unable to verify the SOD X509 certificate. \(reason)", comment: "UnableToVerifyX509CertificateForSOD")
        case .UnableToParseSODHashes(let reason):
            return NSLocalizedString("Unable to parse the SOD Datagroup hashes. \(reason)", comment: "UnableToParseSODHashes")
        case .UnableToGetSignedDataFromPKCS7(let reason):
            return NSLocalizedString("Unable to parse the SOD Datagroup hashes. \(reason)", comment: "UnableToGetSignedDataFromPKCS7")
        case .InvalidDataGroupHash(let reason):
            return NSLocalizedString("DataGroup hash not present or didn't match  \(reason)!", comment: "InvalidDataGroupHash")
        case .SODMissing(let reason):
            return NSLocalizedString("DataGroup SOD not present or not read  \(reason)!", comment: "SODMissing")

        }
    }
}
