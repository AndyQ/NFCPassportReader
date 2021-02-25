//
//  ChipAuthenticationPublicKeyInfo.swift
//  NFCPassportReader
//
//  Created by Andy Qua on 25/02/2021.
//

import Foundation

@available(iOS 13, macOS 10.15, *)
public class ChipAuthenticationPublicKeyInfo : SecurityInfo {
    var oid : String
    var pubKey : OpaquePointer
    var keyId : Int?
    
    
    static func checkRequiredIdentifier(_ oid : String) -> Bool {
        return ID_PK_DH_OID == oid
            || ID_PK_ECDH_OID == oid
    }
    
    init(oid:String, pubKey:OpaquePointer, keyId: Int? = nil) {
        self.oid = oid
        self.pubKey = pubKey
        self.keyId = keyId
    }
}
