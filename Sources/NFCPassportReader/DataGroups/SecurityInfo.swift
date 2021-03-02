//
//  SecurityInfo.swift
//  NFCPassportReader
//
//  Created by Andy Qua on 25/02/2021.
//

import Foundation
import OpenSSL

@available(iOS 13, macOS 10.15, *)
public class SecurityInfo {
    static let ID_AA_OID = "2.23.136.1.1.5"
    
    // Chip Authentication Public Key OIDS
    static let ID_PK_DH_OID = "0.4.0.127.0.7.2.2.1.1"
    static let ID_PK_ECDH_OID = "0.4.0.127.0.7.2.2.1.2"
    
    // Chip Authentication OIDS
    static let ID_CA_DH_3DES_CBC_CBC_OID = "0.4.0.127.0.7.2.2.3.1.1"
    static let ID_CA_ECDH_3DES_CBC_CBC_OID = "0.4.0.127.0.7.2.2.3.2.1"
    static let ID_CA_DH_AES_CBC_CMAC_128_OID = "0.4.0.127.0.7.2.2.3.1.2"
    static let ID_CA_DH_AES_CBC_CMAC_192_OID = "0.4.0.127.0.7.2.2.3.1.3"
    static let ID_CA_DH_AES_CBC_CMAC_256_OID = "0.4.0.127.0.7.2.2.3.1.4"
    static let ID_CA_ECDH_AES_CBC_CMAC_128_OID = "0.4.0.127.0.7.2.2.3.2.2"
    static let ID_CA_ECDH_AES_CBC_CMAC_192_OID = "0.4.0.127.0.7.2.2.3.2.3"
    static let ID_CA_ECDH_AES_CBC_CMAC_256_OID = "0.4.0.127.0.7.2.2.3.2.4"
    
    public func getObjectIdentifier() -> String {
        preconditionFailure("This method must be overridden")
    }
    
    public func getProtocolOIDString() -> String {
        preconditionFailure("This method must be overridden")
    }
    
    static func getInstance( object : ASN1Item, body: [UInt8] ) -> SecurityInfo? {
        let oid = object.getChild(0)?.value ?? ""
        let requiredData = object.getChild(1)!
        var optionalData : ASN1Item? = nil
        if (object.getNumberOfChildren() == 3) {
            optionalData = object.getChild(2)
        }
        
        if (ChipAuthenticationPublicKeyInfo.checkRequiredIdentifier(oid)) {
            
            let keyData : [UInt8] = [UInt8](body[requiredData.pos ..< requiredData.pos+requiredData.headerLen+requiredData.length])
            
            var subjectPublicKeyInfo : OpaquePointer? = nil
            let _ = keyData.withUnsafeBytes { (ptr) in
                var newPtr = ptr.baseAddress?.assumingMemoryBound(to: UInt8.self)
                
                subjectPublicKeyInfo = d2i_PUBKEY(nil, &newPtr, keyData.count)
            }
            
            if let subjectPublicKeyInfo = subjectPublicKeyInfo {
                                
                if optionalData == nil {
                    return ChipAuthenticationPublicKeyInfo(oid:oid, pubKey:subjectPublicKeyInfo);
                } else {
                    let keyId = Int(optionalData!.value)
                    return ChipAuthenticationPublicKeyInfo(oid:oid, pubKey:subjectPublicKeyInfo, keyId: keyId);
                }
                
            }
        } else if (ChipAuthenticationInfo.checkRequiredIdentifier(oid)) {
            let version = Int(requiredData.value) ?? -1
            if (optionalData == nil) {
                return ChipAuthenticationInfo(oid: oid, version: version);
            } else {
                let keyId = Int(optionalData!.value)
                return ChipAuthenticationInfo(oid: oid, version: version, keyId: keyId);
            }
        }
        
        return nil
    }
}
