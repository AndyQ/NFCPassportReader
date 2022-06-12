//
//  ChipAuthenticationHandler.swift
//  NFCPassportReader
//
//  Created by Andy Qua on 25/02/2021.
//

import Foundation
import OpenSSL

#if !os(macOS)
import CoreNFC
import CryptoKit

@available(iOS 13, *)
class ChipAuthenticationHandler {
    
    private static let NO_PACE_KEY_REFERENCE : UInt8 = 0x00
    private static let ENC_MODE : UInt8 = 0x1
    private static let MAC_MODE : UInt8 = 0x2
    private static let PACE_MODE : UInt8 = 0x3

    private static let COMMAND_CHAINING_CHUNK_SIZE = 224

    var tagReader : TagReader?
    var gaSegments = [[UInt8]]()
    
    var chipAuthInfos = [Int:ChipAuthenticationInfo]()
    var chipAuthPublicKeyInfos = [ChipAuthenticationPublicKeyInfo]()
    
    var completedHandler : ((Bool)->())?

    var isChipAuthenticationSupported : Bool = false
    
    public init(dg14 : DataGroup14, tagReader: TagReader) {
        self.tagReader = tagReader
        
        for secInfo in dg14.securityInfos {
            if let cai = secInfo as? ChipAuthenticationInfo {
                let keyId = cai.getKeyId()
                chipAuthInfos[keyId] = cai
            } else if let capki = secInfo as? ChipAuthenticationPublicKeyInfo {
                chipAuthPublicKeyInfos.append(capki)
            }
        }
        
        if chipAuthPublicKeyInfos.count > 0 {
            isChipAuthenticationSupported = true
        }
    }

    public func doChipAuthentication( completed: @escaping (Bool)->() ) {
        
        self.completedHandler = completed
        
        Log.info( "Performing Chip Authentication - number of public keys found - \(chipAuthPublicKeyInfos.count)" )
        guard isChipAuthenticationSupported else {
            completed( false )
            return
        }
         
        self.doChipAuthenticationForNextPublicKey()
    }
    
    private func doChipAuthenticationForNextPublicKey( ) {
        // If no more public keys to try then we've failed
        guard chipAuthPublicKeyInfos.count > 0 else {
            completedHandler?( false )
            return
        }
        
        // So it turns out that some passports don't have ChipAuthInfo items.
        // So if we do have a ChipAuthInfo the we take the keyId (if present) and OID from there,
        // BUT if we don't then we will try to infer the OID from the public key
        let chipAuthPublicKeyInfo = chipAuthPublicKeyInfos.removeFirst()
        let keyId = chipAuthPublicKeyInfo.keyId
        let chipAuthInfoOID : String
        if let chipAuthInfo = chipAuthInfos[keyId ?? 0] {
            chipAuthInfoOID = chipAuthInfo.oid
        } else {
            if let oid = inferOID( fromPublicKeyOID:chipAuthPublicKeyInfo.oid) {
                chipAuthInfoOID = oid
            } else {
                self.doChipAuthenticationForNextPublicKey()
                return
            }
        }
        
        do {
            Log.info("Starting Chip Authentication!")
            // For each public key, do chipauth
            try self.doCA( keyId: keyId, encryptionDetailsOID: chipAuthInfoOID, publicKey: chipAuthPublicKeyInfo.pubKey, completed: { [unowned self] (success) in
                
                Log.info("Finished Chip Authentication - success - \(success)")
                if !success {
                    self.doChipAuthenticationForNextPublicKey()
                } else {
                    completedHandler?( true )
                }
            })
        } catch {
            Log.error( "ERROR! - \(error)" )
            doChipAuthenticationForNextPublicKey()

        }
    }
    
    /// Infer OID from public key type - Best guess seems to be to use 3DES_CBC_CBC for both ECDH and DH keys
    /// Apparently works for French passports
    private func inferOID(fromPublicKeyOID: String ) -> String? {
        if fromPublicKeyOID == SecurityInfo.ID_PK_ECDH_OID {
            Log.warning("No ChipAuthenticationInfo - guessing its id-CA-ECDH-3DES-CBC-CBC");
            return SecurityInfo.ID_CA_ECDH_3DES_CBC_CBC_OID
        } else if fromPublicKeyOID == SecurityInfo.ID_PK_DH_OID {
            Log.warning("No ChipAuthenticationInfo - guessing its id-CA-DH-3DES-CBC-CBC");
            return SecurityInfo.ID_CA_DH_3DES_CBC_CBC_OID
        }
        
        Log.warning("No ChipAuthenticationInfo and unsupported ChipAuthenticationPublicKeyInfo public key OID \(fromPublicKeyOID)")
        return nil;
    }
    
    private func doCA( keyId: Int?, encryptionDetailsOID oid: String, publicKey: OpaquePointer, completed: @escaping (Bool)->() ) throws {
        
        // Generate Ephemeral Keypair from parameters from DG14 Public key
        // This should work for both EC and DH keys
        var ephemeralKeyPair : OpaquePointer? = nil
        let pctx = EVP_PKEY_CTX_new(publicKey, nil)
        EVP_PKEY_keygen_init(pctx)
        EVP_PKEY_keygen(pctx, &ephemeralKeyPair)
        EVP_PKEY_CTX_free(pctx)
        
        // Send the public key to the passport
        try sendPublicKey(oid: oid, keyId: keyId, pcdPublicKey: ephemeralKeyPair!, completed: { [unowned self] (response, err) in
            
            if let error = err {
                print( "ERROR! - \(error.localizedDescription)" )
                completed(false)
                return
            }
            
            Log.debug( "Public Key successfully sent to passport!" )
            
            // Use our ephemeral private key and the passports public key to generate a shared secret
            // (the passport with do the same thing with their private key and our public key)
            let sharedSecret = OpenSSLUtils.computeSharedSecret(privateKeyPair:ephemeralKeyPair!, publicKey:publicKey)
            
            // Now try to restart Secure Messaging using the new shared secret and
            do {
                try restartSecureMessaging( oid : oid, sharedSecret : sharedSecret, maxTranceiveLength : 1, shouldCheckMAC : true)
                completed(true)
            } catch {
                Log.error( "Failed to restart secure messaging - \(error)" )
                completed(false)
            }
        })
    }
    
    private func sendPublicKey(oid : String, keyId : Int?, pcdPublicKey : OpaquePointer, completed: @escaping (ResponseAPDU?, NFCPassportReaderError?)->()) throws {
        let cipherAlg = try ChipAuthenticationInfo.toCipherAlgorithm(oid: oid)
        guard let keyData = OpenSSLUtils.getPublicKeyData(from: pcdPublicKey) else {
            completed(nil, NFCPassportReaderError.InvalidDataPassed("Unable to get public key data from public key" ))
            return
        }
        
        if cipherAlg.hasPrefix("DESede") {
        
            var idData : [UInt8] = []
            if let keyId = keyId {
                idData = intToBytes( val:keyId, removePadding:true)
                idData = wrapDO( b:0x84, arr:idData)
            }
            let wrappedKeyData = wrapDO( b:0x91, arr:keyData)
            self.tagReader?.sendMSEKAT(keyData: Data(wrappedKeyData), idData: Data(idData), completed: completed)
        } else if cipherAlg.hasPrefix("AES") {
            self.tagReader?.sendMSESetATIntAuth(oid: oid, keyId: keyId, completed: { [unowned self] response, error in
                // Handle Error
                if let error = error {
                    completed(nil, error)
                } else {
                    let data = wrapDO(b: 0x80, arr:keyData)
                    gaSegments = self.chunk(data: data, segmentSize: ChipAuthenticationHandler.COMMAND_CHAINING_CHUNK_SIZE )
                    self.handleGeneralAuthentication( completed: completed )
                }
            })
        } else {
            completed( nil, NFCPassportReaderError.InvalidDataPassed("Cipher Algorithm \(cipherAlg) not supported"))
        }
    }
    
    private func handleGeneralAuthentication( completed: @escaping (ResponseAPDU?, NFCPassportReaderError?)->() ) {
        // Pull next segment from list
        let segment = gaSegments.removeFirst()
        let isLast = gaSegments.isEmpty
        
        // send it
        self.tagReader?.sendGeneralAuthenticate(data: segment, isLast: isLast, completed: { [unowned self] response, error in
            if let error = error {
                completed( nil, error )
            } else {
                if isLast {
                    completed( response, error )
                } else {
                    self.handleGeneralAuthentication( completed: completed )
                }
            }
        })
    }
        
    private func restartSecureMessaging( oid : String, sharedSecret : [UInt8], maxTranceiveLength : Int, shouldCheckMAC : Bool) throws  {
        let cipherAlg = try ChipAuthenticationInfo.toCipherAlgorithm(oid: oid)
        let keyLength = try ChipAuthenticationInfo.toKeyLength(oid: oid)
        
        // Start secure messaging.
        let smskg = SecureMessagingSessionKeyGenerator()
        let ksEnc = try smskg.deriveKey(keySeed: sharedSecret, cipherAlgName: cipherAlg, keyLength: keyLength, mode: .ENC_MODE)
        let ksMac = try smskg.deriveKey(keySeed: sharedSecret, cipherAlgName: cipherAlg, keyLength: keyLength, mode: .MAC_MODE)
        
        let ssc = withUnsafeBytes(of: 0.bigEndian, Array.init)
        if (cipherAlg.hasPrefix("DESede")) {
            Log.info( "Restarting secure messaging using DESede encryption")
            let sm = SecureMessaging(encryptionAlgorithm: .DES, ksenc: ksEnc, ksmac: ksMac, ssc: ssc)
            tagReader?.secureMessaging = sm
        } else if (cipherAlg.hasPrefix("AES")) {
            Log.info( "Restarting secure messaging using AES encryption")
            let sm = SecureMessaging(encryptionAlgorithm: .AES, ksenc: ksEnc, ksmac: ksMac, ssc: ssc)
            tagReader?.secureMessaging = sm
        } else {
            Log.error( "Not restarting secure messaging as unsupported cipher algorithm requested - \(cipherAlg)")
            throw NFCPassportReaderError.InvalidDataPassed("Unsupported cipher algorithm \(cipherAlg)" )
        }
    }
    
    
    func inferDigestAlgorithmFromCipherAlgorithmForKeyDerivation( cipherAlg : String, keyLength : Int) throws -> String {
        if cipherAlg == "DESede" || cipherAlg == "AES-128" {
            return "SHA1"
        }
        if cipherAlg == "AES" && keyLength == 128 {
            return "SHA1"
        }
        if cipherAlg == "AES-256" || cipherAlg ==  "AES-192" {
            return "SHA256"
        }
        if cipherAlg == "AES" && (keyLength == 192 || keyLength == 256) {
            return "SHA256"
        }
        
        throw NFCPassportReaderError.InvalidDataPassed("Unsupported cipher algorithm or key length")
    }
    
    /// Chunks up a byte array into a number of segments of the given size,
    /// and a final segment if there is a remainder.
    /// - Parameter segmentSize the number of bytes per segment
    /// - Parameter data the data to be partitioned
    /// - Parameter a list with the segments
    func chunk( data : [UInt8], segmentSize: Int ) -> [[UInt8]] {
        return stride(from: 0, to: data.count, by: segmentSize).map {
            Array(data[$0 ..< Swift.min($0 + segmentSize, data.count)])
        }
    }
}

#endif
