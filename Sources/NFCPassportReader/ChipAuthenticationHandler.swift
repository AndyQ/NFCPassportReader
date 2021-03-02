//
//  File.swift
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
    
    var chipAuthInfos = [ChipAuthenticationInfo]()
    var chipAuthPublicKeyInfos = [Int:ChipAuthenticationPublicKeyInfo]()
    
    var completedHandler : ((Bool)->())?

    var isChipAuthenticationSupported : Bool = false
    
    public init(dg14 : DataGroup14, tagReader: TagReader) {
        self.tagReader = tagReader
        
        for secInfo in dg14.securityInfos {
            if let cai = secInfo as? ChipAuthenticationInfo {
                chipAuthInfos.append(cai)
            } else if let capki = secInfo as? ChipAuthenticationPublicKeyInfo {
                let keyId = capki.getKeyId()
                chipAuthPublicKeyInfos[keyId] = capki
            }
        }
        
        if chipAuthInfos.count > 0 && chipAuthPublicKeyInfos.count > 0 {
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
        guard chipAuthInfos.count > 0 else {
            completedHandler?( true )
            return
        }
        
        // Grab the next ChipAuthInfo, and get the key id
        // From that, get the associated ChipAuthPublicKeyInfo (contains the publc key) and then do Chip Authentication
        // If that works, we're done, otherwise go on to the next key  (if available) and try that
        let chipAuthInfo = chipAuthInfos.removeFirst()
        let keyId = chipAuthInfo.getKeyId()
        guard let chipAuthPublicKeyInfo = chipAuthPublicKeyInfos[keyId] else {
            self.doChipAuthenticationForNextPublicKey()
            return
        }

        do {
            Log.info("Starting Chip Authentication!")
            // For each public key, do chipauth
            try self.doCA( keyId: chipAuthInfo.keyId, encryptionDetailsOID: chipAuthInfo.oid, publicKey: chipAuthPublicKeyInfo.pubKey, completed: { [unowned self] (success) in
                
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
            let sharedSecret = self.computeSharedSecret(piccPubKey:publicKey, pcdKey:ephemeralKeyPair!)
            
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
        let agreementAlg = try ChipAuthenticationInfo.toKeyAgreementAlgorithm(oid: oid)
        let cipherAlg = try ChipAuthenticationInfo.toCipherAlgorithm(oid: oid)
        let keyData = getKeyData(agreementAlg: agreementAlg, key: pcdPublicKey)
        
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
    
    private func getKeyData( agreementAlg : String, key : OpaquePointer ) -> [UInt8] {
        
        var data : [UInt8] = []
        // Testing
        let v = EVP_PKEY_base_id( key )
        if v == EVP_PKEY_DH {
            let dh = EVP_PKEY_get1_DH(key)
            var dhParams : OpaquePointer?
            DH_get0_key(dh, &dhParams, nil)
            
            let nrBytes = (BN_num_bits(dhParams)+7)/8
            data = [UInt8](repeating: 0, count: Int(nrBytes))
            data.withUnsafeMutableBytes{ ( ptr) in
                _ = BN_bn2bin(dhParams, ptr.baseAddress?.assumingMemoryBound(to: UInt8.self))
            }
            DH_free(dh)
        } else if v == EVP_PKEY_EC {
            
            let ec = EVP_PKEY_get1_EC_KEY(key)
            
            let ec_pub = EC_KEY_get0_public_key(ec)
            let ec_group = EC_KEY_get0_group(ec)
            
            let bn_ctx = BN_CTX_new()
            
            let form = EC_KEY_get_conv_form(ec)
            let len = EC_POINT_point2oct(ec_group, ec_pub,
                                         form, nil, 0, bn_ctx)
            data = [UInt8](repeating: 0, count: Int(len))
            if len != 0 {
                _ = EC_POINT_point2oct(ec_group, ec_pub,
                                       form, &data, len,
                                       bn_ctx)
            }
        }
        
        return data
    }
    
    private func computeSharedSecret( piccPubKey : OpaquePointer, pcdKey: OpaquePointer ) -> [UInt8]{
        let ctx = EVP_PKEY_CTX_new(pcdKey, nil)
        
        if EVP_PKEY_derive_init(ctx) != 1 {
            // error
            print( "ERROR - \(OpenSSLUtils.getOpenSSLError())" )
        }
        
        if EVP_PKEY_derive_set_peer( ctx, piccPubKey ) != 1 {
            // error
            print( "ERROR - \(OpenSSLUtils.getOpenSSLError())" )
        }
        
        // Determine buffer length for shared secret
        var keyLen = 0
        if EVP_PKEY_derive(ctx, nil, &keyLen) != 1 {
            // Error
            print( "ERROR - \(OpenSSLUtils.getOpenSSLError())" )
        }
        
        // Create the buffer
        var secret = [UInt8](repeating: 0, count: keyLen)
        
        // Derive the shared secret
        if EVP_PKEY_derive(ctx, &secret, &keyLen) != 1 {
            // Error
            print( "ERROR - \(OpenSSLUtils.getOpenSSLError())" )
        }
        
        return secret
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
