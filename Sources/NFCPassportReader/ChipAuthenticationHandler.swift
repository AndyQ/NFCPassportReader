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
    
    private static let NO_PACE_KEY_REFERENCE : UInt8 = 0x00;
    private static let ENC_MODE : UInt8 = 0x1;
    private static let MAC_MODE : UInt8 = 0x2;
    private static let PACE_MODE : UInt8 = 0x3;

    var tagReader : TagReader?
    
    var chipAuthInfo : ChipAuthenticationInfo?
    var chipAuthPublicKeyInfos = [ChipAuthenticationPublicKeyInfo]()
    
    var completedHandler : ((Bool)->())?

    var isChipAuthenticationSupported : Bool = false
    
    public init(dg14 : DataGroup14, tagReader: TagReader) {
        self.tagReader = tagReader
        
        for secInfo in dg14.securityInfos {
            if let cai = secInfo as? ChipAuthenticationInfo {
                chipAuthInfo = cai
            } else if let capki = secInfo as? ChipAuthenticationPublicKeyInfo {
                chipAuthPublicKeyInfos.append( capki )
            }
        }
        
        if chipAuthInfo != nil && chipAuthPublicKeyInfos.count > 0 {
            isChipAuthenticationSupported = true
        }
    }

    public func doChipAuthentication( completed: @escaping (Bool)->() ) {
        
        self.completedHandler = completed
        
        Log.info( "Performing Chip Authentication" )
        guard isChipAuthenticationSupported else {
            completed( false )
            return
        }
        
        doChipAuthenticationForNextPublicKey( )
    }
    
    private func doChipAuthenticationForNextPublicKey( ) {
        guard chipAuthPublicKeyInfos.count > 0, let chipAuthInfo = chipAuthInfo else {
            completedHandler?( true )
            return
        }
        let chipAuthPublicKeyInfo = chipAuthPublicKeyInfos.removeFirst()

        print( "Adding CA" )
        do {
            print("Starting chip CA!")
            // For each public key, do chipauth
            try self.doCA( keyId: chipAuthInfo.keyId, oid: chipAuthInfo.oid, publicKeyOID: chipAuthPublicKeyInfo.oid, publicKey: chipAuthPublicKeyInfo.pubKey, completed: { [unowned self] (success) in
                
                print("Finished chip CA!")
                self.doChipAuthenticationForNextPublicKey()
            })
        } catch {
            print( "ERROR! - \(error)" )
            doChipAuthenticationForNextPublicKey()

        }
    }
    
    
    private func doCA( keyId: Int?, oid: String, publicKeyOID: String, publicKey: OpaquePointer, completed: @escaping (Bool)->() ) throws {
        
        // Generate Ephemeral Keypair from parameters from DG14 Public key
        // This should work for both EC and DH keys
        var ephemeralKeyPair : OpaquePointer? = nil
        let pctx = EVP_PKEY_CTX_new(publicKey, nil);
        EVP_PKEY_keygen_init(pctx);
        EVP_PKEY_keygen(pctx, &ephemeralKeyPair);
        EVP_PKEY_CTX_free(pctx);
        
        // Send the public key
        try sendPublicKey(oid: oid, keyId: keyId, pcdPublicKey: ephemeralKeyPair!, completed: { [unowned self] (response, err) in
            
            if let error = err {
                print( "ERROR! - \(error.localizedDescription)" )
                completed(false)
                return
            }
            
            Log.info( "Public Key sent to passport!" )
            let sharedSecret = self.computeSharedSecret(piccPubKey:publicKey, pcdKey:ephemeralKeyPair!);
            
            // Reinit Secure Messaging
            do {
                try restartSecureMessaging( oid : oid, sharedSecret : sharedSecret, maxTranceiveLength : 1, shouldCheckMAC : true)
                Log.info( "Chip authentication completed" )
                completed(true)
            } catch {
                Log.error( "Failed to restart secure messaging - \(error)" )
                completed(false)
            }
        })
    }
    
    private func sendPublicKey(oid : String, keyId : Int?, pcdPublicKey : OpaquePointer, completed: @escaping (ResponseAPDU?, NFCPassportReaderError?)->()) throws {
        let agreementAlg = try ChipAuthenticationInfo.toKeyAgreementAlgorithm(oid: oid);
        let cipherAlg = try ChipAuthenticationInfo.toCipherAlgorithm(oid: oid);
        let keyData = getKeyData(agreementAlg: agreementAlg, key: pcdPublicKey);
        
        if cipherAlg.hasPrefix("DESede") {
            
            var idData : [UInt8] = []
            if let keyId = keyId {
                idData = withUnsafeBytes(of: keyId.bigEndian, Array.init)
                
                // Remove initial 0 bytes
                for i in 0 ..< idData.count {
                    if idData[i] != 0 {
                        idData = [UInt8](idData[i...])
                        break
                    }
                }
                idData = wrapDO( b:0x84, arr:idData)
            }
            let wrappedKeyData = wrapDO( b:0x91, arr:keyData)
            
            self.tagReader?.sendMSEKAT(keyData: Data(wrappedKeyData), idData: Data(idData), completed: completed)
        } else if cipherAlg.hasPrefix("AES") {
            // Not yet handled as can't test but below is what we need to roughly do!
            //            service.sendMSESetATIntAuth(wrapper, oid, keyId);
            //            byte[] data = TLVUtil.wrapDO(0x80, keyData); /* FIXME: Constant for 0x80. */
            //            try {
            //                service.sendGeneralAuthenticate(wrapper, data, true);
            //            } catch (CardServiceException cse) {
            //            LOGGER.log(Level.WARNING, "Failed to send GENERAL AUTHENTICATE, falling back to command chaining", cse);
            //            List<byte[]> segments = Util.partition(COMMAND_CHAINING_CHUNK_SIZE, data);
            //
            //            int index = 0;
            //            for (byte[] segment: segments) {
            //                service.sendGeneralAuthenticate(wrapper, segment, ++index >= segments.size());
            //            }
            completed( nil, NFCPassportReaderError.UnexpectedError)
        } else {
            completed( nil, NFCPassportReaderError.UnexpectedError)
            //throw new IllegalStateException("Cannot set up secure channel with cipher " + cipherAlg);
        }
    }
    
    private func wrapDO( b : UInt8, arr : [UInt8] ) -> [UInt8] {
        let new : [UInt8] = [b, UInt8(arr.count)] + arr
        
        return new;
    }
    
    
    private func getKeyData( agreementAlg : String, key : OpaquePointer ) -> [UInt8] {
        
        var data : [UInt8] = []
        // Testing
        let v = EVP_PKEY_base_id( key )
        if v == EVP_PKEY_DH {
            let dh = EVP_PKEY_get1_DH(key);
            var dhParams : OpaquePointer?
            DH_get0_key(dh, &dhParams, nil);
            
            let nrBytes = (BN_num_bits(dhParams)+7)/8
            data = [UInt8](repeating: 0, count: Int(nrBytes))
            data.withUnsafeMutableBytes{ ( ptr) in
                _ = BN_bn2bin(dhParams, ptr.baseAddress?.assumingMemoryBound(to: UInt8.self));
            }
            DH_free(dh);
        } else if v == EVP_PKEY_EC {
            
            let ec = EVP_PKEY_get1_EC_KEY(key);
            
            let ec_pub = EC_KEY_get0_public_key(ec);
            let ec_group = EC_KEY_get0_group(ec);
            
            let bn_ctx = BN_CTX_new();
            
            let form = EC_KEY_get_conv_form(ec)
            let len = EC_POINT_point2oct(ec_group, ec_pub,
                                         form, nil, 0, bn_ctx);
            data = [UInt8](repeating: 0, count: Int(len))
            if len != 0 {
                _ = EC_POINT_point2oct(ec_group, ec_pub,
                                       form, &data, len,
                                       bn_ctx);
            }
        }
        
        return data
    }
    
    private func computeSharedSecret( piccPubKey : OpaquePointer, pcdKey: OpaquePointer ) -> [UInt8]{
        let ctx = EVP_PKEY_CTX_new(pcdKey, nil);
        
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
        let cipherAlg = try ChipAuthenticationInfo.toCipherAlgorithm(oid: oid);
        let keyLength = try ChipAuthenticationInfo.toKeyLength(oid: oid);
        
        // Start secure messaging.
        let smskg = SecureMessagingSessionKeyGenerator()
        let ksEnc = try smskg.deriveKey(keySeed: sharedSecret, cipherAlgName: cipherAlg, keyLength: keyLength, mode: .ENC_MODE);
        let ksMac = try smskg.deriveKey(keySeed: sharedSecret, cipherAlgName: cipherAlg, keyLength: keyLength, mode: .MAC_MODE);
        
        let ssc = withUnsafeBytes(of: 0.bigEndian, Array.init)
        if (cipherAlg.hasPrefix("DESede")) {
            let sm = SecureMessaging(ksenc: ksEnc, ksmac: ksMac, ssc: ssc)
            tagReader?.secureMessaging = sm
        } else if (cipherAlg.hasPrefix("AES")) {
            // Not yet supported
            //return new AESSecureMessagingWrapper(ksEnc, ksMac, maxTranceiveLength, shouldCheckMAC, 0L);
            throw NFCPassportReaderError.UnexpectedError // new IllegalStateException("Unsupported cipher algorithm " + cipherAlg);
        } else {
            throw NFCPassportReaderError.UnexpectedError //new IllegalStateException("Unsupported cipher algorithm " + cipherAlg);
        }
    }
    
    
    func inferDigestAlgorithmFromCipherAlgorithmForKeyDerivation( cipherAlg : String, keyLength : Int) throws -> String {
        if cipherAlg == "DESede" || cipherAlg == "AES-128" {
            return "SHA1";
        }
        if cipherAlg == "AES" && keyLength == 128 {
            return "SHA1";
        }
        if cipherAlg == "AES-256" || cipherAlg ==  "AES-192" {
            return "SHA256";
        }
        if cipherAlg == "AES" && (keyLength == 192 || keyLength == 256) {
            return "SHA256";
        }
        
        throw NFCPassportReaderError.InvalidDataPassed("Unsupported cipher algorithm or key length")
    }
}

#endif
