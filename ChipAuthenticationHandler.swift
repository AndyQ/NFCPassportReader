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

    var caAvailable : Bool = false
    public init() {
        // For testing only
    }
    
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
            caAvailable = true
        }
    }

    func doChipAuthentication( completed: @escaping (Bool)->() ) {
        
        self.completedHandler = completed
        
        Log.info( "Performing Chip Authentication" )
        guard caAvailable else {
            completed( false )
            return
        }
        
        doCA( )
    }
    
    func doCA( ) {
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
                self.doCA()
            })
        } catch {
            print( "ERROR! - \(error)" )
            doCA()

        }
    }
    
    
    func doCA( keyId: Int?, oid: String, publicKeyOID: String, publicKey: OpaquePointer, completed: @escaping (Bool)->() ) throws {
        
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
    
    func sendPublicKey(oid : String, keyId : Int?, pcdPublicKey : OpaquePointer, completed: @escaping (ResponseAPDU?, NFCPassportReaderError?)->()) throws {
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
    
    func wrapDO( b : UInt8, arr : [UInt8] ) -> [UInt8] {
        let new : [UInt8] = [b, UInt8(arr.count)] + arr
        
        return new;
    }
    
    
    func getKeyData( agreementAlg : String, key : OpaquePointer ) -> [UInt8] {
        
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
    
    func computeSharedSecret( piccPubKey : OpaquePointer, pcdKey: OpaquePointer ) -> [UInt8]{
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
    
    func restartSecureMessaging( oid : String, sharedSecret : [UInt8], maxTranceiveLength : Int, shouldCheckMAC : Bool) throws  {
        let cipherAlg = try ChipAuthenticationInfo.toCipherAlgorithm(oid: oid);
        let keyLength = try ChipAuthenticationInfo.toKeyLength(oid: oid);
        
        /* Start secure messaging. */
        let ksEnc = try deriveKey(keySeed: sharedSecret, cipherAlgName: cipherAlg, keyLength: keyLength, mode: ChipAuthenticationHandler.ENC_MODE);
        let ksMac = try deriveKey(keySeed: sharedSecret, cipherAlgName: cipherAlg, keyLength: keyLength, mode: ChipAuthenticationHandler.MAC_MODE);
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
    
    /// Derives the ENC or MAC key for BAC from the keySeed.
    ///
    /// @Parameters keySeed the key seed.
    /// @param mode either <code>ENC_MODE</code> or <code>MAC_MODE</code>
    ///
    /// @return the key
    ///
    /// @throws GeneralSecurityException on security error
    ////
    func deriveKey( keySeed : [UInt8], mode : UInt8) throws -> [UInt8] {
        return try deriveKey(keySeed: keySeed, cipherAlgName: "DESede", keyLength: 128, mode: mode);
    }
    
    ///
    /// Derives the ENC or MAC key for BAC or PACE or CA.
    ///
    /// @param keySeed the key seed.
    /// @param cipherAlgName either AES or DESede
    /// @param keyLength key length in bits
    /// @param mode either {@code ENC_MODE}, {@code MAC_MODE}, or {@code PACE_MODE}
    ///
    /// @return the key.
    ///
    /// @throws GeneralSecurityException on security error
    ///
    func deriveKey(keySeed : [UInt8], cipherAlgName :String, keyLength : Int, mode : UInt8) throws  -> [UInt8] {
        return try deriveKey(keySeed: keySeed, cipherAlgName: cipherAlgName, keyLength: keyLength, nonce: nil, mode: mode);
    }
    
    /**
     * Derives a shared key.
     *
     * @param keySeed the shared secret, as octets
     * @param cipherAlg in Java mnemonic notation (for example "DESede", "AES")
     * @param keyLength length in bits
     * @param nonce optional nonce or <code>null</code>
     * @param mode the mode either {@code ENC}, {@code MAC}, or {@code PACE} mode
     *
     * @return the derived key
     *
     * @throws GeneralSecurityException if something went wrong
     */
    func deriveKey(keySeed : [UInt8], cipherAlgName :String, keyLength : Int, nonce : [UInt8]?, mode : UInt8) throws -> [UInt8]  {
        return try deriveKey(keySeed: keySeed, cipherAlgName: cipherAlgName, keyLength: keyLength, nonce: nonce, mode: mode, paceKeyReference: ChipAuthenticationHandler.NO_PACE_KEY_REFERENCE);
    }
    
    /**
     * Derives a shared key.
     *
     * @param keySeed the shared secret, as octets
     * @param cipherAlg in Java mnemonic notation (for example "DESede", "AES")
     * @param keyLength length in bits
     * @param nonce optional nonce or <code>null</code>
     * @param mode the mode either {@code ENC}, {@code MAC}, or {@code PACE} mode
     * @param paceKeyReference Key Reference For Pace Protocol
     *
     * @return the derived key
     *
     * @throws GeneralSecurityException if something went wrong
     */
    func deriveKey(keySeed : [UInt8], cipherAlgName :String, keyLength : Int, nonce : [UInt8]?, mode : UInt8, paceKeyReference : UInt8) throws ->  [UInt8] {
        let digestAlgo = try inferDigestAlgorithmFromCipherAlgorithmForKeyDerivation(cipherAlg: cipherAlgName, keyLength: keyLength);
        
        let mode : [UInt8] = [0x00, 0x00, 0x00, mode]
        var dataEls = [Data(keySeed)]
        if let nonce = nonce {
            dataEls.append( Data(nonce) )
        }
        dataEls.append( Data(mode) )
        let hashResult = try getHash(algo: digestAlgo, dataElements: dataEls)
        
        var keyBytes : [UInt8]
        if cipherAlgName == "DESede" || cipherAlgName == "3DES" {
            /* TR-SAC 1.01, 4.2.1. */
            switch(keyLength) {
                case 112, 128:
                    keyBytes = [UInt8](hashResult[0..<16] + hashResult[0..<8])
                    //                    System.arraycopy(hashResult, 0, keyBytes, 0, 8); /* E  (octets 1 to 8) */
                    //                    System.arraycopy(hashResult, 8, keyBytes, 8, 8); /* D  (octets 9 to 16) */
                    //                    System.arraycopy(hashResult, 0, keyBytes, 16, 8); /* E (again octets 1 to 8, i.e. 112-bit 3DES key) */
                    break;
                default:
                    throw NFCPassportReaderError.UnexpectedError // IllegalArgumentException("KDF can only use DESede with 128-bit key length");
            }
        } else if cipherAlgName.lowercased() == "aes" || cipherAlgName.lowercased().hasPrefix("aes") {
            /* TR-SAC 1.01, 4.2.2. */
            switch(keyLength) {
                case 128:
                    keyBytes = [UInt8](hashResult[0..<16]) // NOTE: 128 = 16 * 8
                case 192:
                    keyBytes = [UInt8](hashResult[0..<24]) // NOTE: 192 = 24 * 8
                case 256:
                    keyBytes = [UInt8](hashResult[0..<32]) // NOTE: 256 = 32 * 8
                default:
                    throw NFCPassportReaderError.UnexpectedError // new IllegalArgumentException("KDF can only use AES with 128-bit, 192-bit key or 256-bit length, found: " + keyLength + "-bit key length");
            }
        } else {
            throw NFCPassportReaderError.UnexpectedError
        }
        
        if (paceKeyReference == ChipAuthenticationHandler.NO_PACE_KEY_REFERENCE) {
            return keyBytes
            //            return new SecretKeySpec(keyBytes, cipherAlg);
        } else {
            ///            return new PACESecretKeySpec(keyBytes, cipherAlg, paceKeyReference);
            return []
        }
    }
    
    func  getHash(algo: String, dataElements:[Data] ) throws -> [UInt8] {
        var hash : [UInt8]
        
        let algo = algo.lowercased()
        if algo == "sha1" {
            var hasher = Insecure.SHA1()
            for d in dataElements {
                hasher.update( data:d )
            }
            hash = Array(hasher.finalize())
            
        } else if algo == "sha256" {
            var hasher = SHA256()
            for d in dataElements {
                hasher.update( data:d )
            }
            hash = Array(hasher.finalize())
        } else if algo == "sha384" {
            var hasher = SHA384()
            for d in dataElements {
                hasher.update( data:d )
            }
            hash = Array(hasher.finalize())
        } else if algo == "sha512" {
            var hasher = SHA512()
            for d in dataElements {
                hasher.update( data:d )
            }
            hash = Array(hasher.finalize())
        } else {
            throw NFCPassportReaderError.InvalidHashAlgorithmSpecified
        }
        
        return hash
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
        
        throw NFCPassportReaderError.UnexpectedError //new IllegalArgumentException("Unsupported cipher algorithm or key length \"" + cipherAlg + "\", " + keyLength);
    }
}

#endif
