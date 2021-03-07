//
//  PACEHandler.swift
//  NFCPassportReader
//
//  Created by Andy Qua on 03/03/2021.
//

import Foundation
import OpenSSL
import CryptoTokenKit

#if !os(macOS)
import CoreNFC
import CryptoKit

@available(iOS 13, *)
public class PACEHandler {
    private static let MRZ_PACE_KEY_REFERENCE : UInt8 = 0x01
    private static let CAN_PACE_KEY_REFERENCE : UInt8 = 0x02 // Not currently supported
    private static let PIN_PACE_KEY_REFERENCE : UInt8 = 0x03 // Not currently supported
    private static let CUK_PACE_KEY_REFERENCE : UInt8 = 0x04 // Not currently supported

    var tagReader : TagReader?

    var paceInfo : PACEInfo?
    
    var completedHandler : ((Bool)->())?
    
    var isPACESupported : Bool = false
    
    // Params used
    var paceKey : [UInt8] = []
    var paceKeyType : UInt8 = 0
    var paceOID : String = ""
    var parameterSpec : Int32 = -1
    var mappingType : PACEMappingType!
    var agreementAlg : String = ""
    var cipherAlg : String = ""
    var digestAlg : String = ""
    var keyLength : Int = -1
    
    var decryptedNonce: [UInt8]?

    public init(cardAccess : CardAccess, tagReader: TagReader) {
        self.tagReader = tagReader
        
        if let pi = cardAccess.securityInfos.first as? PACEInfo {
            self.paceInfo = pi
            isPACESupported = true
        }
    }
    
    public func doPACE( mrzKey : String, completed: @escaping (Bool)->() ) {
        guard isPACESupported, let paceInfo = self.paceInfo else {
            completed( false )
            return
        }

        self.completedHandler = completed
        
        do {
            Log.info( "Performing PACE with \(paceInfo.getProtocolOIDString())" )
            
            paceOID = paceInfo.getObjectIdentifier()
            parameterSpec = try paceInfo.getParameterSpec()
            
            mappingType = try PACEInfo.toMappingType(oid: paceOID); /* Either GM, CAM, or IM. */
            agreementAlg = try PACEInfo.toKeyAgreementAlgorithm(oid: paceOID); /* Either DH or ECDH. */
            cipherAlg  = try PACEInfo.toCipherAlgorithm(oid: paceOID); /* Either DESede or AES. */
            digestAlg = try PACEInfo.toDigestAlgorithm(oid: paceOID); /* Either SHA-1 or SHA-256. */
            keyLength = try PACEInfo.toKeyLength(oid: paceOID); /* Of the enc cipher. Either 128, 192, or 256. */

            paceKeyType = PACEHandler.MRZ_PACE_KEY_REFERENCE;
            paceKey = try createPaceKey( from: mrzKey )

            // First start the initial auth call
            tagReader?.sendMSESetATMutualAuth(oid: paceOID, keyType: paceKeyType, completed: { [unowned self] response, error in
                if let error = error {
                    return handleError( "Error - \(error.localizedDescription)" )
                }
                
                self.doStep1()
            })
            
        } catch {
            return handleError( "Error - \(error.localizedDescription)" )
        }
    }
    
    func handleError( _ error: String ) {
        Log.error( "PACEHandler: \(error)" )
        Log.error( "   OpenSSLError: \(OpenSSLUtils.getOpenSSLError())" )
        completedHandler?( false )

    }
    
    func doStep1() {
        Log.debug( "Doing PACE Step1...")
        tagReader?.sendGeneralAuthenticate(data: [], isLast: false, completed: { [unowned self] response, error in
            if let error = error {
                return handleError( "Failed to send GA Step1 - \(error.localizedDescription)" )
            }
            
            do {
                let data = response!.data
                let encryptedNonce = try unwrapDO(tag: 0x80, wrappedData: data)
                Log.verbose( "Encrypted nonce - \(binToHexRep(encryptedNonce, asArray:true))" )

                if self.cipherAlg == "DESede" {
                    let iv = [UInt8](repeating:0, count: 8)
                    self.decryptedNonce = tripleDESDecrypt(key: self.paceKey, message: encryptedNonce, iv: iv)
                } else if self.cipherAlg == "AES" {
                    let iv = [UInt8](repeating:0, count: 16)
                    self.decryptedNonce = AESDecrypt(key: self.paceKey, message: encryptedNonce, iv: iv)
                }

                Log.verbose( "Decrypted nonce - \(binToHexRep(self.decryptedNonce ?? [], asArray:true) )" )
                
                self.doStep2()

            } catch {
                return handleError( "Unable to get encryptedNonce - \(error.localizedDescription)" )
            }
        })
    }
    
    
    func doStep2() {
        Log.debug( "Doing PACE Step2...")
        switch(mappingType) {
            case .CAM, .GM:
                Log.debug( "   Using General Mapping (GM)...")
                return doPACEStep2GM(agreementAlg: agreementAlg, parameterSpec: parameterSpec, piccNonce: self.decryptedNonce!);
            case .IM:
                Log.debug( "   Using Integrated Mapping (IM)...")
                return doPACEStep2IM(agreementAlg: agreementAlg, parameterSpec: parameterSpec, piccNonce: self.decryptedNonce!, cipherAlg: cipherAlg);
            default:
                self.completedHandler?( false )
        }

    }
    
    func doPACEStep2GM(agreementAlg: String, parameterSpec : Int32, piccNonce : [UInt8]) {
        
        // TODO - I think this can move into PACEInfo and rather than passing in the param spec, pass in the params????

        // This will get freed later
        let mappingKey : OpaquePointer = EVP_PKEY_new()

        if agreementAlg == "DH" {
            Log.debug( "Generating DH mapping keys")
            //The EVP_PKEY_CTX_set_dh_rfc5114() and EVP_PKEY_CTX_set_dhx_rfc5114() macros are synonymous. They set the DH parameters to the values defined in RFC5114. The rfc5114 parameter must be 1, 2 or 3 corresponding to RFC5114 sections 2.1, 2.2 and 2.3. or 0 to clear the stored value. This macro can be called during parameter generation. The ctx must have a key type of EVP_PKEY_DHX. The rfc5114 parameter and the nid parameter are mutually exclusive.
            var dhKey : OpaquePointer? = nil
            switch parameterSpec {
                case 0:
                    dhKey = DH_get_1024_160()
                case 1:
                    dhKey = DH_get_2048_224()
                case 2:
                    dhKey = DH_get_2048_256()
                default:
                    // Error
                    break
            }
            guard dhKey != nil else {
                return handleError( "Unable to create DH mapping key" )
            }
            defer{ DH_free( dhKey ) }

            EVP_PKEY_set1_DH(mappingKey, dhKey)
        } else {
            Log.debug( "Generating ECDH mapping keys")
            guard let ecKey = EC_KEY_new_by_curve_name(parameterSpec) else {
                return handleError( "Unable to create EC mapping key" )
            }
            defer{ EC_KEY_free( ecKey ) }
            
            EC_KEY_generate_key(ecKey)
            EVP_PKEY_set1_EC_KEY(mappingKey, ecKey)
        }

        let pcdMappingEncodedPublicKey = getPublicKeyData(from: mappingKey)
        let step2Data = wrapDO(b:0x81, arr:pcdMappingEncodedPublicKey);
        
        Log.debug( "Sending public mapping key to passport..")
        tagReader?.sendGeneralAuthenticate(data:step2Data, isLast:false, completed: { [weak self] response, error in
            guard let sself = self else { return }
            
            if let error = error {
                return sself.handleError( "Error - \(error)" )
            }

            let step2Response = response!.data
            let piccMappingEncodedPublicKey = try? unwrapDO(tag: 0x82, wrappedData: step2Response)
            let piccMappingPublicKey = sself.decodePublicKey(pubKeyData: piccMappingEncodedPublicKey!, params: mappingKey)
            
            Log.debug( "Received passports public mapping key")

            // Do mapping agreement
            // ephmeralParams are free'd in stage 3
            let ephemeralParams = EVP_PKEY_new()

            // First, Convert nonce to BIGNUM
            let bn_nonce = BN_bin2bn(piccNonce, Int32(piccNonce.count), nil);
            defer { BN_free(bn_nonce) }
            if agreementAlg == "DH" {
                Log.debug( "Doing DH Mapping agreement")
                guard let dh_mapping_key = EVP_PKEY_get1_DH(mappingKey) else {
                    // Error
                    return sself.handleError( "Unable to get DH mapping key" )
                }
                
                // Compute the shared secret using the mapping key and the passports public mapping key
                let secret = sself.computeSharedSecret(privateKeyPair: mappingKey, publicKey: piccMappingPublicKey!)
                
                // Convert the secret to a bignum
                let bn_h = BN_bin2bn(secret, Int32(secret.count), nil);
                defer { BN_clear_free(bn_h) }
                
                // Initialize ephemeral parameters with parameters from the mapping key
                guard let ephemeral_key = DHparams_dup(dh_mapping_key) else {
                    // Error
                    return sself.handleError( "Unable to get initialise ephemeral parameters from DH mapping key" )
                }
                defer{ EC_KEY_free(ephemeral_key) }

                var p, q, g : OpaquePointer?
                DH_get0_pqg(dh_mapping_key, &p, &q, &g);
                
                // map to new generator
                guard let bn_g = BN_new() else {
                    return sself.handleError( "Unable to create bn_g" )
                }
                guard let new_g = BN_new() else {
                    return sself.handleError( "Unable to create new_g" )
                }
                defer { BN_free(bn_h) ; BN_free(new_g) }
                
                // bn_g = g^nonce mod p
                // ephemeral_key->g = bn_g mod p * h  => (g^nonce mod p) * h mod p
                guard BN_mod_exp(bn_g, g, bn_nonce, p, nil) != 1,
                      BN_mod_mul(new_g, bn_g, bn_h, p, nil) != 1 else {
                    // Error
                    return sself.handleError( "Failed to generate new parameters" )
                }
                
                guard DH_set0_pqg(ephemeral_key, BN_dup(p), BN_dup(q), new_g) != 1 else {
                    // Error
                    return sself.handleError( "Unable to set DH pqg paramerters" )
                }
                
                // Set the ephemeral params
                guard EVP_PKEY_set1_DH(ephemeralParams, ephemeral_key) != 1 else {
                    // Error
                    return sself.handleError( "Unable to set ephemeral parameters" )
                }

            } else if agreementAlg == "ECDH" {
                Log.debug( "Doing ECDH Mapping agreement")

                let ec_mapping_key = EVP_PKEY_get1_EC_KEY(mappingKey);

                guard let group = EC_GROUP_dup(EC_KEY_get0_group(ec_mapping_key)) else {
                    // Error
                    return sself.handleError( "Unable to get EC mapping key" )
                }
                defer { EC_GROUP_free(group) }
                    
                guard let order = BN_new() else {
                    // Error
                    return sself.handleError( "Unable to create order bignum" )
                }
                defer { BN_free( order ) }
                    
                guard let cofactor = BN_new() else {
                    // error
                    return sself.handleError( "Unable to create cofactor bignum" )
                }
                defer { BN_free( cofactor ) }
                
                guard EC_GROUP_get_order(group, order, nil) == 1 ||
                    EC_GROUP_get_cofactor(group, cofactor, nil) == 1 else {
                    // Handle error
                    return sself.handleError( "Unable to get order or cofactor from group" )
                }
                
                // complete the ECDH and get the resulting point h
                guard let ecp_h = sself.computeECDHKeyPoint(key: mappingKey, inputKey: piccMappingEncodedPublicKey!) else {
                    // Error
                    return sself.handleError( "Failed to compute new ECDH key point from mapping key and passport public mapping key" )
                }
                defer { EC_POINT_free( ecp_h ) }

                /* map to new generator */
                guard let ecp_g = EC_POINT_new(group) else {
                    return sself.handleError( "Unable to create new mapping generator point" )
                }
                defer{ EC_POINT_free(ecp_g) }
                
                /* g' = g*s + h*1 */
                guard EC_POINT_mul(group, ecp_g, bn_nonce, ecp_h, BN_value_one(), nil) == 1 else {
                    return sself.handleError( "Failed to multipl mapping generator params" )
                }
                
                // Initialize ephemeral parameters with parameters from the mapping key
                let ephemeral_key = EC_KEY_dup(ec_mapping_key);
                defer{ EC_KEY_free(ephemeral_key) }
                EVP_PKEY_set1_EC_KEY(ephemeralParams, ephemeral_key);
                
                // configure the new EC_KEY
                guard EC_GROUP_set_generator(group, ecp_g, order, cofactor) == 1,
                      EC_GROUP_check(group, nil) == 1,
                    EC_KEY_set_group(ephemeral_key, group) == 1 else {
                    // Error
                    return sself.handleError( "Unable to configure new ephemeral params" )
                }
            }

            // Need to free the mapping key we created now
            EVP_PKEY_free(mappingKey)
            sself.doStep3KeyExchange(agreementAlg: agreementAlg, ephemeralParams: ephemeralParams!)
        })
    }
    
    func doPACEStep2IM(agreementAlg: String, parameterSpec : Int32, piccNonce: [UInt8], cipherAlg: String) {
        // Not implemented yet
        return handleError( "IM not yet implemented" )

    }
    
    func doStep3KeyExchange(agreementAlg: String, ephemeralParams: OpaquePointer) {
        Log.debug( "Doing PACE Step3 - Key Exchange")

        // Generate ephemeral keypair from ephemeralParams
        var ephemeralKeyPair : OpaquePointer? = nil
        let pctx = EVP_PKEY_CTX_new(ephemeralParams, nil)
        EVP_PKEY_keygen_init(pctx)
        EVP_PKEY_keygen(pctx, &ephemeralKeyPair)
        EVP_PKEY_CTX_free(pctx)
        
        Log.debug( "Generated Ephemeral key pair")
        
        // We've finished with the ephemeralParams now - we can now free it
        EVP_PKEY_free( ephemeralParams )

        let publicKey = getPublicKeyData( from: ephemeralKeyPair! )

        // exchange public keys
        Log.debug( "Sending ephemeral public key to passport")
        let step3Data = wrapDO(b:0x83, arr:publicKey);
        tagReader?.sendGeneralAuthenticate(data:step3Data, isLast:false, completed: { [weak self] response, error in
            guard let sself = self else { return }
            
            if let error = error {
                return sself.handleError( "Error - \(error.localizedDescription)" )
            }

            let step3Response = response!.data
            let passportEncodedPublicKey = try? unwrapDO(tag: 0x84, wrappedData: step3Response)
            let passportPublicKey = sself.decodePublicKey(pubKeyData: passportEncodedPublicKey!, params: ephemeralKeyPair!)

            Log.verbose( "Received passports ephemeral public key - \(binToHexRep(passportEncodedPublicKey!, asArray: true))" )

            sself.doStep3KeyAgreement( pcdKeyPair: ephemeralKeyPair!, passportPublicKey: passportPublicKey!)
        })
    }
    
    func doStep3KeyAgreement( pcdKeyPair: OpaquePointer, passportPublicKey: OpaquePointer) {
        Log.debug( "Doing PACE Step3 Key Agreement...")

        Log.debug( "Computing shared secret...")
        let sharedSecret = computeSharedSecret(privateKeyPair: pcdKeyPair, publicKey: passportPublicKey)
        Log.verbose( "Shared secret - \(binToHexRep(sharedSecret, asArray:true))")

        Log.debug( "Deriving ksEnc and ksMac keys from shared secret")
        let gen = SecureMessagingSessionKeyGenerator()
        let encKey = try! gen.deriveKey(keySeed: sharedSecret, cipherAlgName: cipherAlg, keyLength: keyLength, mode: .ENC_MODE)
        let macKey = try! gen.deriveKey(keySeed: sharedSecret, cipherAlgName: cipherAlg, keyLength: keyLength, mode: .MAC_MODE)
        Log.verbose( "encKey - \(binToHexRep(encKey, asArray:true))")
        Log.verbose( "macKey - \(binToHexRep(macKey, asArray:true))")

        // Step 4 - generate authentication token
        Log.debug( "Generating authentication token")
        let pcdAuthToken = generateAuthenticationToken( oid: self.paceOID, publicKey: passportPublicKey, macKey: macKey)
        Log.verbose( "authentication token - \(pcdAuthToken)")

        Log.debug( "Sending auth token to passport")
        let step4Data = wrapDO(b:0x85, arr:pcdAuthToken)
        tagReader?.sendGeneralAuthenticate(data:step4Data, isLast:true, completed: { [weak self] response, error in
            guard let sself = self else { return }

            if let error = error {
                // Error
                return sself.handleError( "Error - \(error.localizedDescription)" )
            }
            
            let tvlResp = TKBERTLVRecord.sequenceOfRecords(from: Data(response!.data))!
            if tvlResp[0].tag != 0x86 {
                Log.warning("Was expecting tag 0x86, found: \(binToHex(UInt8(tvlResp[0].tag)))");
            }
            // Calculate expected authentication token
            let expectedPICCToken = sself.generateAuthenticationToken(oid: sself.paceOID, publicKey: pcdKeyPair, macKey: macKey)
            Log.verbose( "Expecting authentication token from passport - \(expectedPICCToken)")

            let piccToken = [UInt8](tvlResp[0].value)
            Log.verbose( "Received authentication token from passport - \(piccToken)")

            guard piccToken == expectedPICCToken else {
                Log.error( "Error PICC Token mismatch!\npicToken - \(piccToken)\nexpectedPICCToken - \(expectedPICCToken)" )
                sself.completedHandler?(false)
                return sself.handleError( "Error PICC Token mismatch!\npicToken - \(piccToken)\nexpectedPICCToken - \(expectedPICCToken)" )
            }
            
            Log.debug( "Auth token from passport matches expected token!" )
            
            var encryptedChipAuthenticationData : [UInt8]? = nil
            if (sself.mappingType == PACEMappingType.CAM) {
                if tvlResp[1].tag != 0x8A {
                    Log.warning("CAM: Was expecting tag 0x86, found: \(binToHex(UInt8(tvlResp[1].tag)))");
                }
                encryptedChipAuthenticationData = [UInt8](tvlResp[1].value)
            }
            
            // We're done!
            sself.paceCompleted( ksEnc: encKey, ksMac: macKey )
        })
    }
    
    func paceCompleted( ksEnc: [UInt8], ksMac: [UInt8] ) {
        // Restart secure messaging
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
            return self.handleError( "Not restarting secure messaging as unsupported cipher algorithm requested - \(cipherAlg)" )
        }
        completedHandler?(true)
    }
    
    func generateAuthenticationToken( oid : String, publicKey: OpaquePointer, macKey: [UInt8] ) -> [UInt8] {
        var encodedPublicKeyData = encodePublicKey(oid:self.paceOID, key:publicKey)
        
        if cipherAlg == "DESede" {
            // If DESede (3DES), we need to pad the data
            encodedPublicKeyData = pad(encodedPublicKeyData, blockSize: 8)
        }
        
        Log.verbose( "Generating Authentication Token" )
        Log.verbose( "EncodedPubKey = \(binToHexRep(encodedPublicKeyData, asArray: true))" )
        Log.verbose( "macKey = \(binToHexRep(macKey, asArray: true))" )

        let maccedPublicKeyDataObject = mac(algoName: cipherAlg == "DESede" ? .DES : .AES, key: macKey, msg: encodedPublicKeyData)

        // Take 8 bytes for auth token
        let authToken = [UInt8](maccedPublicKeyDataObject[0..<8])
        Log.verbose( "Generated authToken = \(binToHexRep(authToken, asArray: true))" )
        return authToken
    }

    func encodePublicKey( oid : String, key : OpaquePointer ) -> [UInt8] {
        let encodedOid = oidToBytes(oid:oid, replaceTag: false)
        let pubKeyData = getPublicKeyData(from: key)

        let v = EVP_PKEY_base_id( key )
        let tag : TKTLVTag = v == EVP_PKEY_DH ? 0x84 : 0x86

        let encOid = TKBERTLVRecord(from: Data(encodedOid))!
        let encPub = TKBERTLVRecord(tag:tag, value: Data(pubKeyData))
        let record = TKBERTLVRecord(tag: 0x7F49, records:[encOid, encPub])
        let data = record.data

        return [UInt8](data)
    }


    func getPublicKeyData(from key:OpaquePointer) -> [UInt8] {
        
        var data : [UInt8] = []
        // Testing
        let v = EVP_PKEY_base_id( key )
        if v == EVP_PKEY_DH {
            let dh = EVP_PKEY_get1_DH(key)
            var dhPubKey : OpaquePointer?
            DH_get0_key(dh, &dhPubKey, nil)
            
            let nrBytes = (BN_num_bits(dhPubKey)+7)/8
            data = [UInt8](repeating: 0, count: Int(nrBytes))
            data.withUnsafeMutableBytes{ ( ptr) in
                _ = BN_bn2bin(dhPubKey, ptr.baseAddress?.assumingMemoryBound(to: UInt8.self))
            }
            DH_free(dh)
        } else if v == EVP_PKEY_EC {
            
            let ec = EVP_PKEY_get1_EC_KEY(key)
            defer { EC_KEY_free(ec) }

            let ec_pub = EC_KEY_get0_public_key(ec)
            let ec_group = EC_KEY_get0_group(ec)
            
            let form = EC_KEY_get_conv_form(ec)
            let len = EC_POINT_point2oct(ec_group, ec_pub,
                                         form, nil, 0, nil)
            data = [UInt8](repeating: 0, count: Int(len))
            if len != 0 {
                _ = EC_POINT_point2oct(ec_group, ec_pub,
                                       form, &data, len,
                                       nil)
            }
        }
        
        return data
    }
    

    // Caller is responsible for freeing the key
    func decodePublicKey(pubKeyData: [UInt8], params: OpaquePointer) -> OpaquePointer? {
        var pubKey : OpaquePointer?
        
        var error : Int32 = -1
        let keyType = EVP_PKEY_base_id( params )
        if keyType == EVP_PKEY_DH {
            let bn = BN_bin2bn(pubKeyData, Int32(pubKeyData.count), nil)
            defer{ BN_free(bn) }
            
            let dhKey = DH_new()
            defer{ DH_free(dhKey) }
            
            DH_set0_key(dhKey, bn, nil)
            
            pubKey = EVP_PKEY_new()
            error = EVP_PKEY_set1_DH(pubKey, dhKey)

        } else {
            let ec = EVP_PKEY_get1_EC_KEY(params)
            let group = EC_KEY_get0_group(ec);
            let ecp = EC_POINT_new(group);
            let key = EC_KEY_new();
            defer {
                EC_KEY_free(ec)
                EC_POINT_free(ecp)
                EC_KEY_free(key)
            }

            // Read EC_Point from public key data
            error = EC_POINT_oct2point(group, ecp, pubKeyData, pubKeyData.count, nil)

            error = EC_KEY_set_group(key, group)
            error = EC_KEY_set_public_key(key, ecp);

            pubKey = EVP_PKEY_new()
            error = EVP_PKEY_set1_EC_KEY(pubKey, key);
        }
        
        return pubKey
    }
    
    /// Computes a key seed based on an MRZ key
    /// - Parameter the mrz key
    /// - Returns a encoded key based on the mrz key that can be used for PACE
    func createPaceKey( from mrzKey: String ) throws -> [UInt8] {
        let buf: [UInt8] = Array(mrzKey.utf8)
        let hash = calcSHA1Hash(buf)
        
        let smskg = SecureMessagingSessionKeyGenerator()
        let key = try smskg.deriveKey(keySeed: hash, cipherAlgName: cipherAlg, keyLength: keyLength, nonce: nil, mode: .PACE_MODE, paceKeyReference: paceKeyType)
        return key
    }

    func computeSharedSecret( privateKeyPair: OpaquePointer, publicKey: OpaquePointer ) -> [UInt8] {
        
        let ctx = EVP_PKEY_CTX_new(privateKeyPair, nil)
        defer{ EVP_PKEY_CTX_free(ctx) }
        
        if EVP_PKEY_derive_init(ctx) != 1 {
            // error
            Log.error( "ERROR - \(OpenSSLUtils.getOpenSSLError())" )
        }
        
        // Set the public key
        if EVP_PKEY_derive_set_peer( ctx, publicKey ) != 1 {
            // error
            Log.error( "ERROR - \(OpenSSLUtils.getOpenSSLError())" )
        }
        
        // get buffer length needed for shared secret
        var keyLen = 0
        if EVP_PKEY_derive(ctx, nil, &keyLen) != 1 {
            // Error
            Log.error( "ERROR - \(OpenSSLUtils.getOpenSSLError())" )
        }
        
        // Derive the shared secret
        var secret = [UInt8](repeating: 0, count: keyLen)
        if EVP_PKEY_derive(ctx, &secret, &keyLen) != 1 {
            // Error
            Log.error( "ERROR - \(OpenSSLUtils.getOpenSSLError())" )
        }
        
        return secret
    }
    
    func computeECDHKeyPoint( key : OpaquePointer, inputKey : [UInt8] ) -> OpaquePointer? {
        
        let ecdh = EVP_PKEY_get1_EC_KEY(key)
        defer { EC_KEY_free(ecdh) }

        let privateKey = EC_KEY_get0_private_key(ecdh)

        // decode public key
        guard let group = EC_KEY_get0_group(ecdh) else{ return nil }
        guard let ecp = EC_POINT_new(group) else { return nil }
        defer { EC_POINT_free(ecp) }
        guard EC_POINT_oct2point(group, ecp, inputKey, inputKey.count,nil) != 0 else { return nil }
                
        // create our output point
        let output = EC_POINT_new(group);

        // Multiply our private key with the passports public key to get a new point
        EC_POINT_mul(group, output, nil, ecp, privateKey, nil)
        
        return output;
    }
}

#endif
