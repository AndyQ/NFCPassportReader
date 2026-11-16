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

@available(iOS 15, *)
private enum PACEHandlerError {
    case DHKeyAgreementError(String)
    case ECDHKeyAgreementError(String)
    
    var value: String {
        switch self {
            case .DHKeyAgreementError(let errMsg): return errMsg
            case .ECDHKeyAgreementError(let errMsg): return errMsg

        }
    }
}

@available(iOS 15, *)
extension PACEHandlerError: LocalizedError {
    public var errorDescription: String? {
        return NSLocalizedString(value, comment: "PACEHandlerError")
    }
}

@available(iOS 15, *)
public class PACEHandler {
    
    
    private static let MRZ_PACE_KEY_REFERENCE : UInt8 = 0x01
    private static let CAN_PACE_KEY_REFERENCE : UInt8 = 0x02
    private static let PIN_PACE_KEY_REFERENCE : UInt8 = 0x03 // Not currently supported
    private static let CUK_PACE_KEY_REFERENCE : UInt8 = 0x04 // Not currently supported

    var tagReader : TagReader
    var paceInfo : PACEInfo
    
    var isPACESupported : Bool = false
    var paceError : String = ""
    
    // Params used
    private var paceKey : [UInt8] = []
    private var paceKeyType : UInt8 = 0
    private var accessKey : PassportAccessKey = .mrz("")
    private var paceOID : String = ""
    private var parameterSpec : Int32 = -1
    private var mappingType : PACEMappingType!
    private var agreementAlg : String = ""
    private var cipherAlg : String = ""
    private var digestAlg : String = ""
    private var keyLength : Int = -1
    
    public init(cardAccess : CardAccess, tagReader: TagReader) throws {
        self.tagReader = tagReader
        
        guard let pi = cardAccess.paceInfo else {
            throw NFCPassportReaderError.NotYetSupported( "PACE not supported" )
        }

        self.paceInfo = pi
        isPACESupported = true
    }
    
    @available(*, deprecated, renamed: "doPACE(accessKey:)")
    public func doPACE( mrzKey : String ) async throws {
        try await doPACE(accessKey: .mrz(mrzKey))
    }

    /// Runs PACE with the MRZ or the CAN as password (ICAO 9303-11, 4.4).
    ///
    /// With the CAN, a wrong CAN throws `NFCPassportReaderError.InvalidCAN`, and a chip that doesn't accept the CAN
    /// (MSE:Set AT rejected) throws a `PACEError` saying so.
    public func doPACE( accessKey : PassportAccessKey ) async throws {
        guard isPACESupported else {
            throw NFCPassportReaderError.NotYetSupported( "PACE not supported" )
        }
        
        PassportLog.pace.info( "Performing PACE with \(self.paceInfo.getProtocolOIDString())" )
        
        paceOID = paceInfo.getObjectIdentifier()
        parameterSpec = try paceInfo.getParameterSpec()
        
        mappingType = try paceInfo.getMappingType()  // Either GM, CAM, or IM.
        agreementAlg = try paceInfo.getKeyAgreementAlgorithm()  // Either DH or ECDH.
        cipherAlg  = try paceInfo.getCipherAlgorithm()  // Either DESede or AES.
        digestAlg = try paceInfo.getDigestAlgorithm()  // Either SHA-1 or SHA-256.
        keyLength = try paceInfo.getKeyLength()  // Get key length  the enc cipher. Either 128, 192, or 256.

        self.accessKey = accessKey
        paceKeyType = accessKey.paceKeyReference
        paceKey = try createPaceKey( for: accessKey )
        
        PassportLog.pace.debug(
            "doPace - input parameters",
            content: """
                paceOID - \(self.paceOID)
                parameterSpec - \(self.parameterSpec)
                mappingType - \(self.mappingType!.description())
                agreementAlg - \(self.agreementAlg)
                cipherAlg - \(self.cipherAlg)
                digestAlg - \(self.digestAlg)
                keyLength - \(self.keyLength)
                """
        )
        switch accessKey {
            case .mrz(let mrzKey):
                PassportLog.pace.debug("MRZ key", content: mrzKey, sensitive: true, redactedMessage: "PACE MRZ credential derived")
            case .can(let can):
                PassportLog.pace.debug("CAN", content: can, sensitive: true, redactedMessage: "PACE CAN credential derived")
        }
        PassportLog.pace.debug(
            "PACE key",
            content: binToHexRep(self.paceKey, asArray: true),
            sensitive: true,
            redactedMessage: "PACE key derived"
        )

        tagReader.tracer?.emit(.info, "PACE: \(self.paceInfo.getProtocolOIDString())",
                               detail: "OID=\(paceOID) parameterId=\(paceInfo.getParameterId().map(String.init) ?? "-") password=\(accessKey.passwordName) K_pi=\(binToHexRep(paceKey))",
                               component: .pace,
                               sensitive: true)

        // First start the initial auth call. The chip only says whether it accepts the CAN here: nothing in
        // EF.CardAccess advertises it (ICAO 9303-11, 4.4: the chip MAY accept the CAN).
        do {
            _ = try await tagReader.sendMSESetATMutualAuth(oid: paceOID, keyType: paceKeyType, parameterId: paceInfo.getParameterId())
        } catch NFCPassportReaderError.ResponseError(let reason, let sw1, let sw2) where paceKeyType == PACEHandler.CAN_PACE_KEY_REFERENCE {
            let message = "Chip did not accept the CAN for PACE (\(binToHexRep(sw1))\(binToHexRep(sw2)) \(reason))"
            tagReader.tracer?.emit(.error, "PACE: \(message)", component: .pace)
            throw NFCPassportReaderError.PACEError("MSE:Set AT", message)
        }

        do {
            let decryptedNonce = try await self.doStep1()

            let ephemeralParams = try await self.doStep2(passportNonce: decryptedNonce)
            defer { EVP_PKEY_free( ephemeralParams ) }

            let (ephemeralKeyPair, passportPublicKey) = try await self.doStep3KeyExchange(ephemeralParams: ephemeralParams)
            defer { EVP_PKEY_free(ephemeralKeyPair); EVP_PKEY_free(passportPublicKey) }

            let (encKey, macKey) = try await self.doStep4KeyAgreement( pcdKeyPair: ephemeralKeyPair, passportPublicKey: passportPublicKey)
            try self.paceCompleted( ksEnc: encKey, ksMac: macKey )
        } catch NFCPassportReaderError.InvalidMRZKey where paceKeyType == PACEHandler.CAN_PACE_KEY_REFERENCE {
            // TagReader reports 6300 (authentication failed) as InvalidMRZKey; here it was the CAN.
            throw NFCPassportReaderError.InvalidCAN
        }
        PassportLog.pace.debug("PACE SUCCESSFUL" )
    }
    
    /// Handles an error during the PACE process
    /// Logs and stoes the error and returns false to the caller
    /// - Parameters:
    ///   - stage: Where in the PACE process the error occurred
    ///   - error: The error message
    func handleError( _ stage: String, _ error: String, needToTerminateGA: Bool = false ) {
        PassportLog.pace.error( "PACEHandler: \(stage) - \(error)" )
        PassportLog.pace.error( "   OpenSSLError: \(OpenSSLUtils.getOpenSSLError())" )
        self.paceError = "\(stage) - \(error)"
        //self.completedHandler?( false )

/*
        if needToTerminateGA {
            // This is to fix some passports that don't automatically terminate command chaining!
            // No idea if this is the correct way to do it but testing.....
            let terminateGA = wrapDO(b:0x83, arr:[0x00])
            tagReader.sendGeneralAuthenticate(data:terminateGA, isLast:true, completed: { [weak self] response, error in
                self?.completedHandler?( false )
            })
        } else {
            self.completedHandler?( false )
        }
*/
    }
    
    /// Performs PACE Step 1- receives an encrypted nonce from the passport and decypts it with the PACE key - derived from the MRZ or the CAN
    func doStep1() async throws -> [UInt8] {
        PassportLog.pace.debug("Doing PACE Step1...")
        let response = try await tagReader.sendGeneralAuthenticate(data: [], isLast: false)
            
        let data = response.data
        let encryptedNonce = try unwrapDO(tag: 0x80, wrappedData: data)
        PassportLog.pace.debug(
            "Encrypted PACE nonce",
            content: ReaderTracer.hex(encryptedNonce),
            sensitive: true,
            redactedMessage: "Encrypted PACE nonce received"
        )

        let decryptedNonce: [UInt8]
        if self.cipherAlg == "DESede" {
            let iv = [UInt8](repeating:0, count: 8)
            decryptedNonce = tripleDESDecrypt(key: self.paceKey, message: encryptedNonce, iv: iv)
        } else if self.cipherAlg == "AES" {
            let iv = [UInt8](repeating:0, count: 16)
            decryptedNonce = AESDecrypt(key: self.paceKey, message: encryptedNonce, iv: iv)
        } else {
            throw NFCPassportReaderError.UnsupportedCipherAlgorithm
        }

        PassportLog.pace.debug(
            "Decrypted PACE nonce",
            content: ReaderTracer.hex(decryptedNonce),
            sensitive: true,
            redactedMessage: "PACE nonce decrypted"
        )
        tagReader.tracer?.emit(.info, "PACE step 1: nonce decrypted", detail: "z=\(binToHexRep(encryptedNonce)) s=\(binToHexRep(decryptedNonce))",
                               component: .pace, sensitive: true)
        return decryptedNonce
    }
    
    
    /// Performs PACE Step 2 - computes ephemeral parameters by mapping the nonce received from the passport
    ///  (and if IM used the nonce generated by us)
    ///
    /// Using the supported
    /// - Parameters:
    ///   - passportNonce: The decrypted nonce received from the passport
    func doStep2( passportNonce: [UInt8]) async throws -> OpaquePointer {
        PassportLog.pace.debug( "Doing PACE Step2...")
        switch(mappingType) {
            case .CAM, .GM:
                PassportLog.pace.debug( "   Using General Mapping (GM)...")
                return try await doPACEStep2GM(passportNonce: passportNonce)
            case .IM:
                PassportLog.pace.debug( "   Using Integrated Mapping (IM)...")
                return try await doPACEStep2IM(passportNonce: passportNonce)
            default:
                throw NFCPassportReaderError.PACEError( "Step2GM", "Unsupported Mapping Type" )
        }

    }
    
    /// Performs PACEStep 2 using Generic Mapping
    ///
    /// Using the supported
    /// - Parameters:
    ///   - passportNonce: The decrypted nonce received from the passport
    func doPACEStep2GM(passportNonce : [UInt8]) async throws -> OpaquePointer {
        
        let mappingKey : OpaquePointer
        mappingKey = try self.paceInfo.createMappingKey( )

        guard let pcdMappingEncodedPublicKey = OpenSSLUtils.getPublicKeyData(from: mappingKey) else {
            throw NFCPassportReaderError.PACEError( "Step2GM", "Unable to get public key from mapping key")
        }
        PassportLog.pace.debug("PCD mapping public key", content: ReaderTracer.hex(pcdMappingEncodedPublicKey))

        PassportLog.pace.debug( "Sending public mapping key to passport..")
        let step2Data = wrapDO(b:0x81, arr:pcdMappingEncodedPublicKey)
        let response = try await tagReader.sendGeneralAuthenticate(data:step2Data, isLast:false)

        let piccMappingEncodedPublicKey = try unwrapDO(tag: 0x82, wrappedData: response.data)
        tagReader.tracer?.emit(.info, "PACE step 2: generic mapping",
                               detail: "PKmap_PCD=\(binToHexRep(pcdMappingEncodedPublicKey)) PKmap_PICC=\(binToHexRep(piccMappingEncodedPublicKey))",
                               component: .pace)
            
        PassportLog.pace.debug( "Received passports public mapping key")
        PassportLog.pace.debug("PICC mapping public key", content: ReaderTracer.hex(piccMappingEncodedPublicKey))

        // Do mapping agreement

        // First, Convert nonce to BIGNUM
        guard let bn_nonce = BN_bin2bn(passportNonce, Int32(passportNonce.count), nil) else {
            throw NFCPassportReaderError.PACEError( "Step2GM", "Unable to convert picc nonce to bignum" )
        }
        defer { BN_free(bn_nonce) }

        // ephmeralParams are free'd in stage 3
        let ephemeralParams : OpaquePointer
        if self.agreementAlg == "DH" {
            PassportLog.pace.debug( "Doing DH Mapping agreement")
            ephemeralParams = try self.doDHMappingAgreement(mappingKey: mappingKey, passportPublicKeyData: piccMappingEncodedPublicKey, nonce: bn_nonce )
        } else if self.agreementAlg == "ECDH" {
            PassportLog.pace.debug( "Doing ECDH Mapping agreement")
            ephemeralParams = try self.doECDHMappingAgreement(mappingKey: mappingKey, passportPublicKeyData: piccMappingEncodedPublicKey, nonce: bn_nonce )
        } else {
            throw NFCPassportReaderError.PACEError( "Step2GM", "Unsupported agreement algorithm" )
        }

        // Need to free the mapping key we created now
        EVP_PKEY_free(mappingKey)
        return ephemeralParams
    }
    
    /// Performs PACE Step 2 using Integrated Mapping (ICAO 9303 Part 11, 4.4.3.3.2)
    ///
    /// We choose a nonce t and send it to the passport in clear. Both sides then compute the
    /// mapped generator G^ = f_G(R_p(s, t)) from the passport's nonce s and t.
    /// - Parameters:
    ///   - passportNonce: The decrypted nonce s received from the passport
    func doPACEStep2IM( passportNonce: [UInt8] ) async throws -> OpaquePointer {
        guard self.agreementAlg == "ECDH" else {
            throw NFCPassportReaderError.PACEError( "Step2IM", "DH Integrated Mapping not supported" )
        }

        // t is k bits long (the key size of the PACE cipher; 128 for 3DES)
        let (_, k) = try PACEIntegratedMapping.lengths(cipherAlg: self.cipherAlg, keyLength: self.keyLength)
        let pcdNonce = generateRandomUInt8Array(k / 8)
        PassportLog.pace.debug("Reader nonce t", content: ReaderTracer.hex(pcdNonce))

        let step2Data = wrapDO(b:0x81, arr:pcdNonce)
        let response = try await tagReader.sendGeneralAuthenticate(data:step2Data, isLast:false)

        // DO'82' SHALL be empty for the Integrated Mapping (9303-11, 4.4.5.2.2)
        if !response.data.isEmpty {
            let mappingData = try unwrapDO(tag: 0x82, wrappedData: response.data)
            if !mappingData.isEmpty {
                PassportLog.pace.warning( "Integrated Mapping: expected an empty DO'82', got \(mappingData.count) bytes" )
            }
        }

        let mapping = try PACEIntegratedMapping.map(s: passportNonce, t: pcdNonce, curveName: self.parameterSpec, cipherAlg: self.cipherAlg, keyLength: self.keyLength)
        PassportLog.pace.debug(
            "Integrated mapping PRF R(s,t)",
            content: ReaderTracer.hex(mapping.pseudoRandom),
            sensitive: true,
            redactedMessage: "PACE integrated mapping PRF computed"
        )
        PassportLog.pace.debug(
            "Integrated mapping field element Rp(s,t)",
            content: ReaderTracer.hex(mapping.rp),
            sensitive: true,
            redactedMessage: "PACE integrated mapping field element computed"
        )
        PassportLog.pace.debug(
            "Mapped generator G",
            content: "x: \(ReaderTracer.hex(mapping.generatorX))\ny: \(ReaderTracer.hex(mapping.generatorY))",
            sensitive: true,
            redactedMessage: "PACE mapped generator computed"
        )
        tagReader.tracer?.emit(.info, "PACE step 2: integrated mapping",
                               detail: "s=\(binToHexRep(passportNonce)) t=\(binToHexRep(pcdNonce)) R(s,t)=\(binToHexRep(mapping.pseudoRandom)) " +
                                   "Rp=\(binToHexRep(mapping.rp)) G'x=\(binToHexRep(mapping.generatorX)) G'y=\(binToHexRep(mapping.generatorY))",
                               component: .pace, sensitive: true)

        // ephmeralParams are free'd in stage 3
        return try mapping.ephemeralParameters()
    }
    
    /// Generates an ephemeral public/private key pair based on mapping parameters from step 2, and then sends
    /// the public key to the passport and receives its ephmeral public key in exchange
    /// - Parameters:
    ///     - ephemeralParams: The ehpemeral mapping keys generated by step2
    /// - Returns:
///         - Tuple of Generated Ephemeral KeyPair and the Passport's public key
    func doStep3KeyExchange(ephemeralParams: OpaquePointer) async throws -> (OpaquePointer, OpaquePointer) {
        PassportLog.pace.debug( "Doing PACE Step3 - Key Exchange")

        // Generate the ephemeral key pair on the mapped domain parameters. (OpenSSL 3's EVP_PKEY_keygen
        // can't use these legacy keys, which carry a mapped generator, so build the key directly.)
        var ephKeyPair: OpaquePointer? = try Self.generateEphemeralKeyPair(params: ephemeralParams)
        guard let ephemeralKeyPair = ephKeyPair else {
            throw NFCPassportReaderError.PACEError( "Step3 KeyEx", "Unable to get create ephermeral key pair" )
        }
        defer { EVP_PKEY_free(ephKeyPair) }

        PassportLog.pace.debug( "Generated Ephemeral key pair")

        guard let publicKey = OpenSSLUtils.getPublicKeyData( from: ephemeralKeyPair ) else {
            throw NFCPassportReaderError.PACEError( "Step3 KeyEx", "Unable to get public key from ephermeral key pair" )
        }
        PassportLog.pace.debug("PCD ephemeral public key", content: ReaderTracer.hex(publicKey))

        // exchange public keys
        PassportLog.pace.debug( "Sending ephemeral public key to passport")
        let step3Data = wrapDO(b:0x83, arr:publicKey)
        let response = try await tagReader.sendGeneralAuthenticate(data:step3Data, isLast:false)
        let passportEncodedPublicKey = try? unwrapDO(tag: 0x84, wrappedData: response.data)
        guard let passportPublicKey = OpenSSLUtils.decodePublicKeyFromBytes(pubKeyData: passportEncodedPublicKey!, params: ephemeralKeyPair) else {
            throw NFCPassportReaderError.PACEError( "Step3 KeyEx", "Unable to decode passports ephemeral key" )
        }

        PassportLog.pace.debug("PICC ephemeral public key", content: ReaderTracer.hex(passportEncodedPublicKey!))
        tagReader.tracer?.emit(.info, "PACE step 3: ephemeral keys exchanged",
                               detail: "PK_PCD=\(binToHexRep(publicKey)) PK_PICC=\(binToHexRep(passportEncodedPublicKey!))",
                               component: .pace)
        defer { ephKeyPair = nil } // prevent free to return the value on success path
        return (ephemeralKeyPair, passportPublicKey)
    }
    
    /// This performs PACE Step 4 - Key Agreement.
    /// Here the shared secret is computed from our ephemeral private key and the passports ephemeral public key
    /// The new secure messaging (ksEnc and ksMac) keys are computed from the shared secret
    /// An authentication token is generated from the passports public key and the computed ksMac key
    /// Then, the authetication token is send to the passport, it returns its own computed authentication token
    /// We then compute an expected authentication token from the ksMac key and our ephemeral public key
    /// Finally we compare the recieved auth token to the expected token and if they are the same then PACE has succeeded!
    /// - Parameters:
    ///     - pcdKeyPair: our ephemeral key pair
    ///     - passportPublicKey: passports ephemeral public key
    /// - Returns:
    ///         - Tuple of KSEnc KSMac
    func doStep4KeyAgreement( pcdKeyPair: OpaquePointer, passportPublicKey: OpaquePointer) async throws -> ([UInt8], [UInt8]) {
        PassportLog.pace.debug( "Doing PACE Step4 Key Agreement...")

        PassportLog.pace.debug( "Computing shared secret...")
        let sharedSecret = OpenSSLUtils.computeSharedSecret(privateKeyPair: pcdKeyPair, publicKey: passportPublicKey)
        guard !sharedSecret.isEmpty else {
            throw NFCPassportReaderError.PACEError( "Step4 KeyAgreement", "Unable to compute shared secret" )
        }
        PassportLog.pace.debug(
            "PACE shared secret",
            content: ReaderTracer.hex(sharedSecret),
            sensitive: true,
            redactedMessage: "PACE shared secret derived"
        )

        PassportLog.pace.debug( "Deriving ksEnc and ksMac keys from shared secret")
        let gen = SecureMessagingSessionKeyGenerator()
        let encKey = try gen.deriveKey(keySeed: sharedSecret, cipherAlgName: cipherAlg, keyLength: keyLength, mode: .ENC_MODE)
        let macKey = try gen.deriveKey(keySeed: sharedSecret, cipherAlgName: cipherAlg, keyLength: keyLength, mode: .MAC_MODE)
        PassportLog.pace.debug(
            "PACE encryption key",
            content: ReaderTracer.hex(encKey),
            sensitive: true,
            redactedMessage: "PACE encryption key derived"
        )
        PassportLog.pace.debug(
            "PACE MAC key",
            content: ReaderTracer.hex(macKey),
            sensitive: true,
            redactedMessage: "PACE MAC key derived"
        )

        // Step 4 - generate authentication token
        PassportLog.pace.debug( "Generating authentication token")
        guard let pcdAuthToken = try? generateAuthenticationToken( publicKey: passportPublicKey, macKey: macKey) else {
            throw NFCPassportReaderError.PACEError( "Step3 KeyAgreement", "Unable to generate authentication token using passports public key" )
        }
        PassportLog.pace.debug(
            "PACE reader authentication token",
            content: ReaderTracer.hex(pcdAuthToken),
            sensitive: true,
            redactedMessage: "PACE reader authentication token generated"
        )

        PassportLog.pace.debug( "Sending auth token to passport")
        let step4Data = wrapDO(b:0x85, arr:pcdAuthToken)
        let response = try await tagReader.sendGeneralAuthenticate(data:step4Data, isLast:true)
            
        let tvlResp = TKBERTLVRecord.sequenceOfRecords(from: Data(response.data))!
        if tvlResp[0].tag != 0x86 {
            PassportLog.pace.warning("Was expecting tag 0x86, found: \(binToHex(UInt8(tvlResp[0].tag)))")
        }
        // Calculate expected authentication token
        let expectedPICCToken = try self.generateAuthenticationToken( publicKey: pcdKeyPair, macKey: macKey)
        
        PassportLog.pace.debug(
            "Expected PACE chip authentication token",
            content: ReaderTracer.hex(expectedPICCToken),
            sensitive: true,
            redactedMessage: "PACE chip authentication token computed"
        )

        let piccToken = [UInt8](tvlResp[0].value)
        PassportLog.pace.debug(
            "Received PACE chip authentication token",
            content: ReaderTracer.hex(piccToken),
            sensitive: true,
            redactedMessage: "PACE chip authentication token received"
        )

        guard piccToken == expectedPICCToken else {
            tagReader.tracer?.emit(.error, "PACE step 4: PICC token mismatch",
                                   detail: "got=\(binToHexRep(piccToken)) expected=\(binToHexRep(expectedPICCToken)) K=\(binToHexRep(sharedSecret)) KSmac=\(binToHexRep(macKey))",
                                   component: .pace, sensitive: true)
            PassportLog.pace.error(
                "PACE chip authentication token mismatch",
                content: "Received: \(ReaderTracer.hex(piccToken))\nExpected: \(ReaderTracer.hex(expectedPICCToken))",
                sensitive: true,
                redactedMessage: "PACE chip authentication token mismatch"
            )
            // The chip accepted our token, so with the CAN a mismatch here still means the keys differ.
            if paceKeyType == PACEHandler.CAN_PACE_KEY_REFERENCE { throw NFCPassportReaderError.InvalidCAN }
            throw NFCPassportReaderError.PACEError( "Step3 KeyAgreement", "Error PICC Token mismatch!\npicToken - \(piccToken)\nexpectedPICCToken - \(expectedPICCToken)" )
        }
        
        PassportLog.pace.debug( "Auth token from passport matches expected token!" )
        tagReader.tracer?.emit(.info, "PACE step 4: tokens verified",
                               detail: "K=\(binToHexRep(sharedSecret)) KSenc=\(binToHexRep(encKey)) KSmac=\(binToHexRep(macKey)) " +
                                   "T_PCD=\(binToHexRep(pcdAuthToken)) T_PICC=\(binToHexRep(piccToken))",
                               component: .pace, sensitive: true)
        
        // This will be added for CAM when supported
        // var encryptedChipAuthenticationData : [UInt8]? = nil
        // if (sself.mappingType == PACEMappingType.CAM) {
        //    if tvlResp[1].tag != 0x8A {
        //        PassportLog.pace.warning("CAM: Was expecting tag 0x86, found: \(binToHex(UInt8(tvlResp[1].tag)))")
        //    }
        //    encryptedChipAuthenticationData = [UInt8](tvlResp[1].value)
        // }
        
        // We're done!
        return (encKey, macKey)
    }
    
    /// Called once PACE has completed with the newly generated ksEnc and ksMac keys for restarting secure messaging
    /// - Parameters:
    ///   - ksEnc: the computed encryption key derived from the key agreement
    ///   - ksMac: the computed mac key derived from the key agreement
    func paceCompleted( ksEnc: [UInt8], ksMac: [UInt8] ) throws {
        // Restart secure messaging
        let ssc = withUnsafeBytes(of: 0.bigEndian, Array.init)
        if (cipherAlg.hasPrefix("DESede")) {
            PassportLog.pace.info( "Restarting secure messaging using DESede encryption")
            let sm = SecureMessaging(encryptionAlgorithm: .DES, ksenc: ksEnc, ksmac: ksMac, ssc: ssc)
            tagReader.secureMessaging = sm
        } else if (cipherAlg.hasPrefix("AES")) {
            PassportLog.pace.info( "Restarting secure messaging using AES encryption")
            let sm = SecureMessaging(encryptionAlgorithm: .AES, ksenc: ksEnc, ksmac: ksMac, ssc: ssc)
            tagReader.secureMessaging = sm
        } else {
            throw NFCPassportReaderError.PACEError( "PACECompleted", "Not restarting secure messaging as unsupported cipher algorithm requested - \(cipherAlg)" )
        }
    }
}

// MARK - PACEHandler Utility functions
@available(iOS 15, *)
extension PACEHandler {
    
    /// Does the DH key Mapping agreement
    /// - Parameter mappingKey - Pointer to an EVP_PKEY structure containing the mapping key
    /// - Parameter passportPublicKeyData - byte array containing the publick key read from the passport
    /// - Parameter nonce - Pointer to an BIGNUM structure containing the unencrypted nonce
    /// - Returns the EVP_PKEY containing the mapped ephemeral parameters
    func doDHMappingAgreement( mappingKey : OpaquePointer, passportPublicKeyData: [UInt8], nonce: OpaquePointer ) throws -> OpaquePointer {
        guard let dh_mapping_key = EVP_PKEY_get1_DH(mappingKey) else {
            // Error
            throw PACEHandlerError.DHKeyAgreementError( "Unable to get DH mapping key" )
        }
        
        // Compute the shared secret using the mapping key and the passports public mapping key
        let bn = BN_bin2bn(passportPublicKeyData, Int32(passportPublicKeyData.count), nil)
        defer { BN_free( bn ) }
        
        // Padded, so a secret with leading zero bytes still converts to the right h
        var secret = [UInt8](repeating: 0, count: Int(DH_size(dh_mapping_key)))
        guard DH_compute_key_padded( &secret, bn, dh_mapping_key) > 0 else {
            throw PACEHandlerError.DHKeyAgreementError( "Unable to compute the DH mapping secret" )
        }
        
        // Convert the secret to a bignum
        let bn_h = BN_bin2bn(secret, Int32(secret.count), nil)
        defer { BN_clear_free(bn_h) }
        
        // Initialize ephemeral parameters with parameters from the mapping key
        guard let ephemeral_key = DHparams_dup(dh_mapping_key) else {
            // Error
            throw PACEHandlerError.DHKeyAgreementError("Unable to get initialise ephemeral parameters from DH mapping key")
        }
        defer{ DH_free(ephemeral_key) }
        
        var p : OpaquePointer? = nil
        var q : OpaquePointer? = nil
        var g : OpaquePointer? = nil
        DH_get0_pqg(dh_mapping_key, &p, &q, &g)
        
        // map to new generator
        guard let bn_g = BN_new() else {
            throw PACEHandlerError.DHKeyAgreementError( "Unable to create bn_g" )
        }
        defer{ BN_free(bn_g) }
        guard let new_g = BN_new() else {
            throw PACEHandlerError.DHKeyAgreementError( "Unable to create new_g" )
        }
        defer{ BN_free(new_g) }
        
        // bn_g = g^nonce mod p
        // ephemeral_key->g = bn_g mod p * h  => (g^nonce mod p) * h mod p
        let bn_ctx = BN_CTX_new()
        defer { BN_CTX_free(bn_ctx) }
        guard BN_mod_exp(bn_g, g, nonce, p, bn_ctx) == 1,
              BN_mod_mul(new_g, bn_g, bn_h, p, bn_ctx) == 1 else {
            // Error
            throw PACEHandlerError.DHKeyAgreementError( "Failed to generate new parameters" )
        }
        
        guard DH_set0_pqg(ephemeral_key, BN_dup(p), BN_dup(q), BN_dup(new_g)) == 1 else {
            // Error
            throw PACEHandlerError.DHKeyAgreementError( "Unable to set DH pqg paramerters" )
        }
        
        // Set the ephemeral params
        guard let ephemeralParams = EVP_PKEY_new() else {
            throw PACEHandlerError.ECDHKeyAgreementError( "Unable to create ephemeral params" )
        }

        guard EVP_PKEY_set1_DH(ephemeralParams, ephemeral_key) == 1 else {
            // Error
            EVP_PKEY_free( ephemeralParams )
            throw PACEHandlerError.DHKeyAgreementError( "Unable to set ephemeral parameters" )
        }
        return ephemeralParams
    }
    
    /// Does the ECDH key Mapping agreement
    /// - Parameter mappingKey - Pointer to an EVP_PKEY structure containing the mapping key
    /// - Parameter passportPublicKeyData - byte array containing the publick key read from the passport
    /// - Parameter nonce - Pointer to an BIGNUM structure containing the unencrypted nonce
    /// - Returns the EVP_PKEY containing the mapped ephemeral parameters
    func doECDHMappingAgreement( mappingKey : OpaquePointer, passportPublicKeyData: [UInt8], nonce: OpaquePointer ) throws -> OpaquePointer {

        let ec_mapping_key = EVP_PKEY_get1_EC_KEY(mappingKey)
        
        guard let group = EC_GROUP_dup(EC_KEY_get0_group(ec_mapping_key)) else {
            // Error
            throw PACEHandlerError.ECDHKeyAgreementError( "Unable to get EC group" )
        }
        defer { EC_GROUP_free(group) }
        
        guard let order = BN_new() else {
            // Error
            throw PACEHandlerError.ECDHKeyAgreementError( "Unable to create order bignum" )
        }
        defer { BN_free( order ) }
        
        guard let cofactor = BN_new() else {
            // error
            throw PACEHandlerError.ECDHKeyAgreementError( "Unable to create cofactor bignum" )
        }
        defer { BN_free( cofactor ) }
        
        guard EC_GROUP_get_order(group, order, nil) == 1 ||
                EC_GROUP_get_cofactor(group, cofactor, nil) == 1 else {
            // Handle error
            throw PACEHandlerError.ECDHKeyAgreementError( "Unable to get order or cofactor from group" )
        }
        
        // Create the shared secret in the form of a ECPoint

        // Ideally I'd use OpenSSLUtls.computeSharedSecret for this but for reasons as yet unknown, it only returns the first 32 bytes
        // NOT the full 64 bytes (would then convert to 65 with e header of 4 for uncompressed)
        guard let sharedSecretMappingPoint = self.computeECDHMappingKeyPoint(privateKey: mappingKey, inputKey: passportPublicKeyData) else {
            // Error
            throw PACEHandlerError.ECDHKeyAgreementError( "Failed to compute new shared secret mapping point from mapping key and passport public mapping key" )
        }
        defer { EC_POINT_free( sharedSecretMappingPoint ) }

        // Map the nonce using Generic mapping to get the new parameters (inc a new generator)
        guard let newGenerater = EC_POINT_new(group) else {
            throw PACEHandlerError.ECDHKeyAgreementError( "Unable to create new mapping generator point" )
        }
        defer{ EC_POINT_free(newGenerater) }
        
        // g = (generator * nonce) + (sharedSecretMappingPoint * 1)
        guard EC_POINT_mul(group, newGenerater, nonce, sharedSecretMappingPoint, BN_value_one(), nil) == 1 else {
            throw PACEHandlerError.ECDHKeyAgreementError( "Failed to map nonce to get new generator params" )
        }
        
        // Initialize ephemeral parameters with parameters from the mapping key
        guard let ephemeralParams = EVP_PKEY_new() else {
            throw PACEHandlerError.ECDHKeyAgreementError( "Unable to create ephemeral params" )
        }

        let ephemeral_key = EC_KEY_dup(ec_mapping_key)
        defer{ EC_KEY_free(ephemeral_key) }
        
        // configure the new EC_KEY
        guard EVP_PKEY_set1_EC_KEY(ephemeralParams, ephemeral_key) == 1,
              EC_GROUP_set_generator(group, newGenerater, order, cofactor) == 1,
              EC_GROUP_check(group, nil) == 1,
              EC_KEY_set_group(ephemeral_key, group) == 1 else {
            // Error

            EVP_PKEY_free( ephemeralParams )
            throw PACEHandlerError.ECDHKeyAgreementError( "Unable to configure new ephemeral params" )
        }
        return ephemeralParams
    }
    
    /// Generate Authentication token from a publicKey and and a mac key
    /// - Parameters:
    ///   - publicKey: An EVP_PKEY structure containing a public key data which will be used to generate the auth code
    ///   - macKey: The mac key derived from the key agreement
    /// - Throws: An error if we are unable to encode the public key data
    /// - Returns: The authentication token (8 bytes)
    func generateAuthenticationToken( publicKey: OpaquePointer, macKey: [UInt8] ) throws -> [UInt8] {
        var encodedPublicKeyData = try encodePublicKey(oid:self.paceOID, key:publicKey)
        
        if cipherAlg == "DESede" {
            // If DESede (3DES), we need to pad the data
            encodedPublicKeyData = pad(encodedPublicKeyData, blockSize: 8)
        }
        
        PassportLog.pace.debug( "Generating Authentication Token" )
        PassportLog.pace.debug(
            "PACE authentication-token public-key data",
            content: ReaderTracer.hex(encodedPublicKeyData)
        )
        PassportLog.pace.debug(
            "PACE authentication-token MAC key",
            content: ReaderTracer.hex(macKey),
            sensitive: true,
            redactedMessage: "PACE authentication token MAC key used"
        )

        let maccedPublicKeyDataObject = mac(algoName: cipherAlg == "DESede" ? .DES : .AES, key: macKey, msg: encodedPublicKeyData)

        // Take 8 bytes for auth token
        let authToken = [UInt8](maccedPublicKeyDataObject[0..<8])
        PassportLog.pace.debug(
            "Generated PACE authentication token",
            content: ReaderTracer.hex(authToken),
            sensitive: true,
            redactedMessage: "PACE authentication token generated"
        )
        return authToken
    }
    
    /// Generates a key pair on the same domain parameters as `params`: an EC key on its group, or a DH key
    /// on its p, q and g (PACE with id-PACE-DH-*, whose mapped generator g' comes from step 2).
    /// Caller is responsible for freeing the key.
    static func generateEphemeralKeyPair( params: OpaquePointer ) throws -> OpaquePointer {
        let keyType = EVP_PKEY_get_base_id( params )
        guard let keyPair = EVP_PKEY_new() else {
            throw NFCPassportReaderError.PACEError( "Step3 KeyEx", "Unable to get create ephermeral key pair" )
        }
        if keyType == EVP_PKEY_DH || keyType == EVP_PKEY_DHX {
            guard let dhParams = EVP_PKEY_get0_DH(params), let dh = DHparams_dup(dhParams) else {
                EVP_PKEY_free(keyPair)
                throw NFCPassportReaderError.PACEError( "Step3 KeyEx", "Failed to copy the mapped DH parameters" )
            }
            defer { DH_free(dh) }
            guard DH_generate_key(dh) == 1, EVP_PKEY_set1_DH(keyPair, dh) == 1 else {
                EVP_PKEY_free(keyPair)
                throw NFCPassportReaderError.PACEError( "Step3 KeyEx", "Failed to generate DH key" )
            }
        } else {
            guard let ecKey = EC_KEY_new() else {
                EVP_PKEY_free(keyPair)
                throw NFCPassportReaderError.PACEError( "Step3 KeyEx", "Failed to create EC key" )
            }
            defer { EC_KEY_free(ecKey) }
            guard
                let ecParams = EVP_PKEY_get0_EC_KEY(params),
                let group = EC_KEY_get0_group(ecParams),
                EC_KEY_set_group(ecKey, group) == 1,
                EC_KEY_generate_key(ecKey) == 1,
                EVP_PKEY_set1_EC_KEY(keyPair, ecKey) == 1 else {
                EVP_PKEY_free(keyPair)
                throw NFCPassportReaderError.PACEError( "Step3 KeyEx", "Failed to generate EC key" )
            }
        }
        return keyPair
    }

    /// Encodes a PublicKey as an TLV strucuture based on TR-SAC 1.01 4.5.1 and 4.5.2
    /// - Parameters:
    ///   - oid: The object identifier specifying the key type
    ///   - key: The ECP_PKEY public key to encode
    /// - Throws: Error if unable to encode
    /// - Returns: the encoded public key in tlv format
    func encodePublicKey( oid : String, key : OpaquePointer ) throws -> [UInt8] {
        let encodedOid = oidToBytes(oid:oid, replaceTag: false)
        guard let pubKeyData = OpenSSLUtils.getPublicKeyData(from: key) else {
            PassportLog.pace.error( "PACEHandler: encodePublicKey() - Unable to get public key data" )
            throw NFCPassportReaderError.InvalidDataPassed("Unable to get public key data")
        }

        let keyType = EVP_PKEY_get_base_id( key )
        let tag : TKTLVTag
        if keyType == EVP_PKEY_DH || keyType == EVP_PKEY_DHX {
            tag = 0x84
        } else {
            tag = 0x86
        }

        guard let encOid = TKBERTLVRecord(from: Data(encodedOid)) else {
            throw NFCPassportReaderError.InvalidASN1Value
        }
        let encPub = TKBERTLVRecord(tag:tag, value: Data(pubKeyData))
        let record = TKBERTLVRecord(tag: 0x7F49, records:[encOid, encPub])
        let data = record.data

        return [UInt8](data)
    }

    /// Derives K_pi = KDF(f(pi), 3) from the password (ICAO 9303-11, 9.7.3 and table 8):
    /// f(MRZ) = SHA-1(MRZ information), and f(CAN) = the CAN as an ISO 8859-1 string, not hashed.
    func createPaceKey( for accessKey: PassportAccessKey ) throws -> [UInt8] {
        try Self.paceKey(for: accessKey, cipherAlg: cipherAlg, keyLength: keyLength)
    }

    static func paceKey( for accessKey: PassportAccessKey, cipherAlg: String, keyLength: Int ) throws -> [UInt8] {
        let seed: [UInt8]
        switch accessKey {
            case .mrz(let mrzKey):
                seed = calcSHA1Hash(Array(mrzKey.utf8))
            case .can(let can):
                guard !can.isEmpty, let bytes = can.data(using: .isoLatin1) else {
                    throw NFCPassportReaderError.InvalidDataPassed("The CAN must be a non-empty ISO 8859-1 string")
                }
                seed = [UInt8](bytes)
        }
        let smskg = SecureMessagingSessionKeyGenerator()
        return try smskg.deriveKey(keySeed: seed, cipherAlgName: cipherAlg, keyLength: keyLength, nonce: nil, mode: .PACE_MODE, paceKeyReference: accessKey.paceKeyReference)
    }
    
    /// Performs the ECDH PACE GM key agreement protocol by multiplying a private key with a public key
    /// - Parameters:
    ///   - key: an EVP_PKEY structure containng a ECDH private key
    ///   - inputKey: a public key
    /// - Returns: a new EC_POINT
    func computeECDHMappingKeyPoint( privateKey : OpaquePointer, inputKey : [UInt8] ) -> OpaquePointer? {
        
        let ecdh = EVP_PKEY_get1_EC_KEY(privateKey)
        defer { EC_KEY_free(ecdh) }

        let privateECKey = EC_KEY_get0_private_key(ecdh) // BIGNUM

        // decode public key
        guard let group = EC_KEY_get0_group(ecdh) else{ return nil }
        guard let ecp = EC_POINT_new(group) else { return nil }
        defer { EC_POINT_free(ecp) }
        guard EC_POINT_oct2point(group, ecp, inputKey, inputKey.count,nil) != 0 else { return nil }
                
        // create our output point
        let output = EC_POINT_new(group)

        // Multiply our private key with the passports public key to get a new point
        EC_POINT_mul(group, output, nil, ecp, privateECKey, nil)
        
        return output
    }
}

#endif
