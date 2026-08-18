//
//  BACHandler.swift
//  NFCTest
//
//  Created by Andy Qua on 07/06/2019.
//  Copyright © 2019 Andy Qua. All rights reserved.
//

import Foundation
import OSLog

#if !os(macOS)
import CoreNFC

@available(iOS 15, *)
public class BACHandler {
    let KENC : [UInt8] = [0,0,0,1]
    let KMAC : [UInt8] = [0,0,0,2]
    
    public var ksenc : [UInt8] = []
    public var ksmac : [UInt8] = []

    var rnd_icc : [UInt8] = []
    var rnd_ifd : [UInt8] = []
    public var kifd : [UInt8] = []
    
    var tagReader : TagReader?
    
    public init() {
        // For testing only
    }
    
    public init(tagReader: TagReader) {
        self.tagReader = tagReader
    }

    public func performBACAndGetSessionKeys( mrzKey : String ) async throws {
        guard let tagReader = self.tagReader else {
            throw NFCPassportReaderError.NoConnectedTag
        }
        
        Logger.bac.debug( "BACHandler - deriving Document Basic Access Keys" )
        _ = try self.deriveDocumentBasicAccessKeys(mrz: mrzKey)
        
        // Make sure we clear secure messaging (could happen if we read an invalid DG or we hit a secure error
        tagReader.secureMessaging = nil
        
        // get Challenge
        Logger.bac.debug( "BACHandler - Getting initial challenge" )
        let response = try await tagReader.getChallenge()
    
        Logger.bac.debug( "BACHandler - Doing mutual authentication" )
        let cmd_data = self.authentication(rnd_icc: [UInt8](response.data))
        let maResponse = try await tagReader.doMutualAuthentication(cmdData: Data(cmd_data))
        guard maResponse.data.count > 0 else {
            throw NFCPassportReaderError.InvalidMRZKey
        }
        
        let (KSenc, KSmac, ssc) = try self.sessionKeys(data: [UInt8](maResponse.data))
        tagReader.secureMessaging = SecureMessaging(ksenc: KSenc, ksmac: KSmac, ssc: ssc)
        Logger.bac.debug( "BACHandler - complete" )
    }


    func deriveDocumentBasicAccessKeys(mrz: String) throws -> ([UInt8], [UInt8]) {
        let kseed = generateInitialKseed(kmrz:mrz)
    
        Logger.bac.debug("Calculate the Basic Access Keys (Kenc and Kmac) using TR-SAC 1.01, 4.2")
        let smskg = SecureMessagingSessionKeyGenerator()
        self.ksenc = try smskg.deriveKey(keySeed: kseed, mode: .ENC_MODE)
        self.ksmac = try smskg.deriveKey(keySeed: kseed, mode: .MAC_MODE)
                
        return (ksenc, ksmac)
    }
    
    ///
    /// Calculate the kseed from the kmrz:
    /// - Calculate a SHA-1 hash of the kmrz
    /// - Take the most significant 16 bytes to form the Kseed.
    /// @param kmrz: The MRZ information
    /// @type kmrz: a string
    /// @return: a 16 bytes string
    ///
    /// - Parameter kmrz: mrz key
    /// - Returns: first 16 bytes of the mrz SHA1 hash
    ///
    func generateInitialKseed(kmrz : String ) -> [UInt8] {
        
        Logger.bac.debug("Calculate the SHA-1 hash of MRZ_information")
        let hash = calcSHA1Hash( [UInt8](kmrz.data(using:.utf8)!) )
        
        let subHash = Array(hash[0..<16])
        Logger.bac.debug("Take the most significant 16 bytes to form the Kseed")
        
        return Array(subHash)
    }
    
    
    /// Construct the command data for the mutual authentication.
    /// - Request an 8 byte random number from the MRTD's chip (rnd.icc)
    /// - Generate an 8 byte random (rnd.ifd) and a 16 byte random (kifd)
    /// - Concatenate rnd.ifd, rnd.icc and kifd (s = rnd.ifd + rnd.icc + kifd)
    /// - Encrypt it with TDES and the Kenc key (eifd = TDES(s, Kenc))
    /// - Compute the MAC over eifd with TDES and the Kmax key (mifd = mac(pad(eifd))
    /// - Construct the APDU data for the mutualAuthenticate command (cmd_data = eifd + mifd)
    ///
    /// @param rnd_icc: The challenge received from the ICC.
    /// @type rnd_icc: A 8 bytes binary string
    /// @return: The APDU binary data for the mutual authenticate command
    func authentication( rnd_icc : [UInt8]) -> [UInt8] {
        self.rnd_icc = rnd_icc
        
        Logger.bac.debug("Request an 8 byte random number from the MRTD's chip")

        let rnd_ifd = generateRandomUInt8Array(8)
        let kifd = generateRandomUInt8Array(16)
        
        Logger.bac.debug("Generate an 8 byte random and a 16 byte random")
        
        let s = rnd_ifd + rnd_icc + kifd
        
        Logger.bac.debug("Concatenate RND.IFD, RND.ICC and Kifd")
        
        let iv : [UInt8] = [0, 0, 0, 0, 0, 0, 0, 0]
        let eifd = tripleDESEncrypt(key: ksenc,message: s, iv: iv)
        
        Logger.bac.debug("Encrypt S with TDES key Kenc as calculated in Appendix 5.2")
        
        let mifd = mac(algoName: .DES, key: ksmac, msg: pad(eifd, blockSize:8))

        Logger.bac.debug("Compute MAC over eifd with TDES key Kmac as calculated in-Appendix 5.2")
        // Construct APDU
        
        let cmd_data = eifd + mifd
        Logger.bac.debug("Construct command data for MUTUAL AUTHENTICATE")
        
        self.rnd_ifd = rnd_ifd
        self.kifd = kifd

        return cmd_data
    }
    
    /// Calculate the session keys (KSenc, KSmac) and the SSC from the data
    /// received by the mutual authenticate command.
    
    /// @param data: the data received from the mutual authenticate command send to the chip.
    /// @type data: a binary string
    /// @return: A set of two 16 bytes keys (KSenc, KSmac) and the SSC
    public func sessionKeys(data : [UInt8] ) throws -> ([UInt8], [UInt8], [UInt8]) {
        Logger.bac.debug("Decrypt and verify received data and compare received RND.IFD with generated RND.IFD")

        // ICAO 9303-11: response is E_ICC (32) || M_ICC (8)
        guard data.count >= 40 else {
            throw NFCPassportReaderError.InvalidMRZKey
        }

        let eicc = [UInt8](data[0..<32])
        let micc = [UInt8](data[32..<40])
        let computedMac = mac(algoName: .DES, key: self.ksmac, msg: pad(eicc, blockSize: 8))
        guard computedMac == micc else {
            throw NFCPassportReaderError.InvalidResponseChecksum
        }

        let response = tripleDESDecrypt(key: self.ksenc, message: eicc, iv: [0,0,0,0,0,0,0,0] )
        guard response.count >= 32 else {
            throw NFCPassportReaderError.InvalidMRZKey
        }

        let response_rndicc = [UInt8](response[0..<8])
        let response_rndifd = [UInt8](response[8..<16])
        let response_kicc = [UInt8](response[16..<32])
        guard response_rndicc == self.rnd_icc, response_rndifd == self.rnd_ifd else {
            throw NFCPassportReaderError.InvalidMRZKey
        }

        let Kseed = xor(self.kifd, response_kicc)
        Logger.bac.debug("Calculate XOR of Kifd and Kicc")
        
        let smskg = SecureMessagingSessionKeyGenerator()
        let KSenc = try smskg.deriveKey(keySeed: Kseed, mode: .ENC_MODE)
        let KSmac = try smskg.deriveKey(keySeed: Kseed, mode: .MAC_MODE)
        
        Logger.bac.debug("Calculate Session Keys (KSenc and KSmac) using Appendix 5.1")
        
        let ssc = [UInt8](self.rnd_icc.suffix(4) + self.rnd_ifd.suffix(4))
        Logger.bac.debug("Calculate Send Sequence Counter")
        return (KSenc, KSmac, ssc)
    }
    
}
#endif
