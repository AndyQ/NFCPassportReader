//
//  BACHandler.swift
//  NFCTest
//
//  Created by Andy Qua on 07/06/2019.
//  Copyright © 2019 Andy Qua. All rights reserved.
//

import Foundation
import CoreNFC

@available(iOS 13, *)
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

    public func performBACAndGetSessionKeys( mrzKey : String, completed: @escaping (_ error : TagError?)->() ) {
        guard let tagReader = self.tagReader else {
            completed( TagError.NoConnectedTag)
            return
        }
        
        _ = self.deriveDocumentBasicAccessKeys(mrz: mrzKey)
        
        // Make sure we clear secure messaging (could happen if we read an invalid DG or we hit a secure error
        tagReader.secureMessaging = nil
        
        // get Challenge
        tagReader.getChallenge() { [unowned self] (response, error) in
            
            guard let response = response else {
                Log.debug( "ERROR - \(error?.localizedDescription ?? "")" )
                completed( error )
                return
            }
            
            Log.debug( "DATA - \(response.data)" )
            let cmd_data = self.authentication(rnd_icc: [UInt8](response.data))
            tagReader.doMutualAuthentication(cmdData: Data(cmd_data)) { [unowned self] (response, error) in
                guard let response = response else {
                    Log.debug( "ERROR - \(error?.localizedDescription ?? "")" )
                    completed( error )
                    return
                }
                Log.debug( "DATA - \(response.data)" )
                
                let (KSenc, KSmac, ssc) = self.sessionKeys(data: [UInt8](response.data))
                tagReader.secureMessaging = SecureMessaging(ksenc: KSenc, ksmac: KSmac, ssc: ssc)
                completed( nil)
            }
        }
    }


    func deriveDocumentBasicAccessKeys(mrz: String) -> ([UInt8], [UInt8]) {
        let kmrz = getMRZInfo(mrz: mrz)
        let kseed = generateInitialKseed(kmrz:kmrz)
    
        Log.debug("Calculate the Basic Acces Keys (Kenc and Kmac) using Appendix 5.1")
        let (kenc, kmac) = computeKeysFromKseed(Kseed: kseed)
        self.ksenc = kenc
        self.ksmac = kmac
                
        return (kenc, kmac)
    }
    
    /// - Parameter mrz:
    func getMRZInfo( mrz : String ) -> String {
        let kmrz = mrz
        //        kmrz = docNumber + docNumberChecksum + \
        //            mrz.dateOfBirth + mrz.dateOfBirthCheckSum + \
        //                mrz.dateOfExpiry + mrz.dateOfExpiryChecksum
        
        return kmrz
    }
    
    ///
    /// Calculate the kseed from the kmrz:
    /// - Calculate a SHA-1 hash of the kmrz
    /// - Take the most significant 16 bytes to form the Kseed.
    /// @param kmrz: The MRZ information
    /// @type kmrz: a string
    /// @return: a 16 bytes string
    ///
    /// - Parameter kmrz: <#kmrz description#>
    /// - Returns: first 16 bytes of the mrz SHA1 hash
    ///
    func generateInitialKseed(kmrz : String ) -> [UInt8] {
        
        Log.debug("Calculate the SHA-1 hash of MRZ_information")
        let hash = calcSHA1Hash( [UInt8](kmrz.data(using:.utf8)!) )
        
        Log.debug("\tHsha1(MRZ_information): \(binToHexRep(hash))")
        
        let subHash = Array(hash[0..<16])
        Log.debug("Take the most significant 16 bytes to form the Kseed")
        Log.debug("\tKseed: \(binToHexRep(subHash))" )
        
        return Array(subHash)
    }
    

    func computeKeysFromKseed(Kseed : [UInt8] ) -> ([UInt8], [UInt8]) {
        Log.debug("Compute Encryption key (c: \(binToHexRep(KENC))")
        let kenc = self.keyDerivation(kseed: Kseed, c: KENC)
        
        Log.debug("Compute MAC Computation key (c: \(binToHexRep(KMAC))")
        let kmac = self.keyDerivation(kseed: Kseed, c: KMAC)
        
        //        return (kenc, kmac)
        return (kenc, kmac)
    }
    
    /// Key derivation from the kseed:
    /// - Concatenate Kseed and c (c=0 for KENC or c=1 for KMAC)
    /// - Calculate the hash of the concatenation of kseed and c (h = (sha1(kseed + c)))
    /// - Adjust the parity bits
    /// - return the key (The first 8 bytes are Ka and the next 8 bytes are Kb)
    /// @param kseed: The Kseed
    /// @type kseed: a 16 bytes string
    /// @param c: specify if it derives KENC (c=0) of KMAC (c=1)
    /// @type c: a byte
    /// @return: Return a 16 bytes key
    func keyDerivation( kseed : [UInt8], c: [UInt8] ) -> [UInt8] {
        //        if c not in (BAC.KENC,BAC.KMAC):
        //        raise BACException, "Bad parameter (c=0 or c=1)"
        
        let d = kseed + c
        Log.debug("\tConcatenate Kseed and c")
        Log.debug("\t\tD: \(binToHexRep(d))" )
        
        let h = calcSHA1Hash(d)
        
        //        h = sha1(str(d)).digest()
        Log.debug("\tCalculate the SHA-1 hash of D")
        Log.debug("\t\tHsha1(D): \(binToHexRep(h))")
        
        var Ka = Array(h[0..<8])
        var Kb = Array(h[8..<16])
        
        Log.debug("\tForm keys Ka and Kb")
        Log.debug("\t\tKa: \(binToHexRep(Ka))")
        Log.debug("\t\tKb: \(binToHexRep(Kb))")
        
        Ka = self.DESParity(Ka)
        Kb = self.DESParity(Kb)
        
        Log.debug("\tAdjust parity bits")
        Log.debug("\t\tKa: \(binToHexRep(Ka))")
        Log.debug("\t\tKb: \(binToHexRep(Kb))")

        return Ka+Kb
    }
    
    func DESParity(_ data : [UInt8] ) -> [UInt8] {
        var adjusted = [UInt8]()
        for x in data {
            let y = x & 0xfe
            var parity :UInt8 = 0
            for z in 0 ..< 8 {
                parity += y >> z & 1
            }
            
            let s = y + (parity % 2 == 0 ? 1 : 0)
            
            adjusted.append(s) // chr(y + (not parity % 2))
        }
        return adjusted
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
        
        Log.debug("Request an 8 byte random number from the MRTD's chip")
        Log.debug("\tRND.ICC: " + binToHexRep(self.rnd_icc))
        
        self.rnd_icc = rnd_icc

        let rnd_ifd = generateRandomUInt8Array(8)
        let kifd = generateRandomUInt8Array(16)
        
        Log.debug("Generate an 8 byte random and a 16 byte random")
        Log.debug("\tRND.IFD: \(binToHexRep(rnd_ifd))" )
        Log.debug("\tRND.Kifd: \(binToHexRep(kifd))")
        
        let s = rnd_ifd + rnd_icc + kifd
        
        Log.debug("Concatenate RND.IFD, RND.ICC and Kifd")
        Log.debug("\tS: \(binToHexRep(s))")
        
        let iv : [UInt8] = [0, 0, 0, 0, 0, 0, 0, 0]
        let eifd = tripleDESEncrypt(key: ksenc,message: s, iv: iv)
        
        Log.debug("Encrypt S with TDES key Kenc as calculated in Appendix 5.2")
        Log.debug("\tEifd: \(binToHexRep(eifd))")
        
        let mifd = mac(key: ksmac, msg: pad(eifd))

        Log.debug("Compute MAC over eifd with TDES key Kmac as calculated in-Appendix 5.2")
        Log.debug("\tMifd: \(binToHexRep(mifd))")
        // Construct APDU
        
        let cmd_data = eifd + mifd
        Log.debug("Construct command data for MUTUAL AUTHENTICATE")
        Log.debug("\tcmd_data: \(binToHexRep(cmd_data))")
        
        self.rnd_ifd = rnd_ifd
        self.kifd = kifd

        return cmd_data
    }
    
    /// Calculate the session keys (KSenc, KSmac) and the SSC from the data
    /// received by the mutual authenticate command.
    
    /// @param data: the data received from the mutual authenticate command send to the chip.
    /// @type data: a binary string
    /// @return: A set of two 16 bytes keys (KSenc, KSmac) and the SSC
    public func sessionKeys(data : [UInt8] ) -> ([UInt8], [UInt8], [UInt8]) {
        Log.debug("Decrypt and verify received data and compare received RND.IFD with generated RND.IFD \(binToHexRep(self.ksmac))" )
        
        let response = tripleDESDecrypt(key: self.ksenc, message: [UInt8](data[0..<32]), iv: [0,0,0,0,0,0,0,0] )

        let response_kicc = [UInt8](response[16..<32])
        let Kseed = xor(self.kifd, response_kicc)
        Log.debug("Calculate XOR of Kifd and Kicc")
        Log.debug("\tKseed: \(binToHexRep(Kseed))" )
        
        let KSenc = self.keyDerivation(kseed: Kseed,c: KENC)
        let KSmac = self.keyDerivation(kseed: Kseed,c: KMAC)
        
        Log.debug("Calculate Session Keys (KSenc and KSmac) using Appendix 5.1")
        Log.debug("\tKSenc: \(binToHexRep(KSenc))" )
        Log.debug("\tKSmac: \(binToHexRep(KSmac))" )
        
        
        let ssc = [UInt8](self.rnd_icc.suffix(4) + self.rnd_ifd.suffix(4))
        Log.debug("Calculate Send Sequence Counter")
        Log.debug("\tSSC: \(binToHexRep(ssc))" )
        return (KSenc, KSmac, ssc)
    }
    
}
