//
//  SecureMessaging.swift
//  NFCTest
//
//  Created by Andy Qua on 09/06/2019.
//  Copyright © 2019 Andy Qua. All rights reserved.
//

import Foundation
import CoreNFC

/// This class implements the secure messaging protocol.
/// The class is a new layer that comes between the reader and the iso7816.
/// It gives a new transmit method that takes an APDU object formed by the iso7816 layer,
/// ciphers it following the doc9303 specification, sends the ciphered APDU to the reader
/// layer and returns the unciphered APDU.
class SecureMessaging {
    private var ksenc : [UInt8]
    private var ksmac : [UInt8]
    private var ssc : [UInt8]
    
    
    init(ksenc : [UInt8], ksmac : [UInt8], ssc : [UInt8]) {
        self.ksenc = ksenc
        self.ksmac = ksmac
        self.ssc = ssc
    }

    /// Protect the apdu following the doc9303 specification
    func protect(apdu : NFCISO7816APDU ) throws -> NFCISO7816APDU {
    
        let cmdHeader = self.maskClassAndPad(apdu: apdu)
        var do87 : [UInt8] = []
        var do97 : [UInt8] = []
        
        var tmp = "Concatenate CmdHeader"
        if apdu.data != nil {
            tmp += " and DO87"
            do87 = try self.buildD087(apdu: apdu)
        }
        if apdu.expectedResponseLength > 0 {
            tmp += " and DO97"
            do97 = self.buildD097(apdu: apdu)
        }
        
        let M = cmdHeader + do87 + do97
        log.debug(tmp)
        log.debug("\tM: " + binToHexRep(M))
        
        log.debug("\t\tSSC: " + binToHexRep(self.ssc))
        self.ssc = self.incSSC()
        log.debug("Compute MAC of M")
        log.debug("\tIncrement SSC with 1")
        log.debug("\t\tSSC: " + binToHexRep(self.ssc))
        
        let N = pad(self.ssc + M)
        log.debug("\tConcatenate SSC and M and add padding")
        log.debug("\t\tN: " + binToHexRep(N))

        let CC = mac(key: self.ksmac, msg: N)
        log.debug("\tCompute MAC over N with KSmac")
        log.debug("\t\tCC: " + binToHexRep(CC))
        
        let do8e = self.buildD08E(mac: CC)
        let size = do87.count + do97.count + do8e.count
        var protectedAPDU = [UInt8](cmdHeader[0..<4]) + intToBin(size)
        protectedAPDU += do87 + do97 + do8e + [0x00]
        
        log.debug("Construct and send protected APDU")
        log.debug("\tProtectedAPDU: " + binToHexRep(protectedAPDU))
        
        let data = Data(do87 + do97 + do8e)
        let newAPDUData : [UInt8] = [UInt8](cmdHeader[0..<4]) + intToBin(data.count) + data + [0x00]
        let newAPDU = NFCISO7816APDU(data:Data(newAPDUData))!
        return newAPDU
    }

    /// Unprotect the APDU following the iso7816 specification
    func unprotect(rapdu : ResponseAPDU ) throws -> ResponseAPDU {
        var needCC = false
        var do87 : [UInt8] = []
        var do87Data : [UInt8] = []
        var do99 : [UInt8] = []
        //var do8e : [UInt8] = []
        var offset = 0
        
        // Check for a SM error
        if(rapdu.sw1 != 0x90 || rapdu.sw2 != 0x00) {
            return rapdu
        }
        
         let rapduBin = rapdu.data + [rapdu.sw1, rapdu.sw2]
        log.debug("Receive response APDU of MRTD's chip")
        log.debug("\tRAPDU: " + binToHexRep(rapduBin))
        
        // DO'87'
        // Mandatory if data is returned, otherwise absent
        if rapduBin[0] == 0x87 {
            let (encDataLength, o) = try asn1Length(data:[UInt8](rapduBin[1...]))
            offset = 1 + o
            
            if rapduBin[offset] != 0x1 {
                throw TagError.D087Malformed
//                raise SecureMessagingException("DO87 malformed, must be 87 L 01 <encdata> : " + binToHexRep(rapdu))
            }
            
            do87 = [UInt8](rapduBin[0 ..< offset + Int(encDataLength)])
            do87Data = [UInt8](rapduBin[offset+1 ..< offset + Int(encDataLength)])
            offset += Int(encDataLength)
            needCC = true
        }
        
        //DO'99'
        // Mandatory, only absent if SM error occurs
        do99 = [UInt8](rapduBin[offset..<offset+4])
        let sw1 = rapduBin[offset+2]
        let sw2 = rapduBin[offset+3]
        offset += 4
        needCC = true
        
        if do99[0] != 0x99 && do99[1] != 0x02 {
            //SM error, return the error code
            return ResponseAPDU(data: [], sw1: sw1, sw2: sw2)
        }
        
        // DO'8E'
        //Mandatory if DO'87' and/or DO'99' is present
        if rapduBin[offset] == 0x8E {
            let ccLength : Int = Int(binToHex(rapduBin[offset+1]))
            let CC = [UInt8](rapduBin[offset+2 ..< offset+2+ccLength])
            // do8e = [UInt8](rapduBin[offset ..< offset+2+ccLength])
            
            // CheckCC
            var tmp = ""
            if do87.count > 0 {
                tmp += " DO'87"
            }
            if do99.count > 0 {
                tmp += " DO'99"
            }
            log.debug("Verify RAPDU CC by computing MAC of" + tmp)
            
            log.debug("\t\tSSC: " + binToHexRep(self.ssc))
            self.ssc = self.incSSC()
            log.debug("\tIncrement SSC with 1")
            log.debug("\t\tSSC: " + binToHexRep(self.ssc))
            
            let K = pad(self.ssc + do87 + do99)
            log.debug("\tConcatenate SSC and" + tmp + " and add padding")
            log.debug("\t\tK: " + binToHexRep(K))
            
            log.debug("\tCompute MAC with KSmac")
            let CCb = mac(key: self.ksmac, msg: K)
            log.debug("\t\tCC: " + binToHexRep(CCb))
            
            let res = (CC == CCb)
            log.debug("\tCompare CC with data of DO'8E of RAPDU")
            log.debug("\t\t\(binToHexRep(CC))  == \(binToHexRep(CCb)) ? \(res)")
            
            if !res {
                throw TagError.InvalidResponseChecksum
                //raise SecureMessagingException("Invalid checksum for the rapdu : " + str(binToHex(rapdu)))
            }
        }
        else if needCC {
            throw TagError.MissingMandatoryFields
            //raise SecureMessagingException("Mandatory id DO'87' and/or DO'99' is present")
        }
        
        var data : [UInt8] = []
        if do87Data.count > 0 {
            // There is a payload
            let dec = tripleDESDecrypt(key: self.ksenc, message: do87Data, iv: [0,0,0,0,0,0,0,0])
            data = unpad(dec)
            log.debug("Decrypt data of DO'87 with KSenc")
            log.debug("\tDecryptedData: " + binToHexRep(data))
        }
        
        log.info("Unprotected APDU: [\(binToHexRep(data))] \(binToHexRep(sw1)) \(binToHexRep(sw2))" )
        return ResponseAPDU(data: data, sw1: sw1, sw2: sw2)
    }

    func maskClassAndPad(apdu : NFCISO7816APDU ) -> [UInt8] {
        log.debug("Mask class byte and pad command header")
        let res = pad([0x0c, apdu.instructionCode, apdu.p1Parameter, apdu.p2Parameter])
        log.debug("\tCmdHeader: " + binToHexRep(res))
        return res
    }
    
    func buildD087(apdu : NFCISO7816APDU) throws -> [UInt8] {
        let cipher = [0x01] + self.padAndEncryptData(apdu)
        let res = try [0x87] + toAsn1Length(data:UInt64(cipher.count)) + cipher
        log.debug("Build DO'87")
        log.debug("\tDO87: " + binToHexRep(res))
        return res
    }
    
    func padAndEncryptData(_ apdu : NFCISO7816APDU) -> [UInt8] {
        // Pad the data, encrypt data with KSenc and build DO'87
        let data = [UInt8](apdu.data!)
        let paddedData = pad( data )
        let enc = tripleDESEncrypt(key: self.ksenc, message: paddedData, iv: [0,0,0,0,0,0,0,0])
        log.debug("Pad data")
        log.debug("\tData: " + binToHexRep(paddedData))
        log.debug("Encrypt data with KSenc")
        log.debug("\tEncryptedData: " + binToHexRep(enc))
        return enc
    }
    
    func incSSC() -> [UInt8] {
        let val = binToHex(self.ssc) + 1
        return hexToBin( val )

//        out = binToHex(self.ssc) + 1
//        res = hexToBin(out)
//        return res
    }
    
    func buildD08E(mac : [UInt8]) -> [UInt8] {
        let res : [UInt8] = [0x8E, UInt8(mac.count)] + mac
        log.debug("Build DO'8E")
        log.debug("\tDO8E: \(binToHexRep(res))" )
        return res
    }

    func buildD097(apdu : NFCISO7816APDU) -> [UInt8] {
        let res : [UInt8] = [0x97, 0x01] + intToBin(apdu.expectedResponseLength)
        log.debug("Build DO'97")
        log.debug("\tDO97: \(res)")
        return res
    }
    
    
    /// Take an asn.1 length, and return a couple with the decoded length in hexa and the total length of the encoding (1,2 or 3 bytes)
    ///
    /// >>> from pyPassport.asn1.asn1 import *
    /// >>> asn1Length("\x22")
    /// (34, 1)
    /// >>> asn1Length("\x81\xaa")
    /// (170, 2)
    /// >>> asn1Length("\x82\xaa\xbb")
    /// (43707, 3)
    ///
    /// @param data: A length value encoded in the asn.1 format.
    /// @type data: A binary string.
    /// @return: A tuple with the decoded hexa length and the length of the asn.1 encoded value.
    /// @raise asn1Exception: If the parameter does not follow the asn.1 notation.

}
