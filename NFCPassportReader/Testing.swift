//
//  Testing.swift
//  NFCTest
//
//  Created by Andy Qua on 11/06/2019.
//  Copyright © 2019 Andy Qua. All rights reserved.
//

import Foundation
import CoreNFC

/// Just a quick class for testing stuff
class Testing {
    
    func doTest() {
        
    }

    func testDES3Encryption() {
        let msg = [UInt8]("maryhadalittlelambaaaaaa".data(using: .utf8)!)
        let iv : [UInt8] = [0, 0, 0, 0, 0, 0, 0, 0]
        let key : [UInt8] = [191, 73, 56, 112, 158, 148, 146, 127, 157, 76, 117, 8, 239, 128, 87, 42]
        let enc = tripleDESEncrypt(key: key, message: msg, iv: iv)
        let dec = tripleDESDecrypt(key: key, message: enc, iv: iv)
        log.debug("KEY: \(binToHexRep(key))")
        log.debug("MSG: \(binToHexRep(msg))")
        log.debug("ENC: \(binToHexRep(enc))")
        log.debug("DEC: \(binToHexRep(dec))")
    }
    
    func testSessionKeyHandling() {
        
        let sessionData = hexRepToBin("6A904F9AAB554AA99B8B7C79470829335C732E8601ED728B04EA0A00C97BA924B4042B12DE260089")
        let handler = BACHandler( )
        handler.ksenc = hexRepToBin("45F83D1C8F298CC2A4E64A7F20C11C7A")
        handler.ksmac = hexRepToBin("017AD9988F73862AAE2CD9EA839D2CA8")
        handler.kifd = hexRepToBin("F3187BC597491B3015B78FDCA309AC08")
        
        let (KSenc, KSmac, ssc) = handler.sessionKeys(data:sessionData)
        log.debug( "Generated session keys" )
        log.debug( "   KSenc - \(KSenc)" )
        log.debug( "   KSmac - \(KSmac)" )
        log.debug( "   ssc - \(ssc)" )
    }
    
    func testSecureMessagingProtect() {
        
        let KSenc = hexRepToBin("979EC13B1CBFE9DCD01AB0FED307EAE5")
        let KSmac = hexRepToBin("F1CB1F1FB5ADF208806B89DC579DC1F8")
        let ssc = hexRepToBin("887022120C06C226")
        
        let sm = SecureMessaging(ksenc: KSenc, ksmac: KSmac, ssc: ssc)
        
        let data : [UInt8] = [0x00, 0xA4, 0x02, 0x0C, 0x02, 0x01, 0x1E, 0x00]
        let apdu = NFCISO7816APDU(data:Data(data))!
        //        let apdu = NFCISO7816APDU(instructionClass: 0x00, instructionCode: 0xA4, p1Parameter: 0x02, p2Parameter: 0x0C, data: Data([0x01, 0x1E]), expectedResponseLength: -1)
        let protApdu = try! sm.protect( apdu: apdu )
        print( "Protected APDU:" )
        print( "   instructionClass       - \(binToHexRep(protApdu.instructionClass))" )
        print( "   instructionCode        - \(binToHexRep(protApdu.instructionCode))" )
        print( "   p1Parameter            - \(binToHexRep(protApdu.p1Parameter))" )
        print( "   p2Parameter            - \(binToHexRep(protApdu.p2Parameter))" )
        print( "   data                   - \(binToHexRep([UInt8](protApdu.data ?? Data())))" )
        print( "   expectedResponseLength - \(binToHexRep(UInt8(protApdu.expectedResponseLength)))" )
    }
    
    func testSecureMessagingUnprotect() {
        
        let KSenc = hexRepToBin("70D67043E57308D961A4F8A7C77C986D")
        let KSmac = hexRepToBin("38512CAB790480D051DF4389EF315898")
        let ssc = hexRepToBin("2FD7F3450917665A")
        
        let sm = SecureMessaging(ksenc: KSenc, ksmac: KSmac, ssc: ssc)
        let data = hexRepToBin("8709014D3671088A50A89F990290008E081C4EF9BADFCCAACB9000")
        let rep = ResponseAPDU(data: data, sw1: 0x90, sw2: 0)
        let unprotectedRespApdu = try! sm.unprotect(rapdu: rep)
        
        print( "Unprotected Response APDU:" )
        print( "   data                   - \(binToHexRep(unprotectedRespApdu.data)))" )
        print( "   p1Parameter            - \(binToHexRep(unprotectedRespApdu.sw1))" )
        print( "   p2Parameter            - \(binToHexRep(unprotectedRespApdu.sw2))" )

    }
}
