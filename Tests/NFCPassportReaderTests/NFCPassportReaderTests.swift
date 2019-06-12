import XCTest
import CoreNFC

@testable import NFCPassportReader

public func XCTAssertNoThrow<T>(_ expression: @autoclosure () throws -> T, _ message: String = "", file: StaticString = #file, line: UInt = #line, also validateResult: (T) -> Void) {
    func executeAndAssignResult(_ expression: @autoclosure () throws -> T, to: inout T?) rethrows {
        to = try expression()
    }
    var result: T?
    XCTAssertNoThrow(try executeAndAssignResult(expression(), to: &result), message, file: file, line: line)
    if let r = result {
        validateResult(r)
    }
}


final class NFCPassportReaderTests: XCTestCase {

    func testBinToHexRep() {
        let val : [UInt8] = [0x12, 0x24, 0x55, 0x77]
        XCTAssertEqual( binToHexRep(val), "12245577" )
    }
    
    func testHexRepToBin() {
        let val : [UInt8] = [0x12, 0x24, 0x55, 0x77]
        XCTAssertEqual( hexRepToBin("12245577"), val  )
    }
    
    func testDES3Encryption() {
        let msg = [UInt8]("maryhadalittlelambaaaaaa".data(using: .utf8)!)
        let iv : [UInt8] = [0, 0, 0, 0, 0, 0, 0, 0]
        let key : [UInt8] = [191, 73, 56, 112, 158, 148, 146, 127, 157, 76, 117, 8, 239, 128, 87, 42]
        let enc = tripleDESEncrypt(key: key, message: msg, iv: iv)
        Log.debug("KEY: \(binToHexRep(key))")
        Log.debug("MSG: \(binToHexRep(msg))")
        Log.debug("ENC: \(binToHexRep(enc))")
        
        XCTAssertEqual( binToHexRep(enc), "4DAF068AB358BC9E8F5E916D3DEDE750D92315370E44D9B3" )
    }
    
    func testDES3Decryption() {
        let enc = hexRepToBin("4DAF068AB358BC9E8F5E916D3DEDE750D92315370E44D9B3")
        let iv : [UInt8] = [0, 0, 0, 0, 0, 0, 0, 0]
        let key : [UInt8] = [191, 73, 56, 112, 158, 148, 146, 127, 157, 76, 117, 8, 239, 128, 87, 42]
        let dec = tripleDESDecrypt(key: key, message: enc, iv: iv)
        Log.debug("KEY: \(binToHexRep(key))")
        Log.debug("ENC: \(binToHexRep(enc))")
        Log.debug("DEC: \(binToHexRep(dec))")
        
        let val = String(data:Data(dec), encoding:.utf8)
        XCTAssertEqual( val, "maryhadalittlelambaaaaaa" )
    }
    
    func testSecureMessagingProtect() {
        
        let KSenc = hexRepToBin("8FDCFE759E40A4DF4575160B3BFB79FB")
        let KSmac = hexRepToBin("2AE92531E55707D9C4CEF8C2D6E5AD70")
        let ssc = hexRepToBin("73061884A0E57AA7")
        
        let sm = SecureMessaging(ksenc: KSenc, ksmac: KSmac, ssc: ssc)
        
        let data : [UInt8] = [0x00, 0xA4, 0x02, 0x0C, 0x02, 0x01, 0x01, 0x00]
        let apdu = NFCISO7816APDU(data:Data(data))!
        let protApdu = try! sm.protect( apdu: apdu )
        
        XCTAssertNotNil(protApdu.data )
        XCTAssertEqual( protApdu.instructionClass, 0x0c )
        XCTAssertEqual( protApdu.instructionCode, 0xA4 )
        XCTAssertEqual( protApdu.p1Parameter, 0x02 )
        XCTAssertEqual( protApdu.p2Parameter, 0x0c )
        
        let hexDataRep = binToHexRep( [UInt8](protApdu.data!))
        XCTAssertEqual( hexDataRep, "870901CC69089F8F1AB4698E08B6334B3ABD5A9E09" )
        XCTAssertEqual( protApdu.expectedResponseLength, 0 )
    }

    func testSecureMessagingUnprotectNoData() {
        
        // Note - same keys as above but SSC incremented by 1 as per spec
        let KSenc = hexRepToBin("8FDCFE759E40A4DF4575160B3BFB79FB")
        let KSmac = hexRepToBin("2AE92531E55707D9C4CEF8C2D6E5AD70")
        let ssc = hexRepToBin("73061884A0E57AA8")
        
        let sm = SecureMessaging(ksenc: KSenc, ksmac: KSmac, ssc: ssc)
        
        let data : [UInt8] = hexRepToBin("990290008E08C61E440E5DD415469000")
        let protRespApdu = ResponseAPDU(data: data, sw1: 0x90, sw2: 0x00)
        
        XCTAssertNoThrow(try sm.unprotect( rapdu: protRespApdu )) { rapdu in
            XCTAssertEqual(binToHexRep(rapdu.data), "")
            XCTAssertEqual( rapdu.sw1, 0x90 )
            XCTAssertEqual( rapdu.sw2, 0x00 )
        }
    }

    func testSecureMessagingUnprotectWithData() {
        
        let KSenc = hexRepToBin("8FDCFE759E40A4DF4575160B3BFB79FB")
        let KSmac = hexRepToBin("2AE92531E55707D9C4CEF8C2D6E5AD70")
        let ssc = hexRepToBin("73061884A0E57AAA")
        
        let sm = SecureMessaging(ksenc: KSenc, ksmac: KSmac, ssc: ssc)
        
        let data : [UInt8] = hexRepToBin("87090156D0EFCC887F8973990290008E08D6B9C0DA21DC965F9000")
        let protRespApdu = ResponseAPDU(data: data, sw1: 0x90, sw2: 0x00)
        
        XCTAssertNoThrow(try sm.unprotect( rapdu: protRespApdu )) { rapdu in
            XCTAssertEqual(binToHexRep(rapdu.data), "615B5F1F")
            XCTAssertEqual( rapdu.sw1, 0x90 )
            XCTAssertEqual( rapdu.sw2, 0x00 )

        }
    }

    static var allTests = [
        ("testBinToHexRep", testBinToHexRep),
        ("testHexRepToBin", testHexRepToBin),
        ("testDES3Encryption", testDES3Encryption),
        ("testDES3Decryption", testDES3Decryption),
        ("testSecureMessagingProtect", testSecureMessagingProtect),
        ("testSecureMessagingUnprotectNoData", testSecureMessagingUnprotectNoData),
        ("testSecureMessagingUnprotectWithData", testSecureMessagingUnprotectWithData)
    ]
}
