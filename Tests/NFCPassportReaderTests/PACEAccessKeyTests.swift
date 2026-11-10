Tests/NFCPassportReaderTests/PACEAccessKeyTests.swift //
//  PACEAccessKeyTests.swift
//  NFCPassportReaderTests
//
//  K_pi = KDF(f(pi), 3) for the MRZ and the CAN (ICAO 9303-11, 9.7.3 and table 8).
//

import XCTest

@testable import NFCPassportReader

final class PACEAccessKeyTests: XCTestCase {

    /// ICAO 9303-11 Appendix H (PACE-IM worked examples) prints K_pi = 591468CD... Its text says it reuses the MRZ
    /// key from Appendix G, but the value is KDF_pi of the CAN "123456" with AES-128, so it doubles as a CAN vector.
    func testCANKeyMatchesICAOAppendixH() throws {
        let key = try PACEHandler.paceKey(for: .can("123456"), cipherAlg: "AES", keyLength: 128)
        XCTAssertEqual(binToHexRep(key), "591468CDA83D65219CCCB8560233600F")
    }

    /// The CAN itself is the seed: H(CAN || 00000003), with no SHA-1 of the CAN first.
    func testCANKeyIsKDFOfTheCANString() throws {
        let seed = [UInt8]("123456".utf8) + [0x00, 0x00, 0x00, 0x03]
        let key = try PACEHandler.paceKey(for: .can("123456"), cipherAlg: "AES", keyLength: 256)
        XCTAssertEqual(key, calcSHA256Hash(seed))
    }

    /// Appendix G: MRZ "T22000129" / "640812" / "101031" with check digits gives K_pi = 89DED1B2...
    func testMRZKeyMatchesICAOAppendixG() throws {
        let key = try PACEHandler.paceKey(for: .mrz("T22000129364081251010318"), cipherAlg: "AES", keyLength: 128)
        XCTAssertEqual(binToHexRep(key), "89DED1B26624EC1E634C1989302849DD")
    }

    func testEmptyOrNonLatin1CANIsRejected() {
        XCTAssertThrowsError(try PACEHandler.paceKey(for: .can(""), cipherAlg: "AES", keyLength: 128))
        XCTAssertThrowsError(try PACEHandler.paceKey(for: .can("12345€"), cipherAlg: "AES", keyLength: 128))
    }

    func testPasswordReferences() {
        XCTAssertEqual(PassportAccessKey.mrz("x").paceKeyReference, 0x01)
        XCTAssertEqual(PassportAccessKey.can("123456").paceKeyReference, 0x02)
        XCTAssertNil(PassportAccessKey.can("123456").mrzKey)
    }
}
