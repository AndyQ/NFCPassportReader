//
//  DataGroupParsingTests.swift
//  
//
//  Created by Andy Qua on 15/06/2019.
//

import Foundation
import XCTest

@testable import NFCPassportReader


final class DataGroupParsingTests: XCTestCase {
    func testDatagroup1Parsing() {
        
        // Random generated test MRZ
        let mrz = "P<GBRTHATCHER<<BOB<<<<<<<<<<<<<<<<<<<<<<<<<<7125143269GBR3906022M1601013<<<<<<<<<<<<<<08"
        let mrzBin = [UInt8](mrz.data(using: .utf8)!)
        let tag = try! [0x5F,0x1F] +  toAsn1Length(mrzBin.count) + mrzBin
        let dg1 = try! [0x61] + toAsn1Length(tag.count) + tag
        
        let dgp = DataGroupParser()
        XCTAssertNoThrow(try dgp.parseDG(data: dg1)) { dg in
            XCTAssertNotNil(dg)
            XCTAssertTrue( dg is DataGroup1 )
        }
    }
    
    func testDatagroup2ParsingJPEG2000() {
        
        // This is a cut down version of the DG2 record. It contains everything up to the end of the image header - no actuall image data as its way too big to include here
        // I've also adjusted the record lengths accordingly
        
        let dg2 = hexRepToBin("75617F61570201017F6082203FA1128002010081010282010087020101880200085F2E38464143003031300000002026000100002018000000000000000000010000000000000001000000000000000000000000000C6A5020200D0A")
        
        let dgp = DataGroupParser()
        XCTAssertNoThrow(try dgp.parseDG(data: dg2)) { dg in
            XCTAssertNotNil(dg)
            XCTAssertTrue( dg is DataGroup2 )
        }
        
    }
    
    func testDatagroup2ParsingJPEG() {
        
        // This is a cut down version of the DG2 record. It contains everything up to the begininnig of what would be the image data - no actual image data as its way too big to include here
        // I've also adjusted the record lengths accordingly
        
        let dg2 = hexRepToBin("75617F618220470201017F6082203FA1128002010081010282010087020101880200085F2E3846414300303130000000202600010000201800000000000000000001000000000000000100000000000000000000FFD8FFE000104A464946")
        let dgp = DataGroupParser()
        XCTAssertNoThrow(try dgp.parseDG(data: dg2)) { dg in
            XCTAssertNotNil(dg)
            XCTAssertTrue( dg is DataGroup2 )
        }
    }
    
    func testDatagroup7ParsingJPEG() {
        
        // This is a cut down version of the DG7 record. It contains everything up to the end of the image header - no actuall image data as its way too big to include here
        // I've also adjusted the record lengths accordingly
        
        let dg7 = hexRepToBin("678220060201015F4300")
        let dgp = DataGroupParser()
        XCTAssertNoThrow(try dgp.parseDG(data: dg7)) { dg in
            XCTAssertNotNil(dg)
            XCTAssertTrue( dg is DataGroup7 )
        }
    }
    
    func testCOMDatagroupParsing() {
        let com = hexRepToBin("601A5F0104303130375F36063034303030305C08617563676B6C6E6F")
        let dgp = DataGroupParser()
        XCTAssertNoThrow(try dgp.parseDG(data: com)) { dg in
            XCTAssertNotNil(dg)
            XCTAssertTrue( dg is COM )
            guard let com = dg as? COM else { XCTFail(); return }
            
            // Version should be 0x30313037 or [0x30, 0x31, 0x30, 0x37]
            XCTAssertEqual( com.version, 0x30313037)
            
            // Unicode version should be 0x303430303030 or [0x30, 0x34, 0x30, 0x30, 0x30, 0x30]
            XCTAssertEqual( com.unicodeVersion, 0x303430303030)
            
            // Datagroups present are COM, DG1, DG2, DG3, DG7, DG11, DG12, DG14, DG15
            XCTAssertEqual( com.dataGroupsPresent,[0x61, 0x75, 0x63, 0x67, 0x6B, 0x6C, 0x6E, 0x6F])

        }
    }
    
    static var allTests = [
        ("testDatagroup1Parsing", testDatagroup1Parsing),
        ("testDatagroup2Parsing", testDatagroup2ParsingJPEG2000),
        ("testDatagroup2ParsingJPEG", testDatagroup2ParsingJPEG),
        ("testCOMDatagroupParsing", testCOMDatagroupParsing),
    ]
    
}
