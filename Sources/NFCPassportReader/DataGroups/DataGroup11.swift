//
//  DataGroup11.swift
//
//  Created by Andy Qua on 01/02/2021.
//

import Foundation

@available(iOS 13, macOS 10.15, *)
public class DataGroup11 : DataGroup {
    
    public private(set) var fullName : String?
    public private(set) var otherNames : [String]?
    public private(set) var personalNumber : String?
    public private(set) var dateOfBirth : String?
    public private(set) var placeOfBirth : String?
    public private(set) var address : String?
    public private(set) var telephone : String?
    public private(set) var profession : String?
    public private(set) var title : String?
    public private(set) var personalSummary : String?
    public private(set) var proofOfCitizenship : String?
    public private(set) var tdNumbers : String?
    public private(set) var custodyInfo : String?

    public override var datagroupType: DataGroupId { .DG11 }

    required init( _ data : [UInt8] ) throws {
        try super.init(data)
    }

    override func parse(_ data: [UInt8]) throws {
        var tag = try getNextTag()
        try verifyTag(tag, equals: 0x5C)
        _ = try getNextValue()
        
        repeat {
            tag = try getNextTag()
            if tag == 0xA0 {
                otherNames = try parseOtherNames()
                continue
            }
            let val = try String( bytes:getNextValue(), encoding:.utf8)
            if tag == 0x5F0E {
                fullName = val
            } else if tag == 0x5F10 {
                personalNumber = val
            } else if tag == 0x5F11 {
                placeOfBirth = val
            } else if tag == 0x5F2B {
                dateOfBirth = val
            } else if tag == 0x5F42 {
                address = val
            } else if tag == 0x5F12 {
                telephone = val
            } else if tag == 0x5F13 {
                profession = val
            } else if tag == 0x5F14 {
                title = val
            } else if tag == 0x5F15 {
                personalSummary = val
            } else if tag == 0x5F16 {
                proofOfCitizenship = val
            } else if tag == 0x5F17 {
                tdNumbers = val
            } else if tag == 0x5F18 {
                custodyInfo = val
            }
        } while pos < data.count
    }

    /// Other names (tag A0): the number of names (tag 02), then each name (tag 5F0F)
    private func parseOtherNames() throws -> [String] {
        _ = try getNextLength()
        let countTag = try getNextTag()
        try verifyTag(countTag, equals: 0x02)
        let count = try getNextValue().first ?? 0

        var names = [String]()
        for _ in 0 ..< count {
            let tag = try getNextTag()
            try verifyTag(tag, equals: 0x5F0F)
            if let name = try String( bytes:getNextValue(), encoding:.utf8) {
                names.append(name)
            }
        }
        return names
    }
}
