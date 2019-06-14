//
//  File.swift
//  
//
//  Created by Andy Qua on 14/06/2019.
//

import Foundation

class DataGroup {
    var datagroupType : DataGroupId = .Unknown
    
    required init( _ data : [UInt8] ) throws {
        try parse(data)
    }
    
    func parse( _ data:[UInt8] ) throws {
        throw TagError.NotImplemented
    }
}


class NotImplementedDG : DataGroup {
    required init( _ data : [UInt8] ) throws {
        try super.init(data)
        datagroupType = .Unknown
    }
}

class COM : DataGroup {
    required init( _ data : [UInt8] ) throws {
        try super.init(data)
        datagroupType = .COM
    }

}

class SOD : DataGroup {
     required init( _ data : [UInt8] ) throws {
        try super.init(data)
        datagroupType = .SOD
    }

}

class DataGroup1 : DataGroup {
    
    
    var elements : [String:String] = [:]
    
    required init( _ data : [UInt8] ) throws {
        try super.init(data)
        datagroupType = .DG1
    }

    override func parse(_ data: [UInt8]) throws {
        if data[0] != 0x5F && data[1] != 0xF1 {
            throw TagError.InvalidResponse
        }
        let (len, offset) = try asn1Length([UInt8](data[2...]))
        let body = [UInt8](data[(offset+2)...])
        //data = self["5F1F"]
        let docType = getMRZType(length:Int(len))
        
        if docType == "ID1" {
            self.parseTd1(body)
        } else if docType == "TD2" {
            self.parseTd2(body)
        } else {
            self.parseOther(body)
        }
    }
    
    func parseTd1(_ data : [UInt8]) {
        elements["5F03"] = String(bytes: data[0..<2], encoding:.utf8)
        elements["5F28"] = String( bytes:data[2..<5], encoding:.utf8)
        elements["5A"] = String( bytes:data[5..<14], encoding:.utf8)
        elements["5F04"] = String( bytes:data[14..<15], encoding:.utf8)
        elements["53"] = (String( bytes:data[15..<30], encoding:.utf8) ?? "") +
            (String( bytes:data[48..<59], encoding:.utf8) ?? "")
        elements["5F57"] = String( bytes:data[30..<36], encoding:.utf8)
        elements["5F05"] = String( bytes:data[36..<37], encoding:.utf8)
        elements["5F35"] = String( bytes:data[37..<38], encoding:.utf8)
        elements["59"] = String( bytes:data[38..<44], encoding:.utf8)
        elements["5F06"] = String( bytes:data[44..<45], encoding:.utf8)
        elements["5F2C"] = String( bytes:data[45..<48], encoding:.utf8)
        elements["5F07"] = String( bytes:data[59..<60], encoding:.utf8)
        elements["5B"] = String( bytes:data[60...], encoding:.utf8)
    }
    
    func parseTd2(_ data : [UInt8]) {
        elements["5F03"] = String( bytes:data[0..<2], encoding:.utf8)
        elements["5F28"] = String( bytes:data[2..<5], encoding:.utf8)
        elements["5B"] = String( bytes:data[5..<36], encoding:.utf8)
        elements["5A"] = String( bytes:data[36..<45], encoding:.utf8)
        elements["5F04"] = String( bytes:data[45..<46], encoding:.utf8)
        elements["5F2C"] = String( bytes:data[46..<49], encoding:.utf8)
        elements["5F57"] = String( bytes:data[49..<55], encoding:.utf8)
        elements["5F05"] = String( bytes:data[55..<56], encoding:.utf8)
        elements["5F35"] = String( bytes:data[56..<57], encoding:.utf8)
        elements["59"] = String( bytes:data[57..<63], encoding:.utf8)
        elements["5F06"] = String( bytes:data[63..<64], encoding:.utf8)
        elements["53"] = String( bytes:data[64..<71], encoding:.utf8)
        elements["5F07"] = String( bytes:data[71..<72], encoding:.utf8)
    }
    
    func parseOther(_ data : [UInt8]) {
        elements["5F03"] = String( bytes:data[0..<2], encoding:.utf8)
        elements["5F28"] = String( bytes:data[2..<5], encoding:.utf8)
        elements["5F5B"] = String( bytes:data[5..<44], encoding:.utf8)
        elements["5A"]   = String( bytes:data[44..<53], encoding:.utf8)
        elements["5F04"] = String( bytes:[data[53]], encoding:.utf8)
        elements["5F2C"] = String( bytes:data[54..<57], encoding:.utf8)
        elements["5F57"] = String( bytes:data[57..<63], encoding:.utf8)
        elements["5F05"] = String( bytes:[data[63]], encoding:.utf8)
        elements["5F35"] = String( bytes:[data[64]], encoding:.utf8)
        elements["59"]   = String( bytes:data[65..<71], encoding:.utf8)
        elements["5F06"] = String( bytes:[data[71]], encoding:.utf8)
        elements["53"]   = String( bytes:data[72..<86], encoding:.utf8)
        elements["5F02"] = String( bytes:[data[86]], encoding:.utf8)
        elements["5F07"] = String( bytes:[data[87]], encoding:.utf8)
    }
    
    private func getMRZType(length: Int) -> String {
        if length == 0x5A {
            return "TD1"
        }
        if length == 0x48 {
            return "TD2"
        }
        return "OTHER"
    }

}

class DataGroup2 : DataGroup {
    required init( _ data : [UInt8] ) throws {
        try super.init(data)
        datagroupType = .DG2
    }

}

class DataGroupParser {

    let dataGroupNames = ["Common", "DG1", "DG2", "DG3", "DG4", "DG5", "DG6", "DG7", "DG8", "DG9", "DG10", "DG11", "DG12", "DG13", "DG14", "DG15", "DG16", "SecurityData"]
    let tags : [UInt8] = [0x60, 0x61, 0x75, 0x63, 0x76, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x77]
    let classes : [DataGroup.Type] = [COM.self, DataGroup1.self, DataGroup2.self,
              NotImplementedDG.self, NotImplementedDG.self, NotImplementedDG.self,
              NotImplementedDG.self, NotImplementedDG.self, NotImplementedDG.self,
              NotImplementedDG.self, NotImplementedDG.self, NotImplementedDG.self,
              NotImplementedDG.self, NotImplementedDG.self, NotImplementedDG.self,
              NotImplementedDG.self, NotImplementedDG.self, SOD.self]


    func parseDG( data : [UInt8] ) throws -> DataGroup {
        
        let header = data[0..<4]
        let (_, offset) = try asn1Length( header[1...] )
        
        let dg = try tagToDG(header[0])
        let body = [UInt8](data[(offset+1)...])
        
        return try dg.init(body)
    }
    
    
    func tagToDG( _ tag : UInt8 ) throws -> DataGroup.Type {
        guard let index = tags.firstIndex(of: tag) else { throw TagError.UnknownTag}
        return classes[index]
    }
}
