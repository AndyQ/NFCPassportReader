//
//  DataGroup7.swift
//
//  Created by Andy Qua on 01/02/2021.
//

import Foundation

#if !os(macOS)
import UIKit
#endif

@available(iOS 13, macOS 10.15, *)
public class DataGroup7 : DataGroup {
    
    public private(set) var imageData : [UInt8] = []

    public override var datagroupType: DataGroupId { .DG7 }

    required init( _ data : [UInt8] ) throws {
        try super.init(data)
    }
    
#if !os(macOS)
    func getImage() -> UIImage? {
        if imageData.count == 0 {
            return nil
        }
        
        let image = UIImage(data:Data(imageData) )
        return image
    }
#endif
    
    
    override func parse(_ data: [UInt8]) throws {
        var tag = try getNextTag()
        try verifyTag(tag, equals: 0x02)
        _ = try getNextValue()
        
        tag = try getNextTag()
        try verifyTag(tag, equals: 0x5F43)
        
        imageData = try getNextValue()
    }
}
