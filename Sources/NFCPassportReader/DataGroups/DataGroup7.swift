//
//  DataGroup7.swift
//
//  Created by Andy Qua on 01/02/2021.
//

@available(iOS 13, *)
public class DataGroup7 : DataGroup {
    
    public private(set) var imageData : [UInt8] = []
    
    required init( _ data : [UInt8] ) throws {
        try super.init(data)
        datagroupType = .DG7
    }
    
    func getImage() -> UIImage? {
        if imageData.count == 0 {
            return nil
        }
        
        let image = UIImage(data:Data(imageData) )
        return image
    }
    
    
    override func parse(_ data: [UInt8]) throws {
        var tag = try getNextTag()
        if tag != 0x02 {
            throw NFCPassportReaderError.InvalidResponse
        }
        _ = try getNextValue()
        
        tag = try getNextTag()
        if tag != 0x5F43 {
            throw NFCPassportReaderError.InvalidResponse
        }
        
        imageData = try getNextValue()
    }
}
