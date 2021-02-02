//
//  NotImplementedDG.swift
//
//  Created by Andy Qua on 01/02/2021.
//

@available(iOS 13, *)
public class NotImplementedDG : DataGroup {
    required init( _ data : [UInt8] ) throws {
        try super.init(data)
        datagroupType = .Unknown
    }
}

