//
//  Utils.swift
//  NFCTest
//
//  Created by Andy Qua on 09/06/2019.
//  Copyright © 2019 Andy Qua. All rights reserved.
//

import UIKit
import CommonCrypto

extension FileManager {
    static var documentDir : URL {
        return FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
    }
}

extension StringProtocol {
    subscript(bounds: CountableClosedRange<Int>) -> SubSequence {
        let start = index(startIndex, offsetBy: bounds.lowerBound)
        let end = index(start, offsetBy: bounds.count)
        return self[start..<end]
    }
    
    subscript(bounds: CountableRange<Int>) -> SubSequence {
        let start = index(startIndex, offsetBy: bounds.lowerBound)
        let end = index(start, offsetBy: bounds.count)
        return self[start..<end]
    }
    
    func index(of string: Self, options: String.CompareOptions = []) -> Index? {
        return range(of: string, options: options)?.lowerBound
    }

}


public func binToHexRep( _ val : [UInt8] ) -> String {
    var string = ""
    for x in val {
        string += String(format:"%02x", x )
    }
    return string.uppercased()
}

public func binToHexRep( _ val : UInt8 ) -> String {
    let string = String(format:"%02x", val ).uppercased()
    return string
}

public func binToHex( _ val: UInt8 ) -> UInt32 {
    let hexRep = String(format:"%02X", val)
    return UInt32(hexRep, radix:16)!
}

public func binToHex( _ val: [UInt8] ) -> UInt64 {
    let hexVal = UInt64(binToHexRep(val), radix:16)!
    return hexVal
}

public func hexToBin( _ val : UInt64 ) -> [UInt8] {
    let hexRep = String(format:"%lx", val)
    return hexRepToBin( hexRep)
}

public func intToBin(_ data : Int, pad : Int = 2) -> [UInt8] {
    if pad == 2 {
        let hex = String(format:"%02x", data)
        return hexRepToBin(hex)
    } else {
        let hex = String(format:"%04x", data)
        return hexRepToBin(hex)

    }
}

/// 'AABB' --> \xaa\xbb'"""
public func hexRepToBin(_ val : String) -> [UInt8] {
    var output : [UInt8] = []
    var x = 0
    while x < val.count {
        if x+2 <= val.count {
            output.append( UInt8(val[x ..< x + 2], radix:16)! )
        } else {
            output.append( UInt8(val[x ..< x+1], radix:16)! )

        }
        x += 2
    }
    return output
}

public func xor(_ kifd : [UInt8], _ response_kicc : [UInt8] ) -> [UInt8] {
    var kseed = [UInt8]()
    for i in 0 ..< kifd.count {
        kseed.append( kifd[i] ^ response_kicc[i] )
    }
    return kseed
}

public func generateRandomUInt8Array( _ size: Int ) -> [UInt8] {
    
    var ret : [UInt8] = []
    for _ in 0 ..< size {
        ret.append( UInt8(arc4random_uniform(UInt32(UInt8.max) + 1)) )
    }
    return ret
}

public func pad(_ toPad : [UInt8]) -> [UInt8] {
    let size = 8
    let padBlock : [UInt8] = [0x80, 0, 0, 0, 0, 0, 0, 0]
    let left = size - (toPad.count % size)
    return (toPad + [UInt8](padBlock[0 ..< left]))
}

public func unpad( _ tounpad : [UInt8]) -> [UInt8] {
    var i = tounpad.count-1
    while tounpad[i] == 0x00 {
        i -= 1
    }
    
    if tounpad[i] == 0x80 {
        return [UInt8](tounpad[0..<i])
    } else {
        // no padding
        return tounpad
    }
}

public func mac(key : [UInt8], msg : [UInt8]) -> [UInt8]{
    
    let size = msg.count / 8
    var y : [UInt8] = [0,0,0,0,0,0,0,0]
    
    
    for i in 0 ..< size {
        let tmp = [UInt8](msg[i*8 ..< i*8+8])
        Log.debug("x\(i): \(binToHexRep(tmp))" )
        y = DESEncrypt(key: [UInt8](key[0..<8]), message: tmp, iv: y)
        Log.debug("y\(i): \(binToHexRep(y))" )
    }
    
    Log.debug("y: \(binToHexRep(y))" )
    Log.debug("bkey: \(binToHexRep([UInt8](key[8..<16])))" )
    Log.debug("akey: \(binToHexRep([UInt8](key[0..<8])))" )
    let iv : [UInt8] = [0,0,0,0,0,0,0,0]
    let b = DESDecrypt(key: [UInt8](key[8..<16]), message: y, iv: iv, options:UInt32(kCCOptionECBMode))
    Log.debug( "b: \(binToHexRep(b))" )
    let a = DESEncrypt(key: [UInt8](key[0..<8]), message: b, iv: iv, options:UInt32(kCCOptionECBMode))
    Log.debug( "a: \(binToHexRep(a))" )
    
    return a
}
    
public func asn1Length(data : [UInt8]) throws -> (UInt64, Int)  {
    if data[0] <= 0x7F {
        return (UInt64(binToHex(data[0])), 1)
    }
    if data[0] == 0x81 {
        return (UInt64(binToHex(data[1])), 2)
    }
    if data[0] == 0x82 {
        return (binToHex([UInt8](data[1..<3])), 3)
    }
    
    throw TagError.CannotDecodeASN1Length
    
}

/// Take an hexa value and return the value encoded in the asn.1 format.
///
/// >>> binToHexRep(toAsn1Length(34))
/// '22'
/// >>> binToHexRep(toAsn1Length(170))
/// '81aa'
/// >>> binToHexRep(toAsn1Length(43707))
/// '82aabb'
///
/// @param data: The value to encode in asn.1
/// @type data: An integer (hexa)
/// @return: The asn.1 encoded value
/// @rtype: A binary string
/// @raise asn1Exception: If the parameter is too big, must be >= 0 and <= FFFF
public func toAsn1Length(data : UInt64) throws -> [UInt8] {
    if data <= 0x7F {
        return hexToBin(data)
    }
    if data >= 0x80 && data <= 0xFF {
        return [0x81] + hexRepToBin( String(format:"%02x",data))
    }
    if data >= 0x0100 && data <= 0xFFFF { //binToHex("\x01\x00") and data <= binToHex("\xFF\xFF") {
        return [0x82] + hexRepToBin( String(format:"%04x",data))
    }
    
    throw TagError.InvalidASN1Value
}
        
