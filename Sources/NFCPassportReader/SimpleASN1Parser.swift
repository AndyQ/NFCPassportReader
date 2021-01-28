//
//  SimpleASN1Parser.swift
//  NFCPassportReader
//
//  Created by Andy Qua on 25/01/2021.
//

import Foundation
import OpenSSL

@available(iOS 13, *)
class ASN1Item : CustomDebugStringConvertible {
    var pos : Int = -1
    var depth : Int = -1
    var headerLen : Int = -1
    var length : Int = -1
    var itemType : String = "" // Primative or Constructed (prim or cons)
    var type : String = "" // Actual type of the value ( object, set, etc)
    var value : String = ""
    var line : String = ""
    var parent : ASN1Item? = nil
    
    private var children = [ASN1Item] ()
    
    init( line : String, parent : ASN1Item? = nil ) {
        self.parent = parent
        self.line = line
        
        let scanner = Scanner(string: line)
        
        let space = CharacterSet(charactersIn: " =:")
        let equals = CharacterSet(charactersIn: "= ")
        let colon = CharacterSet(charactersIn: ":")
        let end = CharacterSet(charactersIn: "\n")
        
        scanner.charactersToBeSkipped = space
        self.pos = scanner.scanInt() ?? -1
        _ = scanner.scanUpToCharacters(from: equals)
        self.depth = scanner.scanInt() ?? -1
        _ = scanner.scanUpToCharacters(from: equals)
        self.headerLen = scanner.scanInt() ?? -1
        _ = scanner.scanUpToCharacters(from: equals)
        self.length = scanner.scanInt() ?? -1
        self.itemType = scanner.scanUpToCharacters(from: colon) ?? ""
        let rest = scanner.scanUpToCharacters(from: end)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        
        if itemType == "cons" {
            type = rest
            print( "Extracted [\(itemType)]: [\(type)]" )
        } else {
            let items = rest.components(separatedBy: ":" ).filter{ !$0.isEmpty }
            self.type = items[0].trimmingCharacters(in: .whitespacesAndNewlines)
            if ( items.count > 1 ) {
                self.value = items[1].trimmingCharacters(in: .whitespacesAndNewlines)
            }
            print( "Extracted [\(itemType)]: [\(type)] - [\(value)]" )
        }
    }
    
    func addChild( _ child : ASN1Item ) {
        self.children.append( child )
    }
    
    func getChild( _ child : Int ) -> ASN1Item? {
        if ( child < children.count ) {
            return children[child]
        } else {
            return nil
        }
    }
    
    var debugDescription: String {
        var ret = "pos:\(pos), d=\(depth), hl=\(headerLen), l=\(length): \(itemType): \(type) \(value)\n"
        children.forEach { ret += $0.debugDescription }
        return ret
    }
}

/// Very very basic ASN1 parser class - uses OpenSSL to dump an ASN1 structure to a string, and then parses that out into
/// a tree based hieracy of ASN1Item structures - depth based
@available(iOS 13, *)
class SimpleASN1Parser {
    
    func parse( data: Data ) throws -> ASN1Item {
        var parsed : String = ""
        
        var topItem : ASN1Item?

        let _ = try data.withUnsafeBytes { (ptr) in
            guard let out = BIO_new(BIO_s_mem()) else { throw OpenSSLError.UnableToParseASN1("Unable to allocate output buffer") }
            defer { BIO_free(out) }
        
            let rc = ASN1_parse_dump(out, ptr.baseAddress?.assumingMemoryBound(to: UInt8.self), data.count, 0, 0)
            if rc == 0 {
                throw OpenSSLError.UnableToParseASN1("Failed to parse ASN1 Data")
            }
            
            parsed = OpenSSLUtils.bioToString(bio: out)
        }
        
        let lines = parsed.components(separatedBy: "\n")
        var currentParent : ASN1Item?
        for line in lines {
            if line.trimmingCharacters(in: .whitespacesAndNewlines) == "" {
                continue
            }
            let item = ASN1Item(line: line, parent: currentParent)
            if item.depth == 0 {
                topItem = item
            } else if item.depth == currentParent!.depth {
                currentParent!.parent!.addChild( item )
            } else if item.depth > currentParent!.depth {
                currentParent!.addChild( item )
            } else {
                repeat {
                    currentParent = currentParent!.parent
                } while currentParent!.depth > item.depth-1 && currentParent!.depth != 0
                if currentParent!.depth == item.depth-1 {
                    currentParent!.addChild( item )
                }
            }
            currentParent = item
        }
        
        guard let ret = topItem else {
            throw OpenSSLError.UnableToParseASN1("Failed to format ASN1 Data")
        }
        
        return ret
    }
}
