//
//  TagHandler.swift
//  NFCTest
//
//  Created by Andy Qua on 09/06/2019.
//  Copyright © 2019 Andy Qua. All rights reserved.
//

import Foundation
import CoreNFC
@available(iOS 13, *)
public enum PassportTagError : Error {
    case responseError( UInt8, UInt8 )
}
@available(iOS 13, *)
extension PassportTagError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .responseError:
            return NSLocalizedString("A user-friendly description of the error.", comment: "My error")
        }
    }
}

@available(iOS 13, *)
public enum TagError: Error {
    case ResponseError(String, UInt8, UInt8)
    case InvalidResponse
    case UnexpectedError
    case NFCNotSupported
    case NoConnectedTag
    case D087Malformed
    case InvalidResponseChecksum
    case MissingMandatoryFields
    case CannotDecodeASN1Length
    case InvalidASN1Value
    case UnableToProtectAPDU
    case UnableToUnprotectAPDU
    case UnsupportedDataGroup
    case DataGroupNotRead
    case UnknownTag
    case UnknownImageFormat
    case NotImplemented
    case TagNotValid
    case ConnectionError
    case UserCanceled
    case InvalidMRZKey
    case MoreThanOneTagFound

    var value: String {
        switch self {
        case .ResponseError(let errMsg, _, _): return errMsg
        case .InvalidResponse: return "InvalidResponse"
        case .UnexpectedError: return "UnexpectedError"
        case .NFCNotSupported: return "NFCNotSupported"
        case .NoConnectedTag: return "NoConnectedTag"
        case .D087Malformed: return "D087Malformed"
        case .InvalidResponseChecksum: return "InvalidResponseChecksum"
        case .MissingMandatoryFields: return "MissingMandatoryFields"
        case .CannotDecodeASN1Length: return "CannotDecodeASN1Length"
        case .InvalidASN1Value: return "InvalidASN1Value"
        case .UnableToProtectAPDU: return "UnableToProtectAPDU"
        case .UnableToUnprotectAPDU: return "UnableToUnprotectAPDU"
        case .UnsupportedDataGroup: return "UnsupportedDataGroup"
        case .DataGroupNotRead: return "DataGroupNotRead"
        case .UnknownTag: return "UnknownTag"
        case .UnknownImageFormat: return "UnknownImageFormat"
        case .NotImplemented: return "NotImplemented"
        case .TagNotValid: return "TagNotValid"
        case .ConnectionError: return "ConnectionError"
        case .UserCanceled: return "UserCanceled"
        case .InvalidMRZKey: return "InvalidMRZKey"
        case .MoreThanOneTagFound: return "MoreThanOneTagFound"
        }
    }
}

@available(iOS 13, *)
public enum DataGroupId : Int, CaseIterable {
    case COM = 0x60
    case DG1 = 0x61
    case DG2 = 0x75
    case DG3 = 0x63
    case DG4 = 0x76
    case DG5 = 0x65
    case DG6 = 0x66
    case DG7 = 0x67
    case DG8 = 0x68
    case DG9 = 0x69
    case DG10 = 0x6A
    case DG11 = 0x6B
    case DG12 = 0x6C
    case DG13 = 0x6D
    case DG14 = 0x6E
    case DG15 = 0x6F
    case DG16 = 0x70
    case SOD = 0x77
    case Unknown = 0x00
    
    public func getName() -> String {
        switch( self ) {
        case .COM: return "COM"
        case .DG1: return "DG1"
        case .DG2: return "DG2"
        case .DG3: return "DG3"
        case .DG4: return "DG4"
        case .DG5: return "DG5"
        case .DG6: return "DG6"
        case .DG7: return "DG7"
        case .DG8: return "DG8"
        case .DG9: return "DG9"
        case .DG10: return "DG10"
        case .DG11: return "DG11"
        case .DG12: return "DG12"
        case .DG13: return "DG13"
        case .DG14: return "DG14"
        case .DG15: return "DG15"
        case .DG16: return "DG16"
        case .SOD: return "SOD"
        case .Unknown: return "Unknown"
        }
    }
    
    static public func getIDFromName( name: String ) -> DataGroupId {
        switch( name ) {
        case "COM": return .COM
        case "DG1": return .DG1
        case "DG2": return .DG2
        case "DG3": return .DG3
        case "DG4": return .DG4
        case "DG5": return .DG5
        case "DG6": return .DG6
        case "DG7": return .DG7
        case "DG8": return .DG8
        case "DG9": return .DG9
        case "DG10": return .DG10
        case "DG11": return .DG11
        case "DG12": return .DG12
        case "DG13": return .DG13
        case "DG14": return .DG14
        case "DG15": return .DG15
        case "DG16": return .DG16
        case "SOD": return .SOD
        default: return .Unknown
        }
    }

}

@available(iOS 13, *)
private let DataGroupToFileIdMap : [DataGroupId: [UInt8]] = [
    .COM : [0x01,0x1E],
    .DG1 : [0x01,0x01],
    .DG2 : [0x01,0x02],
    .DG3 : [0x01,0x03],
    .DG4 : [0x01,0x04],
    .DG5 : [0x01,0x05],
    .DG6 : [0x01,0x06],
    .DG7 : [0x01,0x07],
    .DG8 : [0x01,0x08],
    .DG9 : [0x01,0x09],
    .DG10 : [0x01,0x0A],
    .DG11 : [0x01,0x0B],
    .DG12 : [0x01,0x0C],
    .DG13 : [0x01,0x0D],
    .DG14 : [0x01,0x0E],
    .DG15 : [0x01,0x0F],
    .DG16 : [0x01,0x10],
    .SOD : [0x01,0x1D],
]

@available(iOS 13, *)
public struct ResponseAPDU {
    
    public var data : [UInt8]
    public var sw1 : UInt8
    public var sw2 : UInt8

    public init(data: [UInt8], sw1: UInt8, sw2: UInt8) {
        self.data = data
        self.sw1 = sw1
        self.sw2 = sw2
    }
}

@available(iOS 13, *)
public class TagReader {
    var tag : NFCISO7816Tag
    var secureMessaging : SecureMessaging?
    var maxDataLengthToRead : Int = 256

    var progress : ((Int)->())?

    init( tag: NFCISO7816Tag) {
        self.tag = tag
    }
    
    func reduceDataReadingAmount() {
        if maxDataLengthToRead == 256 {
            maxDataLengthToRead = 0xA0
        }
    }



    func readDataGroup( dataGroup: DataGroupId, completed: @escaping ([UInt8]?, TagError?)->() )  {
        guard let tag = DataGroupToFileIdMap[dataGroup] else {
            completed(nil, TagError.UnsupportedDataGroup)
            return
        }
        
        selectFileAndRead(tag: tag, completed:completed )
    }
    
    func getChallenge( completed: @escaping (ResponseAPDU?, TagError?)->() ) {
        let cmd : NFCISO7816APDU = NFCISO7816APDU(instructionClass: 00, instructionCode: 0x84, p1Parameter: 0, p2Parameter: 0, data: Data(), expectedResponseLength: 8)
        
        send( cmd: cmd, completed: completed )
    }
    
    func doInternalAuthentication( challenge: [UInt8], completed: @escaping (ResponseAPDU?, TagError?)->() ) {
        let randNonce = Data(challenge)
        
        let cmd = NFCISO7816APDU(instructionClass: 00, instructionCode: 0x88, p1Parameter: 0, p2Parameter: 0, data: randNonce, expectedResponseLength: 256)

        send( cmd: cmd, completed: completed )
    }

    func doMutualAuthentication( cmdData : Data, completed: @escaping (ResponseAPDU?, TagError?)->() ) {
        let cmd : NFCISO7816APDU = NFCISO7816APDU(instructionClass: 00, instructionCode: 0x82, p1Parameter: 0, p2Parameter: 0, data: cmdData, expectedResponseLength: 40)

        send( cmd: cmd, completed: completed )
    }
    
    
    var header = [UInt8]()
    func selectFileAndRead( tag: [UInt8], completed: @escaping ([UInt8]?, TagError?)->() ) {
        selectFile(tag: tag ) { [unowned self] (resp,err) in
            if let error = err {
                completed( nil, error)
                return
            }
            
            // Read first 4 bytes of header to see how big the data structure is
            let data : [UInt8] = [0x00, 0xB0, 0x00, 0x00, 0x00, 0x00,0x04]
            //print( "--------------------------------------\nSending \(binToHexRep(data))" )
            let cmd = NFCISO7816APDU(data:Data(data))!
            self.send( cmd: cmd ) { [unowned self] (resp,err) in
                guard let response = resp else {
                    completed( nil, err)
                    return
                }
                // Header looks like:  <tag><length of data><nextTag> e.g.60145F01 -
                // the total length is the 2nd value plus the two header 2 bytes
                // We've read 4 bytes so we now need to read the remaining bytes from offset 4
                var leftToRead = 0
                
                let (len, o) = try! asn1Length([UInt8](response.data[1..<4]))
                leftToRead = Int(len)
                let offset = o + 1
                
                //print( "Got \(binToHexRep(response.data)) which is \(leftToRead) bytes with offset \(o)" )
                self.header = [UInt8](response.data[..<offset])//response.data

                
                Log.debug( "Amount of data to read - \(leftToRead)" )
                self.readBinaryData(leftToRead: leftToRead, amountRead: offset, completed: completed)

            }
        }
    }
    
    func selectFile( tag: [UInt8], completed: @escaping (ResponseAPDU?, TagError?)->() ) {
        
        let data : [UInt8] = [0x00, 0xA4, 0x02, 0x0C, 0x02] + tag
        let cmd = NFCISO7816APDU(data:Data(data))!
        
        send( cmd: cmd, completed: completed )
    }
    
    func readBinaryData( leftToRead: Int, amountRead : Int, completed: @escaping ([UInt8]?, TagError?)->() ) {
        var readAmount : Int = maxDataLengthToRead
        if leftToRead < maxDataLengthToRead {
            readAmount = leftToRead
        }
        
        self.progress?( Int(Float(amountRead) / Float(leftToRead+amountRead ) * 100))
        let offset = intToBin(amountRead, pad:4)

        let cmd = NFCISO7816APDU(
            instructionClass: 00,
            instructionCode: 0xB0,
            p1Parameter: offset[0],
            p2Parameter: offset[1],
            data: Data(),
            expectedResponseLength: readAmount
        )

        Log.debug( "Expected response length: \(readAmount)" )
        self.send( cmd: cmd ) { (resp,err) in
            guard let response = resp else {
                completed( nil, err)
                return
            }
            Log.debug( "got resp - \(response)" )
            self.header += response.data
            
            let remaining = leftToRead - response.data.count
        //print( "      read \(response.data.count) bytes" )
            Log.debug( "Amount of data left read - \(remaining)" )
            if remaining > 0 {
                self.readBinaryData(leftToRead: remaining, amountRead: amountRead + response.data.count, completed: completed )
            } else {
                completed( self.header, err )
            }
            
        }
    }

    
    func send( cmd: NFCISO7816APDU, completed: @escaping (ResponseAPDU?, TagError?)->() ) {
        
        var toSend = cmd
        if let sm = secureMessaging {
            do {
                toSend = try sm.protect(apdu:cmd)
            } catch {
                completed( nil, TagError.UnableToProtectAPDU )
            }
            Log.debug("[SM] \(toSend)" )
        }

        tag.sendCommand(apdu: toSend) { [unowned self] (data, sw1, sw2, error) in
            if let error = error {
                Log.error( "Error reading tag - \(error.localizedDescription)" )
                completed( nil, TagError.ResponseError( error.localizedDescription, sw1, sw2 ) )
            } else {
                var rep = ResponseAPDU(data: [UInt8](data), sw1: sw1, sw2: sw2)
                
                if let sm = self.secureMessaging {
                    do {
                        rep = try sm.unprotect(rapdu:rep)
//                        Log.debug(String(format:"[SM] \(rep.data), sw1:0x%02x sw2:0x%02x", rep.sw1, rep.sw2) )
                    } catch {
                        completed( nil, TagError.UnableToUnprotectAPDU )
                        return
                    }
                }
                
                if rep.sw1 == 0x90 && rep.sw2 == 0x00 {
                    completed( rep, nil )
                } else {
                    Log.error( "Error reading tag: sw1 - 0x\(binToHexRep(sw1)), sw2 - 0x\(binToHexRep(sw2))" )
                    let tagError: TagError
                    if (rep.sw1 == 0x63 && rep.sw2 == 0x00) {
                        tagError = TagError.InvalidMRZKey
                    } else {
                        let errorMsg = self.decodeError(sw1: rep.sw1, sw2: rep.sw2)
                        Log.error( "reason: \(errorMsg)" )
                        tagError = TagError.ResponseError( errorMsg, sw1, sw2 )
                    }
                    completed( nil, tagError)
                }
            }
        }
    }
    
    private func decodeError( sw1: UInt8, sw2:UInt8 ) -> String {

        let errors : [UInt8 : [UInt8:String]] = [
            0x62: [0x00:"No information given",
                   0x81:"Part of returned data may be corrupted",
                   0x82:"End of file/record reached before reading Le bytes",
                   0x83:"Selected file invalidated",
                   0x84:"FCI not formatted according to ISO7816-4 section 5.1.5"],
            
            0x63: [0x81:"File filled up by the last write",
                   0x82:"Card Key not supported",
                   0x83:"Reader Key not supported",
                   0x84:"Plain transmission not supported",
                   0x85:"Secured Transmission not supported",
                   0x86:"Volatile memory not available",
                   0x87:"Non Volatile memory not available",
                   0x88:"Key number not valid",
                   0x89:"Key length is not correct",
                   0xC:"Counter provided by X (valued from 0 to 15) (exact meaning depending on the command)"],
            0x65: [0x00:"No information given",
                   0x81:"Memory failure"],
            0x67: [0x00:"Wrong length"],
            0x68: [0x00:"No information given",
                   0x81:"Logical channel not supported",
                   0x82:"Secure messaging not supported"],
            0x69: [0x00:"No information given",
                   0x81:"Command incompatible with file structure",
                   0x82:"Security status not satisfied",
                   0x83:"Authentication method blocked",
                   0x84:"Referenced data invalidated",
                   0x85:"Conditions of use not satisfied",
                   0x86:"Command not allowed (no current EF)",
                   0x87:"Expected SM data objects missing",
                   0x88:"SM data objects incorrect"],
            0x6A: [0x00:"No information given",
                   0x80:"Incorrect parameters in the data field",
                   0x81:"Function not supported",
                   0x82:"File not found",
                   0x83:"Record not found",
                   0x84:"Not enough memory space in the file",
                   0x85:"Lc inconsistent with TLV structure",
                   0x86:"Incorrect parameters P1-P2",
                   0x87:"Lc inconsistent with P1-P2",
                   0x88:"Referenced data not found"],
            0x6B: [0x00:"Wrong parameter(s) P1-P2]"],
            0x6D: [0x00:"Instruction code not supported or invalid"],
            0x6E: [0x00:"Class not supported"],
            0x6F: [0x00:"No precise diagnosis"],
            0x90: [0x00:"Success"] //No further qualification
        ]
        
        // Special cases - where sw2 isn't an error but contains a value
        if sw1 == 0x61 {
            return "SW2 indicates the number of response bytes still available - (\(sw2) bytes still available)"
        } else if sw1 == 0x64 {
            return "State of non-volatile memory unchanged (SW2=00, other values are RFU)"
        } else if sw1 == 0x6C {
            return "Wrong length Le: SW2 indicates the exact length - (exact length :\(sw2))"
        }

        if let dict = errors[sw1], let errorMsg = dict[sw2] {
            return errorMsg
        }
        
        return "Unknown error - sw1: 0x\(binToHexRep(sw1)), sw2 - 0x\(binToHexRep(sw2)) "
    }
}

