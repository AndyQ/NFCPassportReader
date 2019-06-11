//
//  PassportReader.swift
//  NFCTest
//
//  Created by Andy Qua on 11/06/2019.
//  Copyright © 2019 Andy Qua. All rights reserved.
//

import UIKit
import CoreNFC

class PassportReader {
    var tagReader : TagReader?
    var bacHandler : BACHandler?
    
    var passportMRZ : String?
    var passportImage : UIImage?
    
    var sendUpdateMessage : ((_ msg : String)->())?

    init() {
        // Here for testng with cached data files
    }
    
    init( passportTag: NFCISO7816Tag ) {
        self.tagReader = TagReader(tag:passportTag)
    }

    func readPassport( mrzKey : String, completed: @escaping (Error?)->() ) {
        self.handleBAC( mrzKey: mrzKey, completed: completed )
    }
    
    func handleBAC( mrzKey: String, completed: @escaping (Error?)->() ) {
        guard let tagReader = self.tagReader else {
            completed(TagError.noConnectedTag)
            return
        }
        
        self.bacHandler = BACHandler( tagReader: tagReader )
        bacHandler?.performBACAndGetSessionKeys( mrzKey: mrzKey ) { success, error in
            self.bacHandler = nil
            // At this point, BAC Has been done and the TagReader has been set up with the SecureMessaging
            // session keys
            self.readPassport() { error in
                completed( error )
            }
        }
    }
    
    func readPassport( completed : @escaping (Error?)->() ) {
        readDG1( completed: completed )
    }
    
    func readDG1( completed : @escaping (Error?)->() ) {
        guard let tagReader = self.tagReader else { completed(TagError.noConnectedTag ); return }
        
        sendUpdateMessage?( "Reading passport data....." )

        do {
            try tagReader.readDataGroup(dataGroup:.DG1) { [unowned self] (response, error) in
                if let response = response {
                    self.passportMRZ = String( data:Data(response), encoding:.utf8)!
                    
                    self.readDG2(completed: completed )
                } else {
                    completed( error )
                }
            }
        } catch {
            completed( error )
        }
    }
    
    func readDG2( completed : @escaping (Error?)->() )  {
        guard let tagReader = self.tagReader else { completed(TagError.noConnectedTag ); return }
        
        sendUpdateMessage?( "Reading passport image....." )
        
        do {
            try tagReader.readDataGroup(dataGroup:.DG2) { [unowned self] (response, error) in
                if let response = response {
                    let startSeqJPEG : [UInt8] = [0xff,0xd8,0xff,0xe0,0x00,0x10,0x4a,0x46,0x49,0x46]
                    let startSeqJP2 : [UInt8] = [0x00,0x00,0x00,0x0c,0x6a,0x50,0x20,0x20,0x0d,0x0a]
                    var startSeq : [UInt8] = []
                    
                    // TODO: This REALY NEEDS to be moved out into a specific DG parser
                    // This is just to get it working for the moment
                    for i in 73 ..< 150 {
                        var match = false
                        if response[i] == startSeqJPEG[0] {
                            match = true
                            startSeq = startSeqJPEG
                        } else if response[i] == startSeqJP2[0] {
                            match = true
                            startSeq = startSeqJP2
                        }
                        
                        if match && i < response.count - startSeq.count {
                            // see if we match
                            
                            var ok = true
                            for j in 0..<startSeq.count {
                                if response[i+j] != startSeq [j] {
                                    ok = false
                                    break
                                }
                            }
                            if ok {
                                let imageBytes = [UInt8](response[i...])
                                let iData = Data(imageBytes)
                                
                                let file = FileManager.documentDir.appendingPathComponent("lastImage.jp2")
                                try! iData.write(to: file )
                                let jpg = UIImage(data: iData)
                                
                                self.passportImage = jpg
                                log.debug( "DONE" )
                                break
                            }
                        }
                    }
                } else if let err = error {
                    log.debug( "error - \(err.localizedDescription)" )
                }
                completed( error )
            }
        } catch {
            completed(error)
        }
    }
}
