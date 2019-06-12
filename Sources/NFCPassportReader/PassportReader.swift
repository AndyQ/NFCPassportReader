//
//  PassportReader.swift
//  NFCTest
//
//  Created by Andy Qua on 11/06/2019.
//  Copyright © 2019 Andy Qua. All rights reserved.
//

import UIKit
import CoreNFC

public class PassportReader : NSObject {
    public var passportMRZ : String?
    public var passportImage : UIImage?

    private var readerSession: NFCTagReaderSession?

    private var tagReader : TagReader?
    private var bacHandler : BACHandler?
    private var mrzKey : String = ""
    
    private var scanCompletedHandler: ((TagError?)->())!

    public init( logLevel: LogLevel = .warning ) {
        super.init()
        
        Log.logLevel = logLevel
    }
    
    public func readPassport( mrzKey : String, completed: @escaping (TagError?)->() ) {
        self.mrzKey = mrzKey
        self.scanCompletedHandler = completed
        
        guard NFCNDEFReaderSession.readingAvailable else {
            scanCompletedHandler( TagError.NFCNotSupported)
            return
        }
        
        if NFCTagReaderSession.readingAvailable {
            readerSession = NFCTagReaderSession(pollingOption: [.iso14443], delegate: self, queue: nil)
            readerSession?.alertMessage = "Hold your iPhone near an NFC enabled passport."
            readerSession?.begin()
        }
    }
    
}


extension PassportReader : NFCTagReaderSessionDelegate {
    // MARK: - NFCTagReaderSessionDelegate
    public func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {
        // If necessary, you may perform additional operations on session start.
        // At this point RF polling is enabled.
        Log.debug( "tagReaderSessionDidBecomeActive" )
    }
    
    public func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        // If necessary, you may handle the error. Note session is no longer valid.
        // You must create a new session to restart RF polling.
        Log.debug( "tagReaderSession:didInvalidateWithError - \(error)" )
        self.readerSession = nil
        
    }
    
    public func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        Log.debug( "tagReaderSession:didDetect - \(tags[0])" )
        if tags.count > 1 {
            session.alertMessage = "More than 1 tags was found. Please present only 1 tag."
            return
        }
        
        let tag = tags.first!
        var passportTag: NFCISO7816Tag
        switch tags.first! {
        case let .iso7816(tag):
            passportTag = tag
        default:
            session.invalidate(errorMessage: "Tag not valid.")
            return
        }
        
        // Connect to tag
        session.connect(to: tag) { [unowned self] (error: Error?) in
            if error != nil {
                session.invalidate(errorMessage: "Connection error. Please try again.")
                return
            }
            
            self.readerSession?.alertMessage = "Authenticating with passport....."

            self.tagReader = TagReader(tag:passportTag)

            self.startReading( )

        }
    }
}


extension PassportReader {
    func startReading() {
        self.handleBAC(completed: { [weak self] error in
            if error == nil {
                // At this point, BAC Has been done and the TagReader has been set up with the SecureMessaging
                // session keys
                self?.readPassport() { [weak self] error in
                    if error != nil {
                        self?.readerSession?.invalidate(errorMessage: "Sorry, there was a problem reading the passport. Please try again" )
                    } else {
                        self?.readerSession?.invalidate()
                    }
                    self?.scanCompletedHandler( error )
                }
            } else {
                self?.readerSession?.invalidate(errorMessage: "Sorry, there was a problem reading the passport. Please try again" )
                self?.scanCompletedHandler(error)
            }
        })
    }
    
    func handleBAC( completed: @escaping (TagError?)->()) {
        guard let tagReader = self.tagReader else {
            completed(TagError.noConnectedTag)
            return
        }
        
        self.bacHandler = BACHandler( tagReader: tagReader )
        bacHandler?.performBACAndGetSessionKeys( mrzKey: mrzKey ) { error in
            self.bacHandler = nil
            completed(error)
        }
    }
    
    func readPassport( completed : @escaping (TagError?)->() ) {
        readDG1( completed: completed )
    }
    
    func readDG1( completed : @escaping (TagError?)->() ) {
        guard let tagReader = self.tagReader else { completed(TagError.noConnectedTag ); return }
        
        self.readerSession?.alertMessage = "Reading passport data....."
        
        tagReader.readDataGroup(dataGroup:.DG1) { [unowned self] (response, error) in
            if let response = response {
                // Skip First 4 bytes for the moment (this will get properly parsed out soon)
                // The first 4 bytes are the 5F1F tag which signifies the start of the MRZ data
                self.passportMRZ = String( data:Data(response[4...]), encoding:.utf8)!
                
                self.readDG2(completed: completed )
            } else {
                completed( error )
            }
        }
    }
    
    func readDG2( completed : @escaping (TagError?)->() )  {
        guard let tagReader = self.tagReader else { completed(TagError.noConnectedTag ); return }
        
        self.readerSession?.alertMessage = "Reading passport image....."
        
        tagReader.readDataGroup(dataGroup:.DG2) { [unowned self] (response, error) in
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
                            
//                            let file = FileManager.documentDir.appendingPathComponent("lastImage.jp2")
//                            try! iData.write(to: file )
                            let jpg = UIImage(data: iData)
                            
                            self.passportImage = jpg
                            Log.debug( "DONE" )
                            break
                        }
                    }
                }
            } else if let err = error {
                Log.debug( "error - \(err.localizedDescription)" )
            }
            completed( error )
        }
    }
}
