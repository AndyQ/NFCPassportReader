//
//  PassportReader.swift
//  NFCTest
//
//  Created by Andy Qua on 11/06/2019.
//  Copyright © 2019 Andy Qua. All rights reserved.
//

import Foundation

#if !os(macOS)
import UIKit
import CoreNFC

@available(iOS 13, *)
public class PassportReader : NSObject {
    private var passport : NFCPassportModel = NFCPassportModel()
    private var readerSession: NFCTagReaderSession?
    private var elementReadAttempts = 0
    private var currentlyReadingDataGroup : DataGroupId?
    
    private var dataGroupsToRead : [DataGroupId] = []
    private var readAllDatagroups = false
    private var skipSecureElements = true

    private var tagReader : TagReader?
    private var bacHandler : BACHandler?
    private var caHandler : ChipAuthenticationHandler?
    private var mrzKey : String = ""
    private var dataAmountToReadOverride : Int? = nil
    
    private var scanCompletedHandler: ((NFCPassportModel?, NFCPassportReaderError?)->())!
    private var nfcViewDisplayMessageHandler: ((NFCViewDisplayMessage) -> String?)?
    private var masterListURL : URL?
    private var shouldNotReportNextReaderSessionInvalidationErrorUserCanceled : Bool = false

    public init( logLevel: LogLevel = .info, masterListURL: URL? = nil ) {
        super.init()
        
        Log.logLevel = logLevel
        self.masterListURL = masterListURL
    }
    
    public func setMasterListURL( _ masterListURL : URL ) {
        self.masterListURL = masterListURL
    }
    
    // This function allows you to override the amount of data the TagReader tries to read from the NFC
    // chip. NOTE - this really shouldn't be used for production but is useful for testing as different
    // passports support different data amounts.
    // It appears that the most reliable is 0xA0 (160 chars) but some will support arbitary reads (0xFF or 256)
    public func overrideNFCDataAmountToRead( amount: Int ) {
        dataAmountToReadOverride = amount
    }
    
    // By default, Passive Authentication uses the new RFS5652 method to verify the SOD, but can be switched to use
    // the previous OpenSSL CMS verification if necessary
    public var passiveAuthenticationUsesOpenSSL : Bool = false
    
    public func readPassport( mrzKey : String, tags: [DataGroupId] = [], skipSecureElements :Bool = true, customDisplayMessage: ((NFCViewDisplayMessage) -> String?)? = nil, completed: @escaping (NFCPassportModel?, NFCPassportReaderError?)->()) {
        self.passport = NFCPassportModel()
        self.mrzKey = mrzKey
        self.dataGroupsToRead.removeAll()
        self.dataGroupsToRead.append( contentsOf:tags)
        self.scanCompletedHandler = completed
        self.nfcViewDisplayMessageHandler = customDisplayMessage
        self.skipSecureElements = skipSecureElements
        
        // If no tags specified, read all
        if self.dataGroupsToRead.count == 0 {
            // Start off with .COM, will always read (and .SOD but we'll add that after), and then add the others from the COM
            self.dataGroupsToRead.append(contentsOf:[.COM, .SOD] )
            self.readAllDatagroups = true
        } else {
            // We are reading specific datagroups
            self.readAllDatagroups = false
        }
        
        guard NFCNDEFReaderSession.readingAvailable else {
            scanCompletedHandler( nil, NFCPassportReaderError.NFCNotSupported)
            return
        }
        
        if NFCTagReaderSession.readingAvailable {
            readerSession = NFCTagReaderSession(pollingOption: [.iso14443], delegate: self, queue: nil)

            self.updateReaderSessionMessage( alertMessage: NFCViewDisplayMessage.requestPresentPassport )
            readerSession?.begin()
        }
    }
}

@available(iOS 13, *)
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
        Log.debug( "tagReaderSession:didInvalidateWithError - \(error.localizedDescription)" )
        self.readerSession = nil

        if let readerError = error as? NFCReaderError, readerError.code == NFCReaderError.readerSessionInvalidationErrorUserCanceled
            && self.shouldNotReportNextReaderSessionInvalidationErrorUserCanceled {
            
            self.shouldNotReportNextReaderSessionInvalidationErrorUserCanceled = false
        } else {
            var userError = NFCPassportReaderError.UnexpectedError
            if let readerError = error as? NFCReaderError {
                Log.error( "tagReaderSession:didInvalidateWithError - Got NFCReaderError - \(readerError.localizedDescription)" )
                switch (readerError.code) {
                case NFCReaderError.readerSessionInvalidationErrorUserCanceled:
                    Log.error( "     - User cancelled session" )
                    userError = NFCPassportReaderError.UserCanceled
                default:
                    Log.error( "     - some other error - \(readerError.localizedDescription)" )
                    userError = NFCPassportReaderError.UnexpectedError
                }
            } else {
                Log.error( "tagReaderSession:didInvalidateWithError - Received error - \(error.localizedDescription)" )
            }
            self.scanCompletedHandler(nil, userError)
        }
    }
    
    public func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        Log.debug( "tagReaderSession:didDetect - \(tags[0])" )
        if tags.count > 1 {
            Log.debug( "tagReaderSession:more than 1 tag detected! - \(tags)" )

            let errorMessage = NFCViewDisplayMessage.error(.MoreThanOneTagFound)
            self.invalidateSession(errorMessage: errorMessage, error: NFCPassportReaderError.MoreThanOneTagFound)
            return
        }

        let tag = tags.first!
        var passportTag: NFCISO7816Tag
        switch tags.first! {
        case let .iso7816(tag):
            passportTag = tag
        default:
            Log.debug( "tagReaderSession:invalid tag detected!!!" )

            let errorMessage = NFCViewDisplayMessage.error(NFCPassportReaderError.TagNotValid)
            self.invalidateSession(errorMessage:errorMessage, error: NFCPassportReaderError.TagNotValid)
            return
        }
        
        
        // Connect to tag
        Log.debug( "tagReaderSession:connecting to tag - \(tag)" )
        session.connect(to: tag) { [unowned self] (error: Error?) in
            if error != nil {
                Log.debug( "tagReaderSession:failed to connect to tag - \(error?.localizedDescription ?? "Unknown error")" )
                let errorMessage = NFCViewDisplayMessage.error(NFCPassportReaderError.ConnectionError)
                self.invalidateSession(errorMessage: errorMessage, error: NFCPassportReaderError.ConnectionError)
                return
            }
            
            Log.debug( "tagReaderSession:connected to tag - starting authentication" )
            self.updateReaderSessionMessage( alertMessage: NFCViewDisplayMessage.authenticatingWithPassport(0) )

            self.tagReader = TagReader(tag:passportTag)
            
            if let newAmount = self.dataAmountToReadOverride {
                self.tagReader?.overrideDataAmountToRead(newAmount: newAmount)
            }
            
            self.tagReader!.progress = { [unowned self] (progress) in
                if let dgId = self.currentlyReadingDataGroup {
                    self.updateReaderSessionMessage( alertMessage: NFCViewDisplayMessage.readingDataGroupProgress(dgId, progress) )
                } else {
                    self.updateReaderSessionMessage( alertMessage: NFCViewDisplayMessage.authenticatingWithPassport(progress) )
                }
            }

            DispatchQueue.global().async {
                self.startReading( )
            }
        }
    }
    
    func updateReaderSessionMessage(alertMessage: NFCViewDisplayMessage ) {
        self.readerSession?.alertMessage = self.nfcViewDisplayMessageHandler?(alertMessage) ?? alertMessage.description
    }
}

@available(iOS 13, *)
extension PassportReader {
    
    func startReading() {
        elementReadAttempts = 0
        self.currentlyReadingDataGroup = nil
        // Set Chip authentication to be unsuccessful - either we haven't done it yet or we have done it but it failed for some reason
        passport.chipAuthenticationSuccessful = false
        self.handleBAC(completed: { [weak self] error in
            if error == nil {
                Log.info( "BAC Successful" )
                // At this point, BAC Has been done and the TagReader has been set up with the SecureMessaging
                // session keys
                self?.readNextDataGroup( ) { [weak self] error in
                    if self?.dataGroupsToRead.count != 0 {
                        // OK we've got more datagroups to go - we've probably failed security verification
                        // So lets re-establish BAC and try again
                        DispatchQueue.global().async {
                            self?.startReading()
                        }
                    } else {
                        if let error = error {
                            self?.invalidateSession(errorMessage:NFCViewDisplayMessage.error(error), error: error)
                        } else {
                            self?.updateReaderSessionMessage(alertMessage: NFCViewDisplayMessage.successfulRead)
                            
                            // Before we finish, check if we should do active authentication
                            self?.doActiveAuthenticationIfNeccessary() { [weak self] in
                                // We succesfully read the passport, now we're about to invalidate the session. Before
                                // doing so, we want to be sure that the 'user cancelled' error that we're causing by
                                // calling 'invalidate' will not be reported back to the user
                                self?.shouldNotReportNextReaderSessionInvalidationErrorUserCanceled = true
                                self?.readerSession?.invalidate()
                                
                                // If we have a masterlist url set then use that and verify the passport now
                                self?.passport.verifyPassport(masterListURL: self?.masterListURL, useCMSVerification: self?.passiveAuthenticationUsesOpenSSL ?? false)
                                self?.scanCompletedHandler( self?.passport, nil )
                            }
                        }
                    }
                }
            } else if let error = error {
                Log.info( "BAC Failed" )
                let displayMessage = NFCViewDisplayMessage.error(error)
                self?.invalidateSession(errorMessage: displayMessage, error: error)
            }
        })
    }
    
    func invalidateSession(errorMessage: NFCViewDisplayMessage, error: NFCPassportReaderError) {
        // Mark the next 'invalid session' error as not reportable (we're about to cause it by invalidating the
        // session). The real error is reported back with the call to the completed handler
        self.shouldNotReportNextReaderSessionInvalidationErrorUserCanceled = true
        self.readerSession?.invalidate(errorMessage: self.nfcViewDisplayMessageHandler?(errorMessage) ?? errorMessage.description)
        self.scanCompletedHandler(nil, error)
    }

    func doActiveAuthenticationIfNeccessary( completed: @escaping ()->() ) {
        guard self.passport.activeAuthenticationSupported else {
            completed()
            return
        }
        
        Log.info( "Performing Active Authentication" )

        let challenge = generateRandomUInt8Array(8)
        self.tagReader?.doInternalAuthentication(challenge: challenge, completed: { (response, err) in
            if let response = response {
                self.passport.verifyActiveAuthentication( challenge:challenge, signature:response.data )
            }

            completed()
        })

    }
    
    func handleBAC( completed: @escaping (NFCPassportReaderError?)->()) {
        guard let tagReader = self.tagReader else {
            completed(NFCPassportReaderError.NoConnectedTag)
            return
        }
        
        Log.info( "Starting Basic Access Control (BAC)" )

        self.bacHandler = BACHandler( tagReader: tagReader )
        bacHandler?.performBACAndGetSessionKeys( mrzKey: mrzKey ) { error in
            self.bacHandler = nil
            completed(error)
        }
    }
    
    func readNextDataGroup( completedReadingGroups completed : @escaping (NFCPassportReaderError?)->() ) {
        guard let tagReader = self.tagReader else { completed(NFCPassportReaderError.NoConnectedTag ); return }
        if dataGroupsToRead.count == 0 {
            completed(nil)
            return
        }
        
        let dgId = dataGroupsToRead[0]
        self.currentlyReadingDataGroup = dgId
        Log.info( "Reading tag - \(dgId)" )
        elementReadAttempts += 1
        
        self.updateReaderSessionMessage( alertMessage: NFCViewDisplayMessage.readingDataGroupProgress(dgId, 0) )
        tagReader.readDataGroup(dataGroup:dgId) { [unowned self] (response, err) in
            self.updateReaderSessionMessage( alertMessage: NFCViewDisplayMessage.readingDataGroupProgress(dgId, 100) )
            if let response = response {
                
                var readNextDG = true
                do {
                    let dg = try DataGroupParser().parseDG(data: response)
                    self.passport.addDataGroup( dgId, dataGroup:dg )
                    
                    if let com = dg as? COM {
                        var dgsPresent = com.dataGroupsPresent.map { DataGroupId.getIDFromName(name:$0) }
                        var foundDGs : [DataGroupId] = [.COM]
                        if dgsPresent.contains( .DG14 ) {
                            foundDGs.append( .DG14 )
                            dgsPresent.removeAll { $0 == .DG14 }
                        }
                        foundDGs += [.SOD] + dgsPresent
                        if self.readAllDatagroups == true {
                            self.dataGroupsToRead = foundDGs
                        } else {
                            // We are reading specific datagroups but remove all the ones we've requested to be read that aren't actually available
                            self.dataGroupsToRead = foundDGs.filter { dataGroupsToRead.contains($0) }
                        }
                        
                        // If we are skipping secure elements then remove .DG3 and .DG4
                        if self.skipSecureElements {
                            self.dataGroupsToRead = self.dataGroupsToRead.filter { $0 != .DG3 && $0 != .DG4 }
                        }
                    } else if let dg14 = dg as? DataGroup14 {
                        self.caHandler = ChipAuthenticationHandler(dg14: dg14, tagReader: (self.tagReader)!)
                        
                        if caHandler?.isChipAuthenticationSupported ?? false {
                            
                            // Do Chip authentication and then continue reading datagroups
                            readNextDG = false
                            self.passport.chipAuthenticationSupported = true
                            self.caHandler?.doChipAuthentication() { [unowned self] (success) in
                                self.passport.chipAuthenticationSuccessful = success
                                self.readNextDataGroup(completedReadingGroups: completed)
                            }
                        }
                    }

                } catch let error as NFCPassportReaderError {
                    Log.error( "TagError reading tag - \(error)" )
                } catch let error {
                    Log.error( "Unexpected error reading tag - \(error)" )
                }

                // Remove it and read the next tag
                self.dataGroupsToRead.removeFirst()
                self.elementReadAttempts = 0
                if readNextDG {
                    self.readNextDataGroup(completedReadingGroups: completed)
                }
                
            } else {
                
                // OK we had an error - depending on what happened, we may want to try to re-read this
                // E.g. we failed to read the last Datagroup because its protected and we can't
                let errMsg = err?.value ?? "Unknown  error"
                Log.error( "ERROR - \(errMsg)" )
                if errMsg == "Session invalidated" || errMsg == "Class not supported" || errMsg == "Tag connection lost"  {
                    // Check if we have done Chip Authentication, if so, set it to nil and try to redo BAC
                    if self.caHandler != nil {
                        self.caHandler = nil
                        completed(nil)
                    } else {
                        // Can't go any more!
                        self.dataGroupsToRead.removeAll()
                        completed( err )
                    }
                } else if errMsg == "Security status not satisfied" || errMsg == "File not found" {
                    // Can't read this element as we aren't allowed - remove it and return out so we re-do BAC
                    self.dataGroupsToRead.removeFirst()
                    completed(nil)
                } else if errMsg == "SM data objects incorrect" || errMsg == "Class not supported" {
                    // Can't read this element security objects now invalid - and return out so we re-do BAC
                    completed(nil)
                } else if errMsg.hasPrefix( "Wrong length" ) || errMsg.hasPrefix( "End of file" ) {  // Should now handle errors 0x6C xx, and 0x67 0x00
                    // OK passport can't handle max length so drop it down
                    self.tagReader?.reduceDataReadingAmount()
                    completed(nil)
                } else {
                    // Retry
                    if self.elementReadAttempts > 3 {
                        self.dataGroupsToRead.removeFirst()
                        self.elementReadAttempts = 0
                    }
                    self.readNextDataGroup(completedReadingGroups: completed)
                }
            }
        }
    }
}
#endif
