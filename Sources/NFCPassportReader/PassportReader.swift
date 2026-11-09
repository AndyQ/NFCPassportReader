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

@available(iOS 15, *)
public protocol PassportReaderTrackingDelegate: AnyObject {
    func nfcTagDetected()
    func readCardAccess(cardAccess: CardAccess)
    func paceStarted()
    func paceSucceeded()
    func paceFailed()
    func bacStarted()
    func bacSucceeded()
    func bacFailed()
}

@available(iOS 15, *)
extension PassportReaderTrackingDelegate {
    func nfcTagDetected() { /* default implementation */ }
    func readCardAccess(cardAccess: CardAccess) { /* default implementation */ }
    func paceStarted() { /* default implementation */ }
    func paceSucceeded() { /* default implementation */ }
    func paceFailed() { /* default implementation */ }
    func bacStarted() { /* default implementation */ }
    func bacSucceeded() { /* default implementation */ }
    func bacFailed() { /* default implementation */ }
}

@available(iOS 15, *)
public class PassportReader : NSObject {
    private typealias NFCCheckedContinuation = CheckedContinuation<NFCPassportModel, Error>
    private var nfcContinuation: NFCCheckedContinuation?

    public weak var trackingDelegate: PassportReaderTrackingDelegate?

    /// Receives all library log and protocol trace events for this reader. This is the library's only log
    /// output; nothing is logged when it is `nil`. Use `PassportLogHandlers.osLog()` for Console output.
    ///
    /// Called synchronously inside the APDU loop on the reader's thread — hand events off quickly and
    /// hop to the main queue before updating UI.
    public var logHandler: PassportLogHandler? {
        get { logger.handler }
        set { logger.handler = newValue }
    }

    /// Controls level, component, and sensitive-detail filtering for this reader.
    public var logConfiguration: PassportLogConfiguration {
        get { logger.configuration }
        set { logger.configuration = newValue }
    }

    /// Receives events logged outside a read, e.g. from `NFCPassportModel(from:)` or a direct
    /// `NFCPassportModel.verifyPassport` call.
    public static var defaultLogHandler: PassportLogHandler? {
        get { PassportLogger.shared.handler }
        set { PassportLogger.shared.handler = newValue }
    }

    /// Filtering applied to `defaultLogHandler`.
    public static var defaultLogConfiguration: PassportLogConfiguration {
        get { PassportLogger.shared.configuration }
        set { PassportLogger.shared.configuration = newValue }
    }

    private let logger = PassportLogger()
    private lazy var tracer = ReaderTracer(logger: logger)
    private var passport : NFCPassportModel = NFCPassportModel()
    
    private var readerSession: NFCTagReaderSession?
    private var currentlyReadingDataGroup : DataGroupId?
    
    private var dataGroupsToRead : [DataGroupId] = []
    private var readAllDatagroups = false
    private var skipSecureElements = true
    private var skipCA = false
    private var skipPACE = false
    
    // Extended mode is used for reading eMRTD's that support extended length APDUs
    private var useExtendedMode = false

    private var bacHandler : BACHandler?
    private var caHandler : ChipAuthenticationHandler?
    private var paceHandler : PACEHandler?
    private var mrzKey : String = ""
    private var aaChallenge: [UInt8]?
    private var dataAmountToReadOverride : Int? = nil
    
    private var scanCompletedHandler: ((NFCPassportModel?, NFCPassportReaderError?)->())!
    private var nfcViewDisplayMessageHandler: ((NFCViewDisplayMessage) -> String?)?
    private var masterListURL : URL?
    private var shouldNotReportNextReaderSessionInvalidationErrorUserCanceled : Bool = false

    // By default, Passive Authentication uses the new RFS5652 method to verify the SOD, but can be switched to use
    // the previous OpenSSL CMS verification if necessary
    public var passiveAuthenticationUsesOpenSSL : Bool = false

    public init( masterListURL: URL? = nil ) {
        super.init()
        
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
    
    /// - Parameter customDisplayMessage: Return a replacement message, or `nil` to use the default description.
    public func readPassport( mrzKey : String, tags : [DataGroupId] = [], aaChallenge: [UInt8]? = nil, skipSecureElements : Bool = true, skipCA : Bool = false, skipPACE : Bool = false, useExtendedMode : Bool = false, customDisplayMessage : ((NFCViewDisplayMessage) -> String?)? = nil) async throws -> NFCPassportModel {
        prepareRead(mrzKey: mrzKey, tags: tags, aaChallenge: aaChallenge, skipSecureElements: skipSecureElements, skipCA: skipCA, skipPACE: skipPACE, useExtendedMode: useExtendedMode, customDisplayMessage: customDisplayMessage)

        guard NFCNDEFReaderSession.readingAvailable else {
            throw NFCPassportReaderError.NFCNotSupported
        }
        
        if NFCTagReaderSession.readingAvailable {
            readerSession = NFCTagReaderSession(pollingOption: [.iso14443], delegate: self, queue: nil)
            
            self.updateReaderSessionMessage( alertMessage: NFCViewDisplayMessage.requestPresentPassport )
            readerSession?.begin()
        }
        
        return try await withCheckedThrowingContinuation({ (continuation: NFCCheckedContinuation) in
            self.nfcContinuation = continuation
        })
    }

    /// Reads a passport from an already connected ISO 7816 tag, without starting an NFC reader session.
    /// Intended for testing against chip simulators (for example PassportSim's apduServer reached through a
    /// socket-backed NFCISO7816Tag); real passports are read with readPassport(mrzKey:...).
    public func readPassport( tag : NFCISO7816Tag, mrzKey : String, tags : [DataGroupId] = [], aaChallenge: [UInt8]? = nil, skipSecureElements : Bool = true, skipCA : Bool = false, skipPACE : Bool = false, useExtendedMode : Bool = false) async throws -> NFCPassportModel {
        prepareRead(mrzKey: mrzKey, tags: tags, aaChallenge: aaChallenge, skipSecureElements: skipSecureElements, skipCA: skipCA, skipPACE: skipPACE, useExtendedMode: useExtendedMode, customDisplayMessage: nil)
        let tagReader = TagReader(tag: tag)
        tagReader.tracer = tracer
        if let newAmount = dataAmountToReadOverride {
            tagReader.overrideDataAmountToRead(newAmount: newAmount)
        }
        tracer.emit(.info, "Tag connected (no NFC session)", detail: "Initially selected AID \(tag.initialSelectedAID)")
        do {
            return try await PassportLogger.withCurrent(logger) {
                try await startReading(tagReader: tagReader)
            }
        } catch let error as NFCPassportReaderError {
            tracer.emit(.error, "Read failed: \(error.value)")
            throw error
        }
    }

    private func prepareRead( mrzKey : String, tags : [DataGroupId], aaChallenge: [UInt8]?, skipSecureElements : Bool, skipCA : Bool, skipPACE : Bool, useExtendedMode : Bool, customDisplayMessage : ((NFCViewDisplayMessage) -> String?)?) {
        
        self.passport = NFCPassportModel()
        self.mrzKey = mrzKey
        self.aaChallenge = aaChallenge
        self.skipCA = skipCA
        self.skipPACE = skipPACE
        self.useExtendedMode = useExtendedMode
        
        self.dataGroupsToRead.removeAll()
        self.dataGroupsToRead.append( contentsOf:tags)
        self.nfcViewDisplayMessageHandler = customDisplayMessage
        self.skipSecureElements = skipSecureElements
        self.currentlyReadingDataGroup = nil
        self.bacHandler = nil
        self.caHandler = nil
        self.paceHandler = nil
        
        // If no tags specified, read all
        if self.dataGroupsToRead.count == 0 {
            // Start off with .COM, will always read (and .SOD but we'll add that after), and then add the others from the COM
            self.dataGroupsToRead.append(contentsOf:[.COM, .SOD] )
            self.readAllDatagroups = true
        } else {
            // We are reading specific datagroups
            self.readAllDatagroups = false
        }
        
        tracer.startSession()
        tracer.emit(.info, "Session \(tracer.session): reading passport",
                    detail: "skipPACE=\(skipPACE) skipCA=\(skipCA) extendedMode=\(useExtendedMode) dataGroups=\(tags.isEmpty ? "all" : tags.map { $0.getName() }.joined(separator: ","))")

    }
}

@available(iOS 15, *)
extension PassportReader : NFCTagReaderSessionDelegate {
    // MARK: - NFCTagReaderSessionDelegate
    public func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {
        // If necessary, you may perform additional operations on session start.
        // At this point RF polling is enabled.
        PassportLogger.withCurrent(logger) {
            PassportLog.passportReader.debug( "tagReaderSessionDidBecomeActive" )
        }
    }
    
    public func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        PassportLogger.withCurrent(logger) {
            // If necessary, you may handle the error. Note session is no longer valid.
            // You must create a new session to restart RF polling.
            PassportLog.passportReader.debug( "tagReaderSession:didInvalidateWithError - \(error.localizedDescription)" )
            self.readerSession?.invalidate()
            self.readerSession = nil

            if let readerError = error as? NFCReaderError, readerError.code == NFCReaderError.readerSessionInvalidationErrorUserCanceled
                && self.shouldNotReportNextReaderSessionInvalidationErrorUserCanceled {

                self.shouldNotReportNextReaderSessionInvalidationErrorUserCanceled = false
            } else {
                var userError = NFCPassportReaderError.UnexpectedError
                if let readerError = error as? NFCReaderError {
                    PassportLog.passportReader.error( "tagReaderSession:didInvalidateWithError - Got NFCReaderError - \(readerError.localizedDescription)" )
                    switch (readerError.code) {
                    case NFCReaderError.readerSessionInvalidationErrorUserCanceled:
                        PassportLog.passportReader.error( "     - User cancelled session" )
                        userError = NFCPassportReaderError.UserCanceled
                    case NFCReaderError.readerSessionInvalidationErrorSessionTimeout:
                        PassportLog.passportReader.error("     - Session timeout")
                        userError = NFCPassportReaderError.TimeOutError
                    default:
                        PassportLog.passportReader.error( "     - some other error - \(readerError.localizedDescription)" )
                        userError = NFCPassportReaderError.UnexpectedError
                    }
                } else {
                    PassportLog.passportReader.error( "tagReaderSession:didInvalidateWithError - Received error - \(error.localizedDescription)" )
                }
                nfcContinuation?.resume(throwing: userError)
                nfcContinuation = nil
            }
        }
    }
    
    public func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        PassportLogger.withCurrent(logger) {
            handleDetectedTags(session, tags: tags)
        }
    }

    private func handleDetectedTags(_ session: NFCTagReaderSession, tags: [NFCTag]) {
        PassportLog.passportReader.debug("NFC tags detected", content: "Count: \(tags.count)")
        if tags.count > 1 {
            PassportLog.passportReader.debug("Multiple NFC tags detected", content: "Count: \(tags.count)")

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
            PassportLog.passportReader.debug( "tagReaderSession:invalid tag detected!!!" )

            let errorMessage = NFCViewDisplayMessage.error(NFCPassportReaderError.TagNotValid)
            self.invalidateSession(errorMessage:errorMessage, error: NFCPassportReaderError.TagNotValid)
            return
        }
        
        Task { [passportTag] in
            await PassportLogger.withCurrent(self.logger) {
                do {
                    try await session.connect(to: tag)

                    PassportLog.passportReader.debug( "tagReaderSession:connected to tag - starting authentication" )
                    self.updateReaderSessionMessage( alertMessage: NFCViewDisplayMessage.authenticatingWithPassport(0) )

                    let tagReader = TagReader(tag:passportTag)
                    tagReader.tracer = self.tracer
                    self.tracer.emit(.info, "Tag connected", detail: "Initially selected AID \(passportTag.initialSelectedAID)")

                    if let newAmount = self.dataAmountToReadOverride {
                        tagReader.overrideDataAmountToRead(newAmount: newAmount)
                    }

                    tagReader.progress = { (progress) in
                        if let dgId = self.currentlyReadingDataGroup {
                            self.updateReaderSessionMessage( alertMessage: NFCViewDisplayMessage.readingDataGroupProgress(dgId, progress) )
                        } else {
                            self.updateReaderSessionMessage( alertMessage: NFCViewDisplayMessage.authenticatingWithPassport(progress) )
                        }
                    }

                    let passportModel = try await self.startReading( tagReader : tagReader)
                    nfcContinuation?.resume(returning: passportModel)
                    nfcContinuation = nil
                } catch let error as NFCPassportReaderError {
                    let errorMessage = NFCViewDisplayMessage.error(error)
                    self.invalidateSession(errorMessage: errorMessage, error: error)
                } catch {
                    PassportLog.passportReader.debug( "tagReaderSession:failed to connect to tag - \(error.localizedDescription)" )

                    // .readerTransceiveErrorTagResponseError is thrown when a "connection lost" scenario is forced by moving the phone away from the NFC chip
                    // .readerTransceiveErrorTagConnectionLost is never thrown for this scenario, but added for the sake of completeness
                    if let nfcError = error as? NFCReaderError,
                       nfcError.errorCode == NFCReaderError.readerTransceiveErrorTagResponseError.rawValue ||
                        nfcError.errorCode == NFCReaderError.readerTransceiveErrorTagConnectionLost.rawValue {
                        let errorMessage = NFCViewDisplayMessage.error(NFCPassportReaderError.ConnectionError)
                        self.invalidateSession(errorMessage: errorMessage, error: NFCPassportReaderError.ConnectionError)
                    } else {
                        let errorMessage = NFCViewDisplayMessage.error(NFCPassportReaderError.Unknown(error))
                        self.invalidateSession(errorMessage: errorMessage, error: NFCPassportReaderError.Unknown(error))
                    }
                }
            }
        }
    }
    
    func updateReaderSessionMessage(alertMessage: NFCViewDisplayMessage ) {
        self.readerSession?.alertMessage = displayMessage(for: alertMessage)
    }

    private func displayMessage(for message: NFCViewDisplayMessage) -> String {
        return nfcViewDisplayMessageHandler?(message) ?? message.description
    }
}

@available(iOS 15, *)
extension PassportReader {
    
    func startReading(tagReader : TagReader) async throws -> NFCPassportModel {
        trackingDelegate?.nfcTagDetected()

        if !skipPACE {
            do {
                trackingDelegate?.paceStarted()

                tracer.emit(.info, "PACE: reading EF.CardAccess")
                let data = try await tagReader.readCardAccess()
                PassportLog.passportReader.debug("EF.CardAccess read", content: ReaderTracer.hex(data))
                let cardAccess = try CardAccess(data)
                passport.cardAccess = cardAccess

                trackingDelegate?.readCardAccess(cardAccess: cardAccess)

                PassportLog.passportReader.info( "Starting Password Authenticated Connection Establishment (PACE)" )
                 
                let paceHandler = try PACEHandler( cardAccess: cardAccess, tagReader: tagReader )
                try await paceHandler.doPACE(mrzKey: mrzKey )
                passport.PACEStatus = .success
                tracer.emit(.info, "PACE succeeded")
                PassportLog.passportReader.debug( "PACE Succeeded" )

                trackingDelegate?.paceSucceeded()
            } catch {
                trackingDelegate?.paceFailed()

                passport.PACEStatus = .failed
                PassportLog.passportReader.error( "PACE Failed - falling back to BAC" )
                tracer.emit(.error, "PACE failed, falling back to BAC: \((error as? NFCPassportReaderError)?.value ?? error.localizedDescription)")
            }
            
            _ = try await tagReader.selectPassportApplication()
        }
        
        // If either PACE isn't supported, we failed whilst doing PACE or we didn't even attempt it, then fall back to BAC
        if passport.PACEStatus != .success {
            do {
                trackingDelegate?.bacStarted()
                try await doBACAuthentication(tagReader : tagReader)
                trackingDelegate?.bacSucceeded()
            } catch {
                trackingDelegate?.bacFailed()
                throw error
            }
        }
        
        // Now to read the datagroups
        try await readDataGroups(tagReader: tagReader)

        try await doActiveAuthenticationIfNeccessary(tagReader : tagReader)

        self.updateReaderSessionMessage(alertMessage: NFCViewDisplayMessage.successfulRead)
        self.shouldNotReportNextReaderSessionInvalidationErrorUserCanceled = true
        self.readerSession?.invalidate()

        // If we have a masterlist url set then use that and verify the passport now
        self.passport.verifyPassport(masterListURL: self.masterListURL, useCMSVerification: self.passiveAuthenticationUsesOpenSSL)
        tracer.emit(.info, "Read complete",
                    detail: "PACE=\(passport.PACEStatus) BAC=\(passport.BACStatus) CA=\(passport.chipAuthenticationStatus) " +
                        "SOD signature=\(passport.passportCorrectlySigned) DSC chain=\(passport.documentSigningCertificateVerified) " +
                        "DG hashes=\(passport.passportDataNotTampered)")

        return self.passport
    }
    
    
    func doActiveAuthenticationIfNeccessary( tagReader : TagReader) async throws {
        guard self.passport.activeAuthenticationSupported else {
            return
        }
        self.updateReaderSessionMessage(alertMessage: NFCViewDisplayMessage.activeAuthentication)

        PassportLog.passportReader.info( "Performing Active Authentication" )

        let challenge = aaChallenge ?? generateRandomUInt8Array(8)
        PassportLog.passportReader.debug("Active Authentication challenge generated", content: ReaderTracer.hex(challenge))
        let response = try await tagReader.doInternalAuthentication(challenge: challenge, useExtendedMode: useExtendedMode)
        self.passport.verifyActiveAuthentication( challenge:challenge, signature:response.data )
        tracer.emit(self.passport.activeAuthenticationPassed ? .info : .error,
                    "Active Authentication \(self.passport.activeAuthenticationPassed ? "passed" : "FAILED")",
                    detail: "challenge=\(binToHexRep(challenge))")
    }
    

    func doBACAuthentication(tagReader : TagReader) async throws {
        self.currentlyReadingDataGroup = nil

        PassportLog.passportReader.info( "Starting Basic Access Control (BAC)" )
        tracer.emit(.info, "BAC started")
        
        self.passport.BACStatus = .failed

        self.bacHandler = BACHandler( tagReader: tagReader )
        try await bacHandler?.performBACAndGetSessionKeys( mrzKey: mrzKey )
        PassportLog.passportReader.info( "Basic Access Control (BAC) - SUCCESS!" )
        tracer.emit(.info, "BAC succeeded")

        self.passport.BACStatus = .success
    }

    func readDataGroups( tagReader: TagReader ) async throws {
        
        // Read COM
        var DGsToRead = [DataGroupId]()

        self.updateReaderSessionMessage( alertMessage: NFCViewDisplayMessage.readingDataGroupProgress(.COM, 0) )
        
        if let com = try await readDataGroup(tagReader:tagReader, dgId:.COM) as? COM {
            self.passport.addDataGroup( .COM, dataGroup:com )
            self.addDatagroupsToRead(com: com, to: &DGsToRead)
        }
        
        if DGsToRead.contains( .DG14 ) {
            
            if !skipCA {
                // If we have been explicitly asked to read DG14 and we will be remove it from the list as we are reading it now.
                DGsToRead.removeAll { $0 == .DG14 }

                // Do Chip Authentication
                if let dg14 = try await readDataGroup(tagReader:tagReader, dgId:.DG14) as? DataGroup14 {
                    self.passport.addDataGroup( .DG14, dataGroup:dg14 )
                    let caHandler = ChipAuthenticationHandler(dg14: dg14, tagReader: tagReader)
                     
                    if caHandler.isChipAuthenticationSupported {
                        do {
                            // Do Chip authentication and then continue reading datagroups
                            tracer.emit(.info, "Chip Authentication started")
                            try await caHandler.doChipAuthentication()
                            self.passport.chipAuthenticationStatus = .success
                            tracer.emit(.info, "Chip Authentication succeeded")
                        } catch {
                            PassportLog.passportReader.info( "Chip Authentication failed - re-establishing BAC")
                            tracer.emit(.error, "Chip Authentication failed, redoing BAC: \(error.localizedDescription)")
                            self.passport.chipAuthenticationStatus = .failed
                            
                            // Failed Chip Auth, need to re-establish BAC
                            try await doBACAuthentication(tagReader: tagReader)
                        }
                    }
                }
            }
        }

        // If we are skipping secure elements then remove .DG3 and .DG4
        if self.skipSecureElements {
            DGsToRead = DGsToRead.filter { $0 != .DG3 && $0 != .DG4 }
        }

        if self.readAllDatagroups != true {
            DGsToRead = DGsToRead.filter { dataGroupsToRead.contains($0) }
        }
        for dgId in DGsToRead {
            self.updateReaderSessionMessage( alertMessage: NFCViewDisplayMessage.readingDataGroupProgress(dgId, 0) )
            if let dg = try await readDataGroup(tagReader:tagReader, dgId:dgId) {
                self.passport.addDataGroup( dgId, dataGroup:dg )
            }
        }
    }
    
    func readDataGroup( tagReader : TagReader, dgId : DataGroupId ) async throws -> DataGroup?  {

        self.currentlyReadingDataGroup = dgId
        PassportLog.passportReader.info( "Reading tag - \(dgId.getName())" )
        tracer.emit(.info, "Reading \(dgId.getName())")
        var readAttempts = 0
        var nfcPassportReaderError: NFCPassportReaderError
        
        self.updateReaderSessionMessage( alertMessage: NFCViewDisplayMessage.readingDataGroupProgress(dgId, 0) )

        repeat {
            do {
                let response = try await tagReader.readDataGroup(dataGroup:dgId)
                let dg = try DataGroupParser().parseDG(data: response)
                return dg
            } catch let error as NFCPassportReaderError {
                PassportLog.passportReader.error( "TagError reading tag - \(error)" )
                nfcPassportReaderError = error

                // OK we had an error - depending on what happened, we may want to try to re-read this
                // E.g. we failed to read the last Datagroup because its protected and we can't
                let errMsg = error.value
                PassportLog.passportReader.error( "ERROR - \(errMsg)" )
                var redoBAC = false
                if errMsg == "Session invalidated" || errMsg == "Class not supported" || errMsg == "Tag connection lost" || errMsg == "Tag response error / no response" {
                    // Check if we have done Chip Authentication, if so, set it to nil and try to redo BAC
                    if self.caHandler != nil {
                        self.caHandler = nil
                        redoBAC = true
                    } else {
                        // Can't go any more!
                        throw error
                    }
                } else if errMsg == "Security status not satisfied" || errMsg == "File not found" {
                    // Can't read this element as we aren't allowed - remove it and return out so we re-do BAC
                    self.dataGroupsToRead.removeFirst()
                    redoBAC = true
                } else if errMsg == "SM data objects incorrect" || errMsg == "Class not supported" {
                    // Can't read this element security objects now invalid - and return out so we re-do BAC
                    redoBAC = true
                } else if errMsg.hasPrefix( "Wrong length" ) || errMsg.hasPrefix( "End of file" ) {  // Should now handle errors 0x6C xx, and 0x67 0x00
                    // OK passport can't handle max length so drop it down
                    tagReader.reduceDataReadingAmount()
                    redoBAC = true
                } else if errMsg == "UnsupportedDataGroup" {
                    // OK, this DataGroup is not supported, lets skip it
                    PassportLog.passportReader.debug("Unsupported DataGroup - \(dgId.rawValue)")
                    return nil
                }
                
                if redoBAC {
                    // Redo BAC and try again
                    try await doBACAuthentication(tagReader : tagReader)
                } else {
                    // Some other error lets have another try
                }
            }
            readAttempts += 1
        } while ( readAttempts < 2 )

        // The error will be thrown after n attempts
        throw nfcPassportReaderError
    }

    func invalidateSession(errorMessage: NFCViewDisplayMessage, error: NFCPassportReaderError) {
        tracer.emit(.error, "Read failed: \(error.value)")
        // Mark the next 'invalid session' error as not reportable (we're about to cause it by invalidating the
        // session). The real error is reported back with the call to the completed handler
        self.shouldNotReportNextReaderSessionInvalidationErrorUserCanceled = true
        self.readerSession?.invalidate(errorMessage: displayMessage(for: errorMessage))
        nfcContinuation?.resume(throwing: error)
        nfcContinuation = nil
    }
    
    internal func addDatagroupsToRead(com: COM, to DGsToRead: inout [DataGroupId]) {
        DGsToRead += com.dataGroupsPresent.compactMap { DataGroupId.getIDFromName(name:$0) }
        DGsToRead.removeAll { $0 == .COM }
        
        // SOD should not be present in COM, but just in case we check before adding it so its not read twice
        if !DGsToRead.contains(.SOD) { DGsToRead.insert(.SOD, at: 0) }
    }
}
#endif
