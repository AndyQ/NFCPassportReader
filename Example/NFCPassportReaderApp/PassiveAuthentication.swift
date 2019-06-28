//
//  PassiveAuthentication.swift
//  NFCPassportReaderApp
//
//  Created by Andy Qua on 27/06/2019.
//  Copyright © 2019 Andy Qua. All rights reserved.
//

import Foundation
import NFCPassportReader


public enum PassiveAuthenticationError: Error {
    case UnableToGetPKCS7CertificateForSOD
    case UnableToVerifyX509CertificateForSOD
    case UnableToParseSODHashes
    case InvalidDataGroupHash(String)
}

extension PassiveAuthenticationError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .UnableToGetPKCS7CertificateForSOD:
            return NSLocalizedString("Unable to read the SOD PKCS7 Certificate.", comment: "UnableToGetPKCS7CertificateForSOD")
        case .UnableToVerifyX509CertificateForSOD:
            return NSLocalizedString("Unable to verify the SOD X509 certificate.", comment: "UnableToVerifyX509CertificateForSOD")
        case .UnableToParseSODHashes:
            return NSLocalizedString("Unable to parse the SOD Datagroup hashes.", comment: "UnableToParseSODHashes")
        case .InvalidDataGroupHash:
            return NSLocalizedString("DataGroup hash not present or didn't match (see message for details)!", comment: "InvalidDataGroupHash")
        }
    }
}

/// This class handles the ePassport PassiveAuthentication
/// It verifies that the SOD Document Signing Certificate (DCS) is valid (ias within a specified masterList)
/// And confirms that the Hashes of the DataGroups match those in the SOD, to ensure no tampering
///
/// Ideally this would be its own Swift Package but it heavily uses OpenSSL library (and the apps C code), and currently SPM doesn't support mixed code it isn't
///
/// Note - because my knowledge of OpenSSL is *VERY* limited, I've currently just brought over all the code directly from the OpenSSL Apps and slightly
/// modified it to allow calling. BUT because of this, all communications between us and OpenSSL is currently through files (which I know is crap!).
/// I'd like a proper swift wrapper around the OpenSSL library at some point (any volunteers?)
///
public class PassiveAuthentication {
    var sodHashAlgo = ""
    var sodHashes : [DataGroupId : String] = [:]
    
    func validatePassport( sodBody : [UInt8], dataGroupsToCheck : [DataGroupId : DataGroup] ) throws  {
        let tmpSODFile = getTempFile()
        // Write SOD to temp file
        let d = Data(sodBody)
        try! d.write(to: tmpSODFile)
        defer {
            cleanupTempFile( tmpSODFile )
        }

        try verifySOD(tmpSODFile)
        Log.debug( "Passport passed SOD Verification" )
        
        try verifyDataGroups(tmpSODFile, dataGroupsToCheck: dataGroupsToCheck )
        Log.debug( "Passport passed SOD Verification" )
    }
    
    private func verifySOD(_ SODFileName : URL) throws {
        let tmpOutFile = getTempFile()
        defer {
            cleanupTempFile( tmpOutFile )
        }

        let rc1 = retrievePKCS7Certificate(SODFileName.path, tmpOutFile.path, 1, 1, 1)
        if rc1 != 0 {
            throw PassiveAuthenticationError.UnableToGetPKCS7CertificateForSOD
        }

        let masterList = Bundle.main.path(forResource: "masterList", ofType: "pem")!
        let rc2 = verifyX509Certificate(tmpOutFile.path, masterList)
        if rc2 != 0 {
            throw PassiveAuthenticationError.UnableToVerifyX509CertificateForSOD
        }
    }
    
    private func verifyDataGroups(_ SODFileName : URL, dataGroupsToCheck : [DataGroupId : DataGroup]) throws {
        // Get SOD Content
        
        let tmpOutFile = getTempFile()
        let tmpHashesFile = getTempFile()
        defer {
            cleanupTempFile( tmpOutFile )
            cleanupTempFile( tmpHashesFile )
        }
        
        // Note this doesn't do any verification at all - just dumps the signature content to the output file
        let rc1 = getPkcs7SignatureContent(1, SODFileName.path, tmpOutFile.path, 1, 1)
        if rc1 != 0 {
            throw PassiveAuthenticationError.UnableToVerifyX509CertificateForSOD
        }
        
        let rc2 = asn1parse(tmpOutFile.path, tmpHashesFile.path, 1, 1)
        if rc2 != 0 {
            throw PassiveAuthenticationError.UnableToParseSODHashes
        }

        let certData = try! String(contentsOf: tmpHashesFile)
        parseSignatureContent( certData )
        
        // Now compare Hashes
        var errors : String = ""
        for (id,val) in sodHashes {
            guard let dg = dataGroupsToCheck[id] else {
                errors += "DataGroup \(id) is missing!\n"
                continue
            }
            
            let hash = binToHexRep(dg.hash(self.sodHashAlgo))

            if hash != val {
                errors += "\(id) invalid hash:\n  SOD:\(val)\n   DG:\(hash)\n"
            }
        }
        
        if errors != "" {
            throw PassiveAuthenticationError.InvalidDataGroupHash(errors)
        }
    }
    
    private func getTempFile() -> URL {
        let temporaryDirectoryURL = URL(fileURLWithPath: NSTemporaryDirectory(),
                                        isDirectory: true)
        let temporaryFilename = ProcessInfo().globallyUniqueString
        
        let temporaryFileURL =
            temporaryDirectoryURL.appendingPathComponent(temporaryFilename)

        return temporaryFileURL
    }
    
    private func cleanupTempFile( _ temporaryFileURL : URL ) {
        try? FileManager.default.removeItem(at: temporaryFileURL)
    }
    
    private func parseSignatureContent( _ content : String ) {
        var currentDG = ""
        
        let lines = content.components(separatedBy: "\n")
        for line in lines {
            if line.contains( "d=2" ) && line.contains( "OBJECT" ) {
                if line.contains( "sha1" ) {
                    self.sodHashAlgo = "SHA1"
                } else if line.contains( "sha256" ) {
                    self.sodHashAlgo = "SHA256"
                }
            } else if line.contains("d=3" ) && line.contains( "INTEGER" ) {
                if let range = line.range(of: "INTEGER") {
                    let substr = line[range.upperBound..<line.endIndex]
                    if let r2 = substr.range(of: ":") {
                        currentDG = String(line[r2.upperBound...])
                    }
                }

            } else if line.contains("d=3" ) && line.contains( "OCTET STRING" ) {
                if let range = line.range(of: "[HEX DUMP]:") {
                    let val = line[range.upperBound..<line.endIndex]
                    if currentDG != "" {
                        if currentDG == "01" {
                            self.sodHashes[.DG1] = String(val)
                        } else if currentDG == "02" {
                            self.sodHashes[.DG2] = String(val)
                        }
                        currentDG = ""
                    }
                }
            }
        }
        
        Log.debug( "Parse - Using Algo - \(self.sodHashAlgo)" )
        Log.debug( "      - Hashes     - \(self.sodHashes)" )
    }
}
