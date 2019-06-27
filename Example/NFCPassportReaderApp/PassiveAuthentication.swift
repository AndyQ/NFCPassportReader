//
//  PassiveAuthentication.swift
//  NFCPassportReaderApp
//
//  Created by Andy Qua on 27/06/2019.
//  Copyright © 2019 Andy Qua. All rights reserved.
//

import Foundation
import NFCPassportReader



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
class PassiveAuthentication {
    var sodHashAlgo = ""
    var sodHashes : [DataGroupId : String] = [:]
    
    func validatePassport( sodBody : [UInt8], dataGroupsToCheck : [DataGroupId : DataGroup] ) -> Bool {
        let tmpSODFile = getTempFile()
        // Write SOD to temp file
        let d = Data(sodBody)
        try! d.write(to: tmpSODFile)
        defer {
            cleanupTempFile( tmpSODFile )
        }

        
        if !verifySOD(tmpSODFile) {
            Log.error( "Passport failed SOD Verification" )
            return false
        }
        
        Log.info( "Passport passed SOD Verification" )
        
        if !verifyDataGroups(tmpSODFile, dataGroupsToCheck: dataGroupsToCheck ) {
            Log.error( "Passport failed DataGroup Verification" )
            return false
        }
        Log.info( "Passport passed SOD Verification" )

        return true
    }
    
    private func verifySOD(_ SODFileName : URL) -> Bool {
        let tmpOutFile = getTempFile()
        defer {
            cleanupTempFile( tmpOutFile )
        }

        let rc1 = retrievePKCS7Certificate(SODFileName.path, tmpOutFile.path, 1, 1, 1)
        Log.debug( "retrievePKCS7Certificate rc = \(rc1)" )
        if rc1 != 0 {
            return false
        }

        let masterList = Bundle.main.path(forResource: "masterList", ofType: "pem")!
        let rc2 = verifyX509Certificate(tmpOutFile.path, masterList)
        Log.debug( "verifyX509Certificate rc = \(rc2)" )
        
        return rc2 == 0
    }
    
    private func verifyDataGroups(_ SODFileName : URL, dataGroupsToCheck : [DataGroupId : DataGroup]) -> Bool {
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
            Log.error( "Failed to get PCKS7 Signature for SOD Object!" )
            return false
        }
        
        let rc2 = asn1parse(tmpOutFile.path, tmpHashesFile.path, 1, 1)
        if rc2 != 0 {
            Log.error( "Failed to get parse out SOD Hashes!" )
            return false
        }

        let certData = try! String(contentsOf: tmpHashesFile)
        parseSignatureContent( certData )
        
        // Now compare Hashes
        for (id,val) in sodHashes {
            guard let dg = dataGroupsToCheck[id] else { Log.error( "DG missing! \(id)" ); return false }
            let hash = binToHexRep(dg.hash(self.sodHashAlgo))
            
            if hash != val {
                Log.info( "\(id) invalid hash - SOD:\(val),  DG:\(hash)" )
                return false
            } else {
                Log.info( "\(id) hash matches SOD - SOD:\(val),  DG:\(hash)" )
            }
        }
        return true
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
