//
//  NFCPassportModel.swift
//  NFCPassportReader
//
//  Created by Andy Qua on 29/10/2019.
//

import UIKit

@available(iOS 13, *)
public struct DataGroupHash {
    public var id: String
    public var sodHash: String
    public var computedHash : String
    public var match : Bool
}

@available(iOS 13, *)
public class NFCPassportModel {
    
    public private(set) lazy var documentType : String = { return String( passportDataElements?["5F03"]?.first ?? "?" ) }()
    public private(set) lazy var documentSubType : String = { return String( passportDataElements?["5F03"]?.last ?? "?" ) }()
    public private(set) lazy var personalNumber : String = { return (passportDataElements?["53"] ?? "?").replacingOccurrences(of: "<", with: "" ) }()
    public private(set) lazy var documentNumber : String = { return (passportDataElements?["5A"] ?? "?").replacingOccurrences(of: "<", with: "" ) }()
    public private(set) lazy var issuingAuthority : String = { return passportDataElements?["5F28"] ?? "?" }()
    public private(set) lazy var documentExpiryDate : String = { return passportDataElements?["59"] ?? "?" }()
    public private(set) lazy var dateOfBirth : String = { return passportDataElements?["5F57"] ?? "?" }()
    public private(set) lazy var gender : String = { return passportDataElements?["5F35"] ?? "?" }()
    public private(set) lazy var nationality : String = { return passportDataElements?["5F2C"] ?? "?" }()

    public private(set) lazy var lastName : String = {
        let names = (passportDataElements?["5B"] ?? "?").components(separatedBy: "<<")
        return names[0].replacingOccurrences(of: "<", with: " " )
    }()
    
    public private(set) lazy var firstName : String = {
        let names = (passportDataElements?["5B"] ?? "?").components(separatedBy: "<<")
        var name = ""
        for i in 1 ..< names.count {
            let fn = names[i].replacingOccurrences(of: "<", with: " " ).trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
            name += fn + " "
        }
        return name.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
    }()
    
    public private(set) lazy var passportMRZ : String = { return passportDataElements?["5F1F"] ?? "NOT FOUND" }()
    
        
    public private(set) lazy var documentSigningCertificate : X509Wrapper? = {
        return certificateSigningGroups[.documentSigningCertificate]
    }()

    public private(set) lazy var countrySigningCertificate : X509Wrapper? = {
        return certificateSigningGroups[.issuerSigningCertificate]
    }()

    // Extract data from COM
    public private(set) lazy var LDSVersion : String = {
        guard let com = dataGroupsRead[.COM] as? COM else { return "Unknown" }
        return com.version
    }()
    
    
    public private(set) lazy var dataGroupsPresent : [String] = {
        guard let com = dataGroupsRead[.COM] as? COM else { return [] }
        return com.dataGroupsPresent
    }()
    
    // Parsed datagroup hashes
    public private(set) var dataGroupsAvailable = [DataGroupId]()
    public private(set) var dataGroupsRead : [DataGroupId:DataGroup] = [:]
    public private(set) var dataGroupHashes = [DataGroupId: DataGroupHash]()

    public private(set) var passportCorrectlySigned : Bool = false
    public private(set) var documentSigningCertificateVerified : Bool = false
    public private(set) var passportDataNotTampered : Bool = false
    public private(set) var activeAuthenticationPassed : Bool = false
    public private(set) var verificationErrors : [Error] = []

    public var passportImage : UIImage? {
        guard let dg2 = dataGroupsRead[.DG2] as? DataGroup2 else { return nil }
        
        return dg2.getImage()
    }
    
    public var signatureImage : UIImage? {
        guard let dg7 = dataGroupsRead[.DG7] as? DataGroup7 else { return nil }
        
        return dg7.getImage()
    }
    
    public var activeAuthenticationSupported : Bool {
        guard let dg15 = dataGroupsRead[.DG15] as? DataGroup15 else { return false }
        if dg15.ecdsaPublicKey != nil || dg15.rsaPublicKey != nil {
            return true
        }
        return false
    }

    private var certificateSigningGroups : [CertificateType:X509Wrapper] = [:]

    private var passportDataElements : [String:String]? {
        guard let dg1 = dataGroupsRead[.DG1] as? DataGroup1 else { return nil }
        
        return dg1.elements
    }
        
    
    public init() {
        
    }
    
    public func addDataGroup(_ id : DataGroupId, dataGroup: DataGroup ) {
        self.dataGroupsRead[id] = dataGroup
        if id != .COM && id != .SOD {
            self.dataGroupsAvailable.append( id )
        }
    }

    public func getDataGroup( _ id : DataGroupId ) -> DataGroup? {
        return dataGroupsRead[id]
    }

    public func getHashesForDatagroups( hashAlgorythm: String ) -> [DataGroupId:[UInt8]]  {
        var ret = [DataGroupId:[UInt8]]()
        
        for (key, value) in dataGroupsRead {
            if hashAlgorythm == "SHA256" {
                ret[key] = calcSHA256Hash(value.body)
            } else if hashAlgorythm == "SHA384" {
                ret[key] = calcSHA1Hash(value.body)
            } else if hashAlgorythm == "SHA1" {
                ret[key] = calcSHA1Hash(value.body)
            }
        }
        
        return ret
    }
    
            
    // Two Parts:
    // Part 1 - Has the SOD (Security Object Document) been signed by a valid country signing certificate authority (CSCA)?
    // Part 2 - has it been tampered with (e.g. hashes of Datagroups match those in the SOD?
    //        guard let sod = model.getDataGroup(.SOD) else { return }


    public func verifyPassport( masterListURL: URL? ) {
        if let masterListURL = masterListURL {
            do {
                try validateAndExtractSigningCertificates( masterListURL: masterListURL )
            } catch let error {
                verificationErrors.append( error )
            }
        }
        
        do {
            try ensureReadDataNotBeenTamperedWith( )
        } catch let error {
            verificationErrors.append( error )
        }
    }
    
    public func verifyActiveAuthentication( challenge: [UInt8], signature: [UInt8] ) {
        
        // Get AA Public key
        self.activeAuthenticationPassed = false
        guard  let dg15 = self.dataGroupsRead[.DG15] as? DataGroup15 else { return }
        if let _ = dg15.rsaPublicKey {
            // TODO
        } else if let ecdsaPublicKey = dg15.ecdsaPublicKey {
            if OpenSSLUtils.verifyECDSASignature( publicKey:ecdsaPublicKey, signature: signature, data: challenge ) {
                self.activeAuthenticationPassed = true
            }
        }
    }
    
    // Check if signing certificate is on the revocation list
    // We do this by trying to build a trust chain of the passport certificate against the ones in the revocation list
    // and if we are successful then its been revoked.
    // NOTE - NOT USED YET AS NOT ABLE TO TEST
    func hasCertBeenRevoked( revocationListURL : URL ) -> Bool {
        var revoked = false
        do {
            try validateAndExtractSigningCertificates( masterListURL: revocationListURL )
            
            // Certificate chain found - which means certificate is on revocation list
            revoked = true
        } catch {
            // No chain found - certificate not revoked
        }
        
        return revoked
    }

    private func validateAndExtractSigningCertificates( masterListURL: URL ) throws {
        self.passportCorrectlySigned = false
        
        guard let sod = getDataGroup(.SOD) else {
            throw PassiveAuthenticationError.SODMissing("No SOD found" )
        }

        let data = Data(sod.body)
        let cert = try OpenSSLUtils.getX509CertificatesFromPKCS7( pkcs7Der: data ).first!
        self.certificateSigningGroups[.documentSigningCertificate] = cert

        let rc = OpenSSLUtils.verifyTrustAndGetIssuerCertificate( x509:cert, CAFile: masterListURL )
        switch rc {
        case .success(let csca):
            self.certificateSigningGroups[.issuerSigningCertificate] = csca
        case .failure(let error):
            throw error
        }
                
        Log.debug( "Passport passed SOD Verification" )
        self.passportCorrectlySigned = true

    }

    private func ensureReadDataNotBeenTamperedWith( ) throws  {
        guard let sod = getDataGroup(.SOD) else {
            throw PassiveAuthenticationError.SODMissing("No SOD found" )
        }

        // Get SOD Content and verify that its correctly signed by the Document Signing Certificate
        let data = Data(sod.body)
        var signedData : Data
        documentSigningCertificateVerified = false
        do {
            signedData = try OpenSSLUtils.verifyAndGetSignedDataFromPKCS7(pkcs7Der: data)
            documentSigningCertificateVerified = true
        } catch {
            signedData = try OpenSSLUtils.extractSignedDataNoVerificationFromPKCS7( pkcs7Der : data)
        }
                
        // Now Verify passport data by comparing compare Hashes in SOD against
        // computed hashes to ensure data not been tampered with
        passportDataNotTampered = false
        let asn1Data = try OpenSSLUtils.ASN1Parse( data: signedData )
        let (sodHashAlgorythm, sodHashes) = try parseSODSignatureContent( asn1Data )
        
        var errors : String = ""
        for (id,dgVal) in dataGroupsRead {
            guard let sodHashVal = sodHashes[id] else {
                // SOD and COM don't have hashes so these aren't errors
                if id != .SOD && id != .COM {
                    errors += "DataGroup \(id) is missing!\n"
                }
                continue
            }
            
            let computedHashVal = binToHexRep(dgVal.hash(sodHashAlgorythm))
            
            var match = true
            if computedHashVal != sodHashVal {
                errors += "\(id) invalid hash:\n  SOD hash:\(sodHashVal)\n   Computed hash:\(computedHashVal)\n"
                match = false
            }

            dataGroupHashes[id] = DataGroupHash(id: id.getName(), sodHash:sodHashVal, computedHash:computedHashVal, match:match)
        }
        
        if errors != "" {
            Log.error( "HASH ERRORS - \(errors)" )
            throw PassiveAuthenticationError.InvalidDataGroupHash(errors)
        }
        
        Log.debug( "Passport passed Datagroup Tampering check" )
        passportDataNotTampered = true
    }
    
    
    /// Parses an text ASN1 structure, and extracts the Hash Algorythm and Hashes contained from the Octect strings
    /// - Parameter content: the text ASN1 stucure format
    /// - Returns: The Has Algorythm used - either SHA1 or SHA256, and a dictionary of hashes for the datagroups (currently only DG1 and DG2 are handled)
    private func parseSODSignatureContent( _ content : String ) throws -> (String, [DataGroupId : String]){
        var currentDG = ""
        var sodHashAlgo = ""
        var sodHashes :  [DataGroupId : String] = [:]
        
        let lines = content.components(separatedBy: "\n")
        
        let dgList : [DataGroupId] = [.COM,.DG1,.DG2,.DG3,.DG4,.DG5,.DG6,.DG7,.DG8,.DG9,.DG10,.DG11,.DG12,.DG13,.DG14,.DG15,.DG16,.SOD]

        for line in lines {
            if line.contains( "d=2" ) && line.contains( "OBJECT" ) {
                if line.contains( "sha1" ) {
                    sodHashAlgo = "SHA1"
                } else if line.contains( "sha256" ) {
                    sodHashAlgo = "SHA256"
                } else if line.contains( "sha384" ) {
                    sodHashAlgo = "SHA384"
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
                    if currentDG != "", let id = Int(currentDG, radix:16) {
                        sodHashes[dgList[id]] = String(val)
                        currentDG = ""
                    }
                }
            }
        }
        
        if sodHashAlgo == "" {
            throw PassiveAuthenticationError.UnableToParseSODHashes("Unable to find hash algorythm used" )
        }
        if sodHashes.count == 0 {
            throw PassiveAuthenticationError.UnableToParseSODHashes("Unable to extract hashes" )
        }

        Log.debug( "Parse - Using Algo - \(sodHashAlgo)" )
        Log.debug( "      - Hashes     - \(sodHashes)" )
        
        return (sodHashAlgo, sodHashes)
    }
}
