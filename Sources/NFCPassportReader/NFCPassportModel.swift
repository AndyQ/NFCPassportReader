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
    
    public lazy var documentType : String = { return String( passportDataElements?["5F03"]?.first ?? "?" ) }()
    public lazy var documentSubType : String = { return String( passportDataElements?["5F03"]?.last ?? "?" ) }()
    public lazy var personalNumber : String = { return (passportDataElements?["53"] ?? "?").replacingOccurrences(of: "<", with: "" ) }()
    public lazy var documentNumber : String = { return (passportDataElements?["5A"] ?? "?").replacingOccurrences(of: "<", with: "" ) }()
    public lazy var issuingAuthority : String = { return passportDataElements?["5F28"] ?? "?" }()
    public lazy var documentExpiryDate : String = { return passportDataElements?["59"] ?? "?" }()
    public lazy var dateOfBirth : String = { return passportDataElements?["5F57"] ?? "?" }()
    public lazy var gender : String = { return passportDataElements?["5F35"] ?? "?" }()
    public lazy var nationality : String = { return passportDataElements?["5F2C"] ?? "?" }()

    public lazy var lastName : String = {
        let names = (passportDataElements?["5B"] ?? "?").components(separatedBy: "<<")
        return names[0].replacingOccurrences(of: "<", with: " " )
    }()
    
    public lazy var firstName : String = {
        let names = (passportDataElements?["5B"] ?? "?").components(separatedBy: "<<")
        var name = ""
        for i in 1 ..< names.count {
            let fn = names[i].replacingOccurrences(of: "<", with: " " ).trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
            name += fn + " "
        }
        return name.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
    }()
    
    public lazy var passportMRZ : String = { return passportDataElements?["5F1F"] ?? "NOT FOUND" }()
    
        
    public lazy var documentSigningCertificate : X509Wrapper? = {
        return certificateSigningGroups[.documentSigningCertificate]
    }()

    public lazy var countrySigningCertificate : X509Wrapper? = {
        return certificateSigningGroups[.issuerSigningCertificate]
    }()

    // Extract data from COM
    public lazy var LDSVersion : String = {
        guard let com = dataGroupsRead[.COM] as? COM else { return "Unknown" }
        return com.version
    }()
    
    public lazy var dataGroupsPresent : [String] = {
        guard let com = dataGroupsRead[.COM] as? COM else { return [] }
        return com.dataGroupsPresent
    }()
    
    // Parsed datagroup hashes
    public var dataGroupHashes = [DataGroupId: DataGroupHash]()
    

    public var passportCorrectlySigned : Bool = false
    public var passportDataValid : Bool = false
    public var verificationErrors : [Error] = []

    
    public var passportImage : UIImage? {
        guard let dg2 = dataGroupsRead[.DG2] as? DataGroup2 else { return nil }
        
        return dg2.getImage()
        
    }
    public var signatureImage : UIImage? {
        guard let dg7 = dataGroupsRead[.DG7] as? DataGroup7 else { return nil }
        
        return dg7.getImage()
    }

    private var dataGroupsRead : [DataGroupId:DataGroup] = [:]
    private var certificateSigningGroups : [CertificateType:X509Wrapper] = [:]

    private var passportDataElements : [String:String]? {
        guard let dg1 = dataGroupsRead[.DG1] as? DataGroup1 else { return nil }
        
        return dg1.elements
    }
        
    public init() {
        
    }
    
    public func addDataGroup(_ id : DataGroupId, dataGroup: DataGroup ) {
        self.dataGroupsRead[id] = dataGroup
    }

    public func getDataGroup( _ id : DataGroupId ) -> DataGroup? {
        return dataGroupsRead[id]
    }

    public func getHashesForDatagroups( hashAlgorythm: String ) -> [DataGroupId:[UInt8]]  {
        var ret = [DataGroupId:[UInt8]]()
        
        for (key, value) in dataGroupsRead {
            if hashAlgorythm == "SHA256" {
                ret[key] = calcSHA256Hash(value.body)
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


    public func verifyPassport( masterListURL: URL ) -> Bool {
        OpenSSLUtils.loadOpenSSL()
        defer { OpenSSLUtils.cleanupOpenSSL() }
        do {
            try validateAndExtractSigningCertificates( masterListURL: masterListURL )
            self.passportCorrectlySigned = true
        } catch let error {
            self.passportCorrectlySigned = false
            verificationErrors.append( error )
        }
        
        do {
            try ensureReadDataNotBeenTamperedWith( )
            self.passportDataValid = true
        } catch let error {
            self.passportDataValid = false
            verificationErrors.append( error )
        }
        
        return self.passportCorrectlySigned && self.passportDataValid
    }
    
    private func validateAndExtractSigningCertificates( masterListURL: URL ) throws {
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
    }

    private func ensureReadDataNotBeenTamperedWith( ) throws  {
        guard let sod = getDataGroup(.SOD) else {
            throw PassiveAuthenticationError.SODMissing("No SOD found" )
        }

        // Get SOD Content
        let data = Data(sod.body)
        
        let signedData = try OpenSSLUtils.verifyAndGetSignedDataFromPKCS7(pkcs7Der: data)
        let asn1Data = try OpenSSLUtils.ASN1Parse( data: signedData )
        
        let (sodHashAlgorythm, sodHashes) = try parseSODSignatureContent( asn1Data )
        
        // Now compare Hashes
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
            throw PassiveAuthenticationError.InvalidDataGroupHash(errors)
        }
        
        Log.debug( "Passport passed Datagroup Tampering check" )
    }
    
    
    /// Parses an text ASN1 structure, and extracts the Hash Algorythm and Hashes contained from the Octect strings
    /// - Parameter content: the text ASN1 stucure format
    /// - Returns: The Has Algorythm used - either SHA1 or SHA256, and a dictionary of hashes for the datagroups (currently only DG1 and DG2 are handled)
    private func parseSODSignatureContent( _ content : String ) throws -> (String, [DataGroupId : String]){
        var currentDG = ""
        var sodHashAlgo = ""
        var sodHashes :  [DataGroupId : String] = [:]
        
        let lines = content.components(separatedBy: "\n")
        for line in lines {
            if line.contains( "d=2" ) && line.contains( "OBJECT" ) {
                if line.contains( "sha1" ) {
                    sodHashAlgo = "SHA1"
                } else if line.contains( "sha256" ) {
                    sodHashAlgo = "SHA256"
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
                            sodHashes[.DG1] = String(val)
                        } else if currentDG == "02" {
                            sodHashes[.DG2] = String(val)
                        }
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
