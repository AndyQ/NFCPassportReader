//
//  PassiveAuthentication.swift
//  NFCPassportReaderApp
//
//  Created by Andy Qua on 27/06/2019.
//  Copyright © 2019 Andy Qua. All rights reserved.
//

import Foundation
import NFCPassportReader
import OpenSSL

@available(iOS 13, *)
public enum PassiveAuthenticationError: Error {
    case UnableToGetX509CertificateFromPKCS7(String)
    case UnableToVerifyX509CertificateForSOD(String)
    case UnableToParseSODHashes(String)
    case UnableToGetSignedDataFromPKCS7(String)
    case InvalidDataGroupHash(String)
}
@available(iOS 13, *)
extension PassiveAuthenticationError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .UnableToGetX509CertificateFromPKCS7(let reason):
            return NSLocalizedString("Unable to read the SOD PKCS7 Certificate. \(reason)", comment: "UnableToGetPKCS7CertificateForSOD")
        case .UnableToVerifyX509CertificateForSOD(let reason):
            return NSLocalizedString("Unable to verify the SOD X509 certificate. \(reason)", comment: "UnableToVerifyX509CertificateForSOD")
        case .UnableToParseSODHashes(let reason):
            return NSLocalizedString("Unable to parse the SOD Datagroup hashes. \(reason)", comment: "UnableToParseSODHashes")
        case .UnableToGetSignedDataFromPKCS7(let reason):
            return NSLocalizedString("Unable to parse the SOD Datagroup hashes. \(reason)", comment: "UnableToGetSignedDataFromPKCS7")
        case .InvalidDataGroupHash(let reason):
            return NSLocalizedString("DataGroup hash not present or didn't match  \(reason)!", comment: "InvalidDataGroupHash")
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
@available(iOS 13, *)
public class PassiveAuthentication {
    let masterList: URL
    
    public init(_ masterList: URL) {
        self.masterList = masterList
        initOpenSSL()
    }
    
    deinit {
        cleanupOpenSSL()
    }
    
    func initOpenSSL() {
        OPENSSL_add_all_algorithms_noconf()
    }
    
    func cleanupOpenSSL() {
        CONF_modules_unload(1)
        OBJ_cleanup();
        EVP_cleanup();
        CRYPTO_cleanup_all_ex_data()
        ERR_remove_thread_state(nil)
        RAND_cleanup()
        ERR_free_strings()
    }
    
    
    /// Checks whether the SOD Object in an EPassport is correctly signed - i.e. a trust chain can be built up and verified
    /// from a masterList.pem file (a text fie containing a list of certificates in PEM format use to try try to build a trust chain)
    /// - Parameter sodBody: The SOD Object body
    public func checkPassportCorrectlySigned( sodBody : [UInt8] ) throws {
        let data = Data(sodBody)
        let cert = try getX509CertificateFromPKCS7( pkcs7Der: data )

        try verifyX509Certificate( x509Cert:cert, CAFile: masterList)

        Log.debug( "Passport passed SOD Verification" )
    }
    
    /// Extracts the signed data section from the SOD Object.  This contains a set of hashes of datagroups contained within the E-Passport
    /// These hashes are then compared against the hashes of the acual datagroups we've read to make sure that the data we have read hasn't been tampered with
    /// - Parameter sodBody: The SOD Object body
    /// - Parameter dataGroupsToCheck: The set of datagroups to check
    public func checkDataNotBeenTamperedWith( sodBody : [UInt8], dataGroupsToCheck : [DataGroupId : DataGroup] ) throws  {
        
        // Get SOD Content
        let data = Data(sodBody)
        
        let signedData = try getSignedDataFromPKCS7(pkcs7Der: data)
        let asn1Data = try ASN1Parse( data: signedData )
        
        let (sodHashAlgorythm, sodHashes) = try parseSignatureContent( asn1Data )
        
        // Now compare Hashes
        var errors : String = ""
        for (id,val) in sodHashes {
            guard let dg = dataGroupsToCheck[id] else {
                errors += "DataGroup \(id) is missing!\n"
                continue
            }
            
            let hash = binToHexRep(dg.hash(sodHashAlgorythm))
            
            if hash != val {
                errors += "\(id) invalid hash:\n  SOD:\(val)\n   DG:\(hash)\n"
            }
        }
        
        if errors != "" {
            throw PassiveAuthenticationError.InvalidDataGroupHash(errors)
        }
        
        Log.debug( "Passport passed Datagroup Tampering check" )
    }
    
    
    /// Parses an text ASN1 structure, and extracts the Hash Algorythm and Hashes contained from the Octect strings
    /// - Parameter content: the text ASN1 stucure format
    /// - Returns: The Has Algorythm used - either SHA1 or SHA256, and a dictionary of hashes for the datagroups (currently only DG1 and DG2 are handled)
    private func parseSignatureContent( _ content : String ) throws -> (String, [DataGroupId : String]){
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

// MARK: OPENSSL wrapper functions
@available(iOS 13, *)
extension PassiveAuthentication {
    /// Extracts a X509 certificate in PEM format from a PKCS7 container
    /// - Parameter pkcs7Der: The PKCS7 container in DER format
    /// - Returns: The PEM formatted X509 certificate
    /// - Throws: A PassiveAuthenticationError.UnableToGetX509CertificateFromPKCS7 are thrown for any error
    func getX509CertificateFromPKCS7( pkcs7Der : Data ) throws -> String {
        
        guard let inf = BIO_new(BIO_s_mem()) else { throw PassiveAuthenticationError.UnableToGetX509CertificateFromPKCS7("Unable to allocate input buffer") }
        defer { BIO_free(inf) }
        let _ = pkcs7Der.withUnsafeBytes { (ptr) in
            BIO_write(inf, ptr.baseAddress?.assumingMemoryBound(to: Int8.self), Int32(pkcs7Der.count))
        }
        guard let out = BIO_new(BIO_s_mem()) else { throw PassiveAuthenticationError.UnableToGetX509CertificateFromPKCS7("Unable to allocate output buffer") }
        defer { BIO_free(out) }

        guard let p7 = d2i_PKCS7_bio(inf, nil) else { throw PassiveAuthenticationError.UnableToGetX509CertificateFromPKCS7("Unable to read PKCS7 DER data") }
        defer { PKCS7_free(p7) }
        
        var certs : UnsafeMutablePointer<stack_st_X509>? = nil
        let i = OBJ_obj2nid(p7.pointee.type);
        switch (i) {
        case NID_pkcs7_signed:
            if let sign = p7.pointee.d.sign {
                certs = sign.pointee.cert
            }
            break;
        case NID_pkcs7_signedAndEnveloped:
            if let signed_and_enveloped = p7.pointee.d.signed_and_enveloped {
                certs = signed_and_enveloped.pointee.cert
            }
            break;
        default:
            break;
        }
        
        if let certs = certs  {
            let certCount = certs.pointee.stack.num
            let _ = certs.withMemoryRebound(to: stack_st.self, capacity: Int(certCount), { (st) in
                for i in 0 ..< certCount {
                    let x = sk_value(st, i).assumingMemoryBound(to: X509.self)
                    PEM_write_bio_X509(out, x);
                    BIO_puts(out, "\n");
                }
            })
        }
            
        let len = BIO_ctrl(out, BIO_CTRL_PENDING, 0, nil)// BIO_pending(bio);
        var buffer = [CChar](repeating: 0, count: len)
        BIO_read(out, &buffer, Int32(buffer.count))
        let ret = String(cString: buffer)

        return ret
    }
    
    /// Checks whether a trust chain can be built up to verify a X509 certificate. A CAFile containing a list of trusted certificates (each in PEM format)
    /// is used to build the trust chain.
    /// The trusted certificates in this use case are typically from a Countries master list (see the scripts for form more informaton on how to prepare this)
    /// - Parameter x509Cert: The X509 certificate (in PEM format) to verify
    /// - Parameter CAFile: The URL path of a file containing the list of certificates used to try to discover and build a trust chain
    @available(iOS 13, *)
    func verifyX509Certificate( x509Cert : String, CAFile : URL ) throws {

        guard let cert_ctx = X509_STORE_new() else { throw PassiveAuthenticationError.UnableToVerifyX509CertificateForSOD("Unable to create certificate store") }
        defer { X509_STORE_free(cert_ctx) }

        X509_STORE_set_verify_cb(cert_ctx) { (ok, ctx) -> Int32 in
            print( "IN CALLBACK" )
            let cert_error = X509_STORE_CTX_get_error(ctx)
            
            if ok == 0 {
                let errVal = X509_verify_cert_error_string(Int(cert_error))
                let val = errVal!.withMemoryRebound(to: CChar.self, capacity: 1000) { (ptr) in
                    return String(cString: ptr)
                }
                
                print("error \(cert_error) at \(X509_STORE_CTX_get_error_depth(ctx)) depth lookup:\(val)" )
            }

            return ok;
        }

        guard let lookup = X509_STORE_add_lookup(cert_ctx, X509_LOOKUP_file()) else { throw PassiveAuthenticationError.UnableToVerifyX509CertificateForSOD("Unable to add lookup to store") }
        
        // Load masterList.pem file
        _ = X509_LOOKUP_ctrl(lookup, X509_L_FILE_LOAD, CAFile.path, Int(X509_FILETYPE_PEM), nil)

        // Load certificate
        guard let cert = BIO_new( BIO_s_mem()) else { throw PassiveAuthenticationError.UnableToVerifyX509CertificateForSOD("Unable to create buffer to load certificate data") }
        defer { BIO_free(cert) }
        let _ = x509Cert.withCString { (ptr) in
            BIO_write(cert, ptr, Int32(x509Cert.count))
        }
        let x = PEM_read_bio_X509_AUX(cert, nil, nil, nil )
        defer { X509_free(x) }
        

        let csc = X509_STORE_CTX_new()
        defer { X509_STORE_CTX_free(csc) }

        X509_STORE_set_flags(cert_ctx, 0);
        let rc = X509_STORE_CTX_init(csc, cert_ctx, x, nil)
        if rc == 0 {
            throw PassiveAuthenticationError.UnableToVerifyX509CertificateForSOD("Unable to initialise X509_STORE_CTX")
        }
        
        // discover and verify X509 certificte chain
        let i = X509_verify_cert(csc);
        if i != 1 {
            let err = X509_STORE_CTX_get_error(csc)
            throw PassiveAuthenticationError.UnableToVerifyX509CertificateForSOD("Verification of certificate failed - errorCode \(err)")
        }
    }

    /// Extracts the signed data section from a PCS7 container (if present)
    /// - Parameter pkcs7Der: The PKCS7 container in DER format
    func getSignedDataFromPKCS7( pkcs7Der : Data ) throws -> Data {
        // we're not verifying here - we just want to dump the signed content out

        guard let inf = BIO_new(BIO_s_mem()) else { throw PassiveAuthenticationError.UnableToGetSignedDataFromPKCS7("Unable to allocate input buffer") }
        defer { BIO_free(inf) }

        guard let out = BIO_new(BIO_s_mem()) else { throw PassiveAuthenticationError.UnableToGetSignedDataFromPKCS7("Unable to allocate output buffer") }
        defer { BIO_free(out) }

        let _ = pkcs7Der.withUnsafeBytes { (ptr) in
            BIO_write(inf, ptr.baseAddress?.assumingMemoryBound(to: UInt8.self), Int32(pkcs7Der.count))
        }
        let p7 = d2i_PKCS7_bio(inf, nil);

        let flags = PKCS7_NOVERIFY | PKCS7_NOSIGS
        if PKCS7_verify(p7, nil, nil, nil, out, flags) == 0 {
            throw PassiveAuthenticationError.UnableToGetSignedDataFromPKCS7("Verification of P7 failed - unable to get signature")
        }

        // print("Verification successful\n");
        let len = BIO_ctrl(out, BIO_CTRL_PENDING, 0, nil)// BIO_pending(bio);
        var buffer = [UInt8](repeating: 0, count: len)
        BIO_read(out, &buffer, Int32(buffer.count))
        let sigData = Data(buffer)

        return sigData
    }

    /// Parses a signed data structures encoded in ASN1 format and returns the structure in text format
    /// - Parameter data: The data to be parsed in ASN1 format
    private func ASN1Parse( data: Data ) throws -> String {
        guard let out = BIO_new(BIO_s_mem()) else { throw PassiveAuthenticationError.UnableToGetSignedDataFromPKCS7("Unable to allocate output buffer") }
        defer { BIO_free(out) }

        var parsed : String = ""
        let _ = try data.withUnsafeBytes { (ptr) in
            let rc = ASN1_parse_dump(out, ptr.baseAddress?.assumingMemoryBound(to: UInt8.self), data.count, 1, 0)
            if rc == 0 {
                throw PassiveAuthenticationError.UnableToGetSignedDataFromPKCS7("Failed to parse ASN1 Data")
            }
        
            let len = BIO_ctrl(out, BIO_CTRL_PENDING, 0, nil)// BIO_pending(bio);
            var buffer = [CChar](repeating: 0, count: len)
            BIO_read(out, &buffer, Int32(buffer.count))
            parsed = String(cString:buffer)
        }
    
        return parsed
    }
}
