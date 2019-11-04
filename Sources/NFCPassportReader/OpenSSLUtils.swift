//
//  OpenSSLUtils.swift
//  NFCPassportReader
//
//  Created by Andy Qua on 29/10/2019.
//

import Foundation
import OpenSSL


class OpenSSLUtils {
    
    /// Initialised the OpenSSL Library
    /// Must be called prior to calling any OpenSSL functions
    static func loadOpenSSL() {
        OPENSSL_add_all_algorithms_noconf()
    }
    
    /// Cleans up the OpenSSL library
    static func cleanupOpenSSL() {
        CONF_modules_unload(1)
        OBJ_cleanup();
        EVP_cleanup();
        CRYPTO_cleanup_all_ex_data()
        ERR_remove_thread_state(nil)
        RAND_cleanup()
        ERR_free_strings()
    }
    
    static func X509ToPEM( x509: UnsafeMutablePointer<X509> ) -> String {
        let out = BIO_new(BIO_s_mem())!
        defer { BIO_free( out) }

        PEM_write_bio_X509(out, x509);
        let str = OpenSSLUtils.bioToString( bio:out )

        return str
    }

    static func pkcs7DataToPEM( pkcs7: Data ) -> String {
        let inf = BIO_new(BIO_s_mem())!
        defer { BIO_free( inf) }
        let out = BIO_new(BIO_s_mem())!
        defer { BIO_free( out) }

        let _ = pkcs7.withUnsafeBytes { (ptr) in
            BIO_write(inf, ptr.baseAddress?.assumingMemoryBound(to: Int8.self), Int32(pkcs7.count))
        }
        guard let p7 = d2i_PKCS7_bio(inf, nil) else { return "" }
        defer { PKCS7_free(p7) }

        PEM_write_bio_PKCS7(out, p7)
        let str = OpenSSLUtils.bioToString( bio:out )
        return str
    }


    /// Extracts a X509 certificate in PEM format from a PKCS7 container
    /// - Parameter pkcs7Der: The PKCS7 container in DER format
    /// - Returns: The PEM formatted X509 certificate
    /// - Throws: A PassiveAuthenticationError.UnableToGetX509CertificateFromPKCS7 are thrown for any error
    static func getX509CertificatesFromPKCS7( pkcs7Der : Data ) throws -> [X509Wrapper] {
        
        guard let inf = BIO_new(BIO_s_mem()) else { throw PassiveAuthenticationError.UnableToGetX509CertificateFromPKCS7("Unable to allocate input buffer") }
        defer { BIO_free(inf) }
        let _ = pkcs7Der.withUnsafeBytes { (ptr) in
            BIO_write(inf, ptr.baseAddress?.assumingMemoryBound(to: Int8.self), Int32(pkcs7Der.count))
        }
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
        
        var ret = [X509Wrapper]()
        if let certs = certs  {
            let certCount = certs.pointee.stack.num
            let _ = certs.withMemoryRebound(to: stack_st.self, capacity: Int(certCount), { (st) in
                for i in 0 ..< certCount {
                    let x = sk_value(st, i).assumingMemoryBound(to: X509.self)
                    if let x509 = X509Wrapper(with:x) {
                        ret.append( x509 )
                    }
                }
            })
        }
            
        return ret
    }
    
    /// Checks whether a trust chain can be built up to verify a X509 certificate. A CAFile containing a list of trusted certificates (each in PEM format)
    /// is used to build the trust chain.
    /// The trusted certificates in this use case are typically from a Countries master list (see the scripts for form more informaton on how to prepare this)
    /// - Parameter x509Cert: The X509 certificate (in PEM format) to verify
    /// - Parameter CAFile: The URL path of a file containing the list of certificates used to try to discover and build a trust chain
    /// - Parameter readCertificates: A dictionary containing the keys: documentSigningCert and issuerSigningCertificate with the readable contents
    @available(iOS 13, *)
    static func verifyTrustAndGetIssuerCertificate( x509 : X509Wrapper, CAFile : URL ) -> Result<X509Wrapper, PassiveAuthenticationError> {

        guard let cert_ctx = X509_STORE_new() else { return .failure(PassiveAuthenticationError.UnableToVerifyX509CertificateForSOD("Unable to create certificate store")) }
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

        guard let lookup = X509_STORE_add_lookup(cert_ctx, X509_LOOKUP_file()) else { return .failure(PassiveAuthenticationError.UnableToVerifyX509CertificateForSOD("Unable to add lookup to store")) }
        
        // Load masterList.pem file
        var rc = X509_LOOKUP_ctrl(lookup, X509_L_FILE_LOAD, CAFile.path, Int(X509_FILETYPE_PEM), nil)

        guard let store = X509_STORE_CTX_new() else {
            return .failure(PassiveAuthenticationError.UnableToVerifyX509CertificateForSOD("Unable to create new X509_STORE_CTX"))
        }
        defer { X509_STORE_CTX_free(store) }

        X509_STORE_set_flags(cert_ctx, 0);
        rc = X509_STORE_CTX_init(store, cert_ctx, x509.cert, nil)
        if rc == 0 {
            return .failure(PassiveAuthenticationError.UnableToVerifyX509CertificateForSOD("Unable to initialise X509_STORE_CTX"))
        }
        
        // discover and verify X509 certificte chain
        let i = X509_verify_cert(store);
        if i != 1 {
            let err = X509_STORE_CTX_get_error(store)
            
            return .failure(PassiveAuthenticationError.UnableToVerifyX509CertificateForSOD("Verification of certificate failed - errorCode \(err)"))
        }
        
        if let certWrapper = X509Wrapper(with: store.pointee.current_issuer)  {
            return .success( certWrapper )
        }
        return .failure(PassiveAuthenticationError.UnableToVerifyX509CertificateForSOD("Unable to get issuer certificate - not found"))
    }
    
    
    /// Extracts the contents of a BIO object and returns it as a String
    /// - Parameter bio: a Pointer to a BIO buffer
    /// - Returns: A string containing the contents of the BIO buffer
    static func bioToString( bio : UnsafeMutablePointer<BIO> ) -> String {
        let len = BIO_ctrl(bio, BIO_CTRL_PENDING, 0, nil)
        var buffer = [CChar](repeating: 0, count: len+1)
        BIO_read(bio, &buffer, Int32(len))
        
        // Ensure last value is 0 (null terminated) otherwise we get buffer overflow!
        buffer[len] = 0
        let ret = String(cString:buffer)
        return ret

    }
    
    /// Verifies the signed data section against the stored certificate and extracts the signed data section from a PKCS7 container (if present and valid)
    /// - Parameter pkcs7Der: The PKCS7 container in DER format
    /// - Returns: The signed data from a PKCS7 container if we could read it
    static func verifyAndGetSignedDataFromPKCS7( pkcs7Der : Data ) throws -> Data {

        guard let inf = BIO_new(BIO_s_mem()) else { throw PassiveAuthenticationError.UnableToGetSignedDataFromPKCS7("Unable to allocate input buffer") }
        defer { BIO_free(inf) }

        guard let out = BIO_new(BIO_s_mem()) else { throw PassiveAuthenticationError.UnableToGetSignedDataFromPKCS7("Unable to allocate output buffer") }
        defer { BIO_free(out) }

        let _ = pkcs7Der.withUnsafeBytes { (ptr) in
            BIO_write(inf, ptr.baseAddress?.assumingMemoryBound(to: UInt8.self), Int32(pkcs7Der.count))
        }
        guard let cms = d2i_CMS_bio(inf, nil) else {
            throw PassiveAuthenticationError.UnableToGetSignedDataFromPKCS7("Verification of P7 failed - unable to create CMS")
        }
        defer { CMS_ContentInfo_free(cms) }

        let flags : UInt32 = UInt32(CMS_NO_SIGNER_CERT_VERIFY)

        if CMS_verify(cms, nil, nil, nil, out, flags) == 0 {
            throw PassiveAuthenticationError.UnableToGetSignedDataFromPKCS7("Verification of P7 failed - unable to verify signature")
        }

        // print("Verification successful\n");
        let len = BIO_ctrl(out, BIO_CTRL_PENDING, 0, nil)
        var buffer = [UInt8](repeating: 0, count: len)
        BIO_read(out, &buffer, Int32(len))
        let sigData = Data(buffer)

        return sigData
    }
    
    /// Extracts the signed data section from a PKCS7 container (if present)
    /// - Parameter pkcs7Der: The PKCS7 container in DER format
    /// - Returns: The signed data from a PKCS7 container if we could read it
    static func getSignedDataFromPKCS72( pkcs7Der : Data ) throws -> Data {
        // NOTE we're not verifying here - we just want to dump the signed content out
        
        // I need to figure out how/why to verify the signed data against the Document signing certificate (I think?)

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
        let len = BIO_ctrl(out, BIO_CTRL_PENDING, 0, nil)
        var buffer = [UInt8](repeating: 0, count: len)
        BIO_read(out, &buffer, Int32(len))
        let sigData = Data(buffer)

        return sigData
    }
    

    /// Parses a signed data structures encoded in ASN1 format and returns the structure in text format
    /// - Parameter data: The data to be parsed in ASN1 format
    /// - Returns: The parsed data as A String
    static func ASN1Parse( data: Data ) throws -> String {
        guard let out = BIO_new(BIO_s_mem()) else { throw PassiveAuthenticationError.UnableToGetSignedDataFromPKCS7("Unable to allocate output buffer") }
        defer { BIO_free(out) }

        var parsed : String = ""
        let _ = try data.withUnsafeBytes { (ptr) in
            let rc = ASN1_parse_dump(out, ptr.baseAddress?.assumingMemoryBound(to: UInt8.self), data.count, 1, 0)
            if rc == 0 {
                throw PassiveAuthenticationError.UnableToGetSignedDataFromPKCS7("Failed to parse ASN1 Data")
            }
        
            parsed = bioToString(bio: out)
        }
    
        return parsed
    }
}
