//
//  OpenSSLUtils.swift
//  NFCPassportReader
//
//  Created by Andy Qua on 29/10/2019.
//

import Foundation
import OpenSSL

public enum OpenSSLError: Error {
    case UnableToGetX509CertificateFromPKCS7(String)
    case UnableToVerifyX509CertificateForSOD(String)
    case UnableToGetSignedDataFromPKCS7(String)
    case UnableToReadECPublicKey(String)
    case UnableToExtractSignedDataFromPKCS7(String)
    case UnableToParseASN1(String)
}

extension OpenSSLError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .UnableToGetX509CertificateFromPKCS7(let reason):
            return NSLocalizedString("Unable to read the SOD PKCS7 Certificate. \(reason)", comment: "UnableToGetPKCS7CertificateForSOD")
        case .UnableToVerifyX509CertificateForSOD(let reason):
            return NSLocalizedString("Unable to verify the SOD X509 certificate. \(reason)", comment: "UnableToVerifyX509CertificateForSOD")
        case .UnableToGetSignedDataFromPKCS7(let reason):
            return NSLocalizedString("Unable to parse the SOD Datagroup hashes. \(reason)", comment: "UnableToGetSignedDataFromPKCS7")
        case .UnableToReadECPublicKey(let reason):
            return NSLocalizedString("Unable to read ECDSA Public key  \(reason)!", comment: "UnableToReadECPublicKey")
        case .UnableToExtractSignedDataFromPKCS7(let reason):
            return NSLocalizedString("Unable to extract Signer data from PKCS7  \(reason)!", comment: "UnableToExtractSignedDataFromPKCS7")
        case .UnableToParseASN1(let reason):
            return NSLocalizedString("DatUnable to parse ANS1  \(reason)!", comment: "UnableToParseASN1")
        }
    }
}

class OpenSSLUtils {
    
    /// Initialised the OpenSSL Library
    /// Must be called prior to calling any OpenSSL functions
    static func loadOpenSSL() {
        OPENSSL_add_all_algorithms_noconf();
        ERR_load_crypto_strings();
        SSL_load_error_strings();
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
    /// - Throws: A OpenSSLError.UnableToGetX509CertificateFromPKCS7 are thrown for any error
    static func getX509CertificatesFromPKCS7( pkcs7Der : Data ) throws -> [X509Wrapper] {
        
        guard let inf = BIO_new(BIO_s_mem()) else { throw OpenSSLError.UnableToGetX509CertificateFromPKCS7("Unable to allocate input buffer") }
        defer { BIO_free(inf) }
        let _ = pkcs7Der.withUnsafeBytes { (ptr) in
            BIO_write(inf, ptr.baseAddress?.assumingMemoryBound(to: Int8.self), Int32(pkcs7Der.count))
        }
        guard let p7 = d2i_PKCS7_bio(inf, nil) else { throw OpenSSLError.UnableToGetX509CertificateFromPKCS7("Unable to read PKCS7 DER data") }
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
    /// The trusted certificates in this use case are typically from a Countries master list (see the scripts for  more informaton on how to prepare this)
    /// - Parameter x509Cert: The X509 certificate (in PEM format) to verify
    /// - Parameter CAFile: The URL path of a file containing the list of certificates used to try to discover and build a trust chain
    /// - Returns: either the X509 issue signing certificate that was used to sign the passed in X509 certificate or an error
    @available(iOS 13, *)
    static func verifyTrustAndGetIssuerCertificate( x509 : X509Wrapper, CAFile : URL ) -> Result<X509Wrapper, OpenSSLError> {

        guard let cert_ctx = X509_STORE_new() else { return .failure(OpenSSLError.UnableToVerifyX509CertificateForSOD("Unable to create certificate store")) }
        defer { X509_STORE_free(cert_ctx) }

        X509_STORE_set_verify_cb(cert_ctx) { (ok, ctx) -> Int32 in
            Log.debug( "IN CALLBACK" )
            let cert_error = X509_STORE_CTX_get_error(ctx)
            
            if ok == 0 {
                let errVal = X509_verify_cert_error_string(Int(cert_error))
                let val = errVal!.withMemoryRebound(to: CChar.self, capacity: 1000) { (ptr) in
                    return String(cString: ptr)
                }
                
                Log.error("error \(cert_error) at \(X509_STORE_CTX_get_error_depth(ctx)) depth lookup:\(val)" )
            }

            return ok;
        }

        guard let lookup = X509_STORE_add_lookup(cert_ctx, X509_LOOKUP_file()) else { return .failure(OpenSSLError.UnableToVerifyX509CertificateForSOD("Unable to add lookup to store")) }
        
        // Load masterList.pem file
        var rc = X509_LOOKUP_ctrl(lookup, X509_L_FILE_LOAD, CAFile.path, Int(X509_FILETYPE_PEM), nil)

        guard let store = X509_STORE_CTX_new() else {
            return .failure(OpenSSLError.UnableToVerifyX509CertificateForSOD("Unable to create new X509_STORE_CTX"))
        }
        defer { X509_STORE_CTX_free(store) }

        X509_STORE_set_flags(cert_ctx, 0);
        rc = X509_STORE_CTX_init(store, cert_ctx, x509.cert, nil)
        if rc == 0 {
            return .failure(OpenSSLError.UnableToVerifyX509CertificateForSOD("Unable to initialise X509_STORE_CTX"))
        }
        
        // discover and verify X509 certificte chain
        let i = X509_verify_cert(store);
        if i != 1 {
            let err = X509_STORE_CTX_get_error(store)
            
            return .failure(OpenSSLError.UnableToVerifyX509CertificateForSOD("Verification of certificate failed - errorCode \(err)"))
        }
        
        if let certWrapper = X509Wrapper(with: store.pointee.current_issuer)  {
            return .success( certWrapper )
        }
        return .failure(OpenSSLError.UnableToVerifyX509CertificateForSOD("Unable to get issuer certificate - not found"))
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

        guard let inf = BIO_new(BIO_s_mem()) else { throw OpenSSLError.UnableToGetSignedDataFromPKCS7("Unable to allocate input buffer") }
        defer { BIO_free(inf) }

        guard let out = BIO_new(BIO_s_mem()) else { throw OpenSSLError.UnableToGetSignedDataFromPKCS7("Unable to allocate output buffer") }
        defer { BIO_free(out) }

        let _ = pkcs7Der.withUnsafeBytes { (ptr) in
            BIO_write(inf, ptr.baseAddress?.assumingMemoryBound(to: UInt8.self), Int32(pkcs7Der.count))
        }
        guard let cms = d2i_CMS_bio(inf, nil) else {
            throw OpenSSLError.UnableToGetSignedDataFromPKCS7("Verification of P7 failed - unable to create CMS")
        }
        defer { CMS_ContentInfo_free(cms) }

        let flags : UInt32 = UInt32(CMS_NO_SIGNER_CERT_VERIFY)

        if CMS_verify(cms, nil, nil, nil, out, flags) == 0 {
            throw OpenSSLError.UnableToGetSignedDataFromPKCS7("Verification of P7 failed - unable to verify signature")
        }

        // print("Verification successful\n");
        let len = BIO_ctrl(out, BIO_CTRL_PENDING, 0, nil)
        var buffer = [UInt8](repeating: 0, count: len)
        BIO_read(out, &buffer, Int32(len))
        let sigData = Data(buffer)

        return sigData
    }

    /// Extracts the signed data section from a PKCS7 container (if present) but does NO verification., Just dumps the data
    /// - Parameter pkcs7Der: The PKCS7 container in DER format
    /// - Returns: The signed data from a PKCS7 container if we could read it
    static func extractSignedDataNoVerificationFromPKCS7(pkcs7Der : Data ) throws -> Data {
        // Dump ASN1 structre
        let asn1 = try ASN1Parse(data: pkcs7Der)
        
        // Grab first OCTET value
        var sigData : Data?
        let lines = asn1.components(separatedBy: "\n")
        for line in lines {
            if line.contains( "OCTET STRING" ) {
                if let range = line.range(of: "[HEX DUMP]:") {
                    let val = String(line[range.upperBound..<line.endIndex])
                    sigData = Data(hexRepToBin( val ))
                    break
                }
            }
        }
        
        guard let ret = sigData else { throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("noDataReturned") }

        return ret
    }

    /// Parses a signed data structures encoded in ASN1 format and returns the structure in text format
    /// - Parameter data: The data to be parsed in ASN1 format
    /// - Returns: The parsed data as A String
    static func ASN1Parse( data: Data ) throws -> String {
        guard let out = BIO_new(BIO_s_mem()) else { throw OpenSSLError.UnableToParseASN1("Unable to allocate output buffer") }
        defer { BIO_free(out) }

        var parsed : String = ""
        let _ = try data.withUnsafeBytes { (ptr) in
            let rc = ASN1_parse_dump(out, ptr.baseAddress?.assumingMemoryBound(to: UInt8.self), data.count, 1, 0)
            if rc == 0 {
                throw OpenSSLError.UnableToParseASN1("Failed to parse ASN1 Data")
            }
        
            parsed = bioToString(bio: out)
        }
    
        return parsed
    }
    
    /// Reads an ECDSA Public Key  in DER  format and converts it to an OpenSSL EVP_PKEY value for use whilst verifying a ECDSA signature
    /// - Parameter data: The ECDSA key in DER forma
    /// - Returns: The EVP_PKEY value
    /// NOTE THE CALLER IS RESPONSIBLE FOR FREEING THE RETURNED KEY USING
    /// EVP_PKEY_free(pemKey);
    static func readECPublicKey( data : [UInt8] ) throws -> UnsafeMutablePointer<EVP_PKEY>? {
        guard let inf = BIO_new(BIO_s_mem()) else { throw OpenSSLError.UnableToReadECPublicKey("Unable to allocate output buffer") }
        defer { BIO_free(inf) }

        let _ = data.withUnsafeBytes { (ptr) in
            BIO_write(inf, ptr.baseAddress?.assumingMemoryBound(to: UInt8.self), Int32(data.count))
        }
        
        guard let eckey = d2i_EC_PUBKEY_bio(inf, nil) else { throw OpenSSLError.UnableToReadECPublicKey("Failed to load") }
        defer{ EC_KEY_free(eckey) }

        guard let outf = BIO_new(BIO_s_mem()) else { throw OpenSSLError.UnableToReadECPublicKey("Unable to allocate output buffer") }
        defer { BIO_free(outf) }
        let _ = PEM_write_bio_EC_PUBKEY(outf, eckey);
        let pemKey = PEM_read_bio_PUBKEY(outf, nil, nil, nil)
        
        return pemKey
    }
    
    /// Verifies aa data valid against an ECDSA signature and ECDSA Public Key - used in Active Authentication
    /// - Parameter publicKey: The OpenSSL EVP_PKEY ECDSA key
    /// - Parameter signature: The ECDSA signature to verify
    /// - Parameter data: The data used to generate the signature
    /// - Returns: True if the signature was verified
    static func verifyECDSASignature( publicKey:UnsafeMutablePointer<EVP_PKEY>, signature: [UInt8], data: [UInt8] ) -> Bool {
        // We first need to convert the signature from PLAIN ECDSA to ASN1 DER encoded
        let ecsig = ECDSA_SIG_new()
        defer { ECDSA_SIG_free(ecsig) }
        var sigData = signature
        BN_bin2bn(&sigData, 32, ecsig?.pointee.r)
        BN_bin2bn(&sigData + 32, 32, ecsig?.pointee.s)
        
        let sigSize = i2d_ECDSA_SIG(ecsig, nil)
        var derBytes = [UInt8](repeating: 0, count: Int(sigSize))
        var derEncodedSignature: UnsafeMutablePointer<UInt8>? = UnsafeMutablePointer<UInt8>(mutating:&derBytes)
        let _ = i2d_ECDSA_SIG(ecsig, &derEncodedSignature)

        var nRes : Int32 = -1
        // check if ECDSA signature and then verify
        let type = EVP_PKEY_base_id(publicKey);
        if (type == EVP_PKEY_EC)
        {
            var ctx : UnsafeMutablePointer<EVP_MD_CTX>?
            let bmd = BIO_new(BIO_f_md());
            defer{ BIO_free(bmd)}

            if BIO_ctrl( bmd, BIO_C_GET_MD_CTX, 0, &ctx) != 1 {
                Log.error( "ERROR GETTING CONTEXT" )
            }
            
            let pctx : UnsafeMutablePointer<OpaquePointer?>? = nil
            nRes = EVP_DigestVerifyInit(ctx!, pctx, nil, nil, publicKey);
            if (1 != nRes)
            {
                return false;
            }
            
/*
            var tctx : UnsafeMutablePointer<EVP_MD_CTX>?
            BIO_ctrl( bmd, BIO_C_GET_MD_CTX, 0, &tctx)
            let md = EVP_MD_CTX_md(tctx);
            let md_name = OBJ_nid2sn(EVP_MD_type(md));
*/
            nRes = EVP_DigestUpdate(ctx, data, data.count);
            if (1 != nRes)
            {
                //let err = ERR_get_error()
                EVP_MD_CTX_cleanup(ctx);
                return false;
            }

            nRes = EVP_DigestVerifyFinal(ctx, derBytes, derBytes.count);
            EVP_MD_CTX_cleanup(ctx);
            if (nRes < 0) {
                return false;
            } else if (nRes == 0) {
                return false;
            }
        }
        else {
            return false;
        }

        return nRes == 1
    }
}
