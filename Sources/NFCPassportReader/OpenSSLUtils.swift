//
//  OpenSSLUtils.swift
//  NFCPassportReader
//
//  Created by Andy Qua on 29/10/2019.
//

import Foundation
import OpenSSL

@available(iOS 13, *)
public enum OpenSSLError: Error {
    case UnableToGetX509CertificateFromPKCS7(String)
    case UnableToVerifyX509CertificateForSOD(String)
    case UnableToGetSignedDataFromPKCS7(String)
    case UnableToReadECPublicKey(String)
    case UnableToExtractSignedDataFromPKCS7(String)
    case UnableToParseASN1(String)
    case UnableToDecryptRSASignature(String)
}

@available(iOS 13, *)
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
            case .UnableToDecryptRSASignature(let reason):
                return NSLocalizedString("DatUnable to decrypt RSA Signature \(reason)!", comment: "UnableToDecryptRSSignature")
        }
    }
}

@available(iOS 13, *)
public class OpenSSLUtils {
    
    private static var loaded = false
    
    /// Initialised the OpenSSL Library
    /// Must be called prior to calling any OpenSSL functions
    public static func loadOpenSSL() {
        OPENSSL_add_all_algorithms_noconf()
        ERR_load_crypto_strings()
        SSL_load_error_strings()
        
        loaded = true
    }
    
    /// Cleans up the OpenSSL library
    public static func cleanupOpenSSL() {
        CONF_modules_unload(1)
        OBJ_cleanup()
        EVP_cleanup()
        CRYPTO_cleanup_all_ex_data()
        ERR_remove_thread_state(nil)
        RAND_cleanup()
        ERR_free_strings()
        
        loaded = false
    }
    
    /// Returns any OpenSSL Error as a String
    static func getOpenSSLError() -> String {
        loadOpenSSL()
        
        guard let out = BIO_new(BIO_s_mem()) else { return "Unknown" }
        defer { BIO_free(out) }
        
        ERR_print_errors( out )
        let str = OpenSSLUtils.bioToString( bio:out )
        
        return str
    }

    static func X509ToPEM( x509: UnsafeMutablePointer<X509> ) -> String {
        if ( !loaded ) {
            loadOpenSSL()
        }
        let out = BIO_new(BIO_s_mem())!
        defer { BIO_free( out) }

        PEM_write_bio_X509(out, x509);
        let str = OpenSSLUtils.bioToString( bio:out )

        return str
    }

    static func pkcs7DataToPEM( pkcs7: Data ) -> String {
        if ( !loaded ) {
            loadOpenSSL()
        }
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
        if ( !loaded ) {
            loadOpenSSL()
        }

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
    static func verifyTrustAndGetIssuerCertificate( x509 : X509Wrapper, CAFile : URL ) -> Result<X509Wrapper, OpenSSLError> {
        if ( !loaded ) {
            loadOpenSSL()
        }

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
        if ( !loaded ) {
            loadOpenSSL()
        }
        
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
    ///
    /// - Note: To test from the command line using openssl (NOTE NOT THE default mac version as it doesn't currently support CMS):
    ///      extract the SOD Base64 from an exported passport (you will need to unescape slashes!) - save this to ppt.b64
    ///      convert to binary (cat ppt.b64 | base64 -D > ppt.bin
    ///      extract the der file from the SOD (which includes header) - tail -c+5 ppt.bin > aq.der (blindy discards header)
    ///      convert der to PEM - openssl pkcs7 -in ppt.der --inform der -out ppt.pem -outform pem
    ///      verify signature data against included document signing cert - openssl cms -verify -in ppt.pem -inform pem -noverify
    ///           the -noverify is don't verify against the signers certifcate (as we don' thave that!)
    ///
    ///      This should return Verification Successful and the signed data
    static func verifyAndReturnSODEncapsulatedDataUsingCMS( sod : SOD ) throws -> Data {
        if ( !loaded ) {
            loadOpenSSL()
        }        
        
        guard let inf = BIO_new(BIO_s_mem()) else { throw OpenSSLError.UnableToGetSignedDataFromPKCS7("Unable to allocate input buffer") }
        defer { BIO_free(inf) }

        guard let out = BIO_new(BIO_s_mem()) else { throw OpenSSLError.UnableToGetSignedDataFromPKCS7("Unable to allocate output buffer") }
        defer { BIO_free(out) }

        let _ = sod.body.withUnsafeBytes { (ptr) in
            BIO_write(inf, ptr.baseAddress?.assumingMemoryBound(to: UInt8.self), Int32(sod.body.count))
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
    
    
    static func verifyAndReturnSODEncapsulatedData( sod : SOD ) throws -> Data {
        if ( !loaded ) {
            loadOpenSSL()
        }

        let encapsulatedContent = try sod.getEncapsulatedContent()
        let signedAttribsHashAlgo = try sod.getEncapsulatedContentDigestAlgorithm()
        let signedAttributes = try sod.getSignedAttributes()
        let messageDigest = try sod.getMessageDigest()
        let signature = try sod.getSignature()
        let sigType = try sod.getSignatureAlgorithm()

        let pubKey = try sod.getPublicKey()

        var mdHash : Data
        if signedAttribsHashAlgo == "sha1" {
            mdHash = Data(calcSHA1Hash( [UInt8](encapsulatedContent) ))
        } else if signedAttribsHashAlgo == "sha256" {
            mdHash = Data(calcSHA256Hash( [UInt8](encapsulatedContent) ))
        } else if signedAttribsHashAlgo == "sha512" {
            mdHash = Data(calcSHA512Hash( [UInt8](encapsulatedContent) ))
        } else {
            throw OpenSSLError.UnableToGetSignedDataFromPKCS7("Unsupported hash algorithm - \(signedAttribsHashAlgo)")
        }
        
        // Make sure that hash equals the messageDigest
        if messageDigest != mdHash {
            // Invalid - signed data hash doesn't match message digest hash
            throw OpenSSLError.UnableToGetSignedDataFromPKCS7("messageDigest Hash doesn't hatch that of the signed attributes")
        }
        
        // Verify signed attributes
        try verifySignedAttributes( signedAttributes: signedAttributes, signature: signature, pubKey: pubKey, signatureType: sigType )

         return encapsulatedContent
    }
    
    /// This code is taken pretty much from pkeyutl.c - to verify a signature with a public key extract
    static func verifySignedAttributes( signedAttributes : Data, signature : Data, pubKey : UnsafeMutablePointer<EVP_PKEY>, signatureType: String ) throws {
        if ( !loaded ) {
            loadOpenSSL()
        }

        // Create EVP_PKEY_CTX
        guard let ctx = EVP_PKEY_CTX_new(pubKey, nil) else {
            throw OpenSSLError.UnableToGetSignedDataFromPKCS7("Failed to extract public key from pkcs7")
        }
        defer { EVP_PKEY_CTX_free(ctx) }
        
        var rv = EVP_PKEY_verify_init(ctx);
        if (rv <= 0) {
            throw OpenSSLError.UnableToGetSignedDataFromPKCS7("Failed to set verify mode")
        }

        // Set our options
        let opts : [String:String]
        let saHash : [UInt8]
        switch( signatureType ) {
            case "sha1WithRSAEncryption":
                opts = ["digest":"sha1" , "rsa_padding_mode":"pkcs1"]
                saHash = calcSHA1Hash(  [UInt8](signedAttributes) )
            case "sha512WithRSAEncryption":
                opts = ["digest":"sha512" , "rsa_padding_mode":"pkcs1"]
                saHash = calcSHA512Hash(  [UInt8](signedAttributes) )
            case "rsassaPss":
                opts = ["digest":"sha256" ,"rsa_padding_mode":"pss", "rsa_pss_saltlen":"-2"]
                saHash = calcSHA256Hash(  [UInt8](signedAttributes) )
            case "sha256WithRSAEncryption":
                fallthrough
            default:
                opts = ["digest":"sha256" , "rsa_padding_mode":"pkcs1"]
                saHash = calcSHA256Hash(  [UInt8](signedAttributes) )
        }

        for (key,val) in opts {
            if EVP_PKEY_CTX_ctrl_str(ctx, key, val) <= 0 {
                throw OpenSSLError.UnableToGetSignedDataFromPKCS7("Error setting parameter")
            }
        }

        // Verify signature against hash
        let _ = signature.withUnsafeBytes { (sigPtr) in
            let _ = saHash.withUnsafeBytes{ (saHashPtr) in
                rv = EVP_PKEY_verify(ctx, sigPtr.baseAddress?.assumingMemoryBound(to: UInt8.self), signature.count,
                             saHashPtr.baseAddress?.assumingMemoryBound(to: UInt8.self), saHash.count);
            }
        }
        if rv != 1 {
            Log.info("Signature Verification Failure")
            throw OpenSSLError.UnableToGetSignedDataFromPKCS7("Signature Verification Failure")
        }
        
        Log.info( "Signature Verified Successfully");
    }


    

    /// Parses a signed data structures encoded in ASN1 format and returns the structure in text format
    /// - Parameter data: The data to be parsed in ASN1 format
    /// - Returns: The parsed data as A String
    static func ASN1Parse( data: Data ) throws -> String {
        if ( !loaded ) {
            loadOpenSSL()
        }

        guard let out = BIO_new(BIO_s_mem()) else { throw OpenSSLError.UnableToParseASN1("Unable to allocate output buffer") }
        defer { BIO_free(out) }
        
        
        var parsed : String = ""
        let _ = try data.withUnsafeBytes { (ptr) in
            let rc = ASN1_parse_dump(out, ptr.baseAddress?.assumingMemoryBound(to: UInt8.self), data.count, 0, 0)
            if rc == 0 {
                ERR_print_errors( out )
                let str = OpenSSLUtils.bioToString( bio:out )
                
                print( str )
                throw OpenSSLError.UnableToParseASN1("Failed to parse ASN1 Data")
            }
        
            parsed = bioToString(bio: out)
        }
    
        return parsed
    }

    
    
    /// Reads an RSA Public Key  in DER  format and converts it to an OpenSSL EVP_PKEY value for use whilst decrypting or verifying an RSA signature
    /// - Parameter data: The RSA key in DER format
    /// - Returns: The EVP_PKEY value
    /// NOTE THE CALLER IS RESPONSIBLE FOR FREEING THE RETURNED KEY USING
    /// EVP_PKEY_free(pemKey);
    static func readRSAPublicKey( data : [UInt8] ) throws -> UnsafeMutablePointer<EVP_PKEY>? {
        loadOpenSSL()
        
        guard let inf = BIO_new(BIO_s_mem()) else { throw OpenSSLError.UnableToReadECPublicKey("Unable to allocate output buffer") }
        defer { BIO_free(inf) }
        
        let _ = data.withUnsafeBytes { (ptr) in
            BIO_write(inf, ptr.baseAddress?.assumingMemoryBound(to: UInt8.self), Int32(data.count))
        }
        
        guard let rsakey = d2i_RSA_PUBKEY_bio(inf, nil) else { throw OpenSSLError.UnableToReadECPublicKey("Failed to load") }
        defer{ RSA_free(rsakey) }
        
        let key = EVP_PKEY_new()
        if EVP_PKEY_set1_RSA(key, rsakey) != 1 {
            EVP_PKEY_free(key)
            throw OpenSSLError.UnableToReadECPublicKey("Failed to load")
        }
        return key
    }
    
    /// This code is taken pretty much from rsautl.c - to decrypt a signature with a public key
    /// NOTE: Current no padding is used! - This seems to be the default for Active Authentication RSA signatures (guess)
    /// - Parameter signature: The RSA encrypted signature to decrypt
    /// - Parameter pubKey: The RSA Public Key
    /// - Returns: The decrypted signature data
    static func decryptRSASignature( signature : Data, pubKey : UnsafeMutablePointer<EVP_PKEY> ) throws -> [UInt8] {
        loadOpenSSL()
        
        let pad = RSA_NO_PADDING
        let rsa = EVP_PKEY_get1_RSA( pubKey )
        
        let keysize = RSA_size(rsa);
        var outputBuf = [UInt8](repeating: 0, count: Int(keysize))
        
        // Decrypt signature
        var outlen : Int32 = 0
        let _ = signature.withUnsafeBytes { (sigPtr) in
            let _ = outputBuf.withUnsafeMutableBytes { (outPtr) in
                outlen = RSA_public_decrypt(Int32(signature.count), sigPtr.baseAddress?.assumingMemoryBound(to: UInt8.self), outPtr.baseAddress?.assumingMemoryBound(to: UInt8.self), rsa, pad)
            }
        }
        
        if outlen == 0 {
            let error = OpenSSLUtils.getOpenSSLError()
            throw OpenSSLError.UnableToDecryptRSASignature( "RSA_public_decrypt failed - \(error)" )
        }
        
        return outputBuf
    }
    
    /// Reads an ECDSA Public Key  in DER  format and converts it to an OpenSSL EVP_PKEY value for use whilst verifying a ECDSA signature
    /// - Parameter data: The ECDSA key in DER forma
    /// - Returns: The EVP_PKEY value
    /// NOTE THE CALLER IS RESPONSIBLE FOR FREEING THE RETURNED KEY USING
    /// EVP_PKEY_free(pemKey);
    static func readECPublicKey( data : [UInt8] ) throws -> UnsafeMutablePointer<EVP_PKEY>? {
        if ( !loaded ) {
            loadOpenSSL()
        }

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
    
    
    /// Verifies Active Authentication data valid against an ECDSA signature and ECDSA Public Key - used in Active Authentication
    /// - Parameter publicKey: The OpenSSL EVP_PKEY ECDSA key
    /// - Parameter signature: The ECDSA signature to verify
    /// - Parameter data: The data used to generate the signature
    /// - Returns: True if the signature was verified
    static func verifyECDSASignature( publicKey:UnsafeMutablePointer<EVP_PKEY>, signature: [UInt8], data: [UInt8] ) -> Bool {
        if ( !loaded ) {
            loadOpenSSL()
        }

        // We first need to convert the signature from PLAIN ECDSA to ASN1 DER encoded
        let ecsig = ECDSA_SIG_new()
        defer { ECDSA_SIG_free(ecsig) }
        let sigData = signature
        sigData.withUnsafeBufferPointer { (unsafeBufPtr) in
            let unsafePointer = unsafeBufPtr.baseAddress!
            BN_bin2bn(unsafePointer, 32, ecsig?.pointee.r)
            BN_bin2bn(unsafePointer + 32, 32, ecsig?.pointee.s)
        }
        let sigSize = i2d_ECDSA_SIG(ecsig, nil)
        var derBytes = [UInt8](repeating: 0, count: Int(sigSize))
        derBytes.withUnsafeMutableBufferPointer { (unsafeBufPtr) in
            var unsafePointer = unsafeBufPtr.baseAddress
            let _ = i2d_ECDSA_SIG(ecsig, &unsafePointer)
        }
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
