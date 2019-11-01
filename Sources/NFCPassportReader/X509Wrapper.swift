//
//  X509Wrapper.swift
//  NFCPassportReader
//
//  Created by Andy Qua on 29/10/2019.
//

import OpenSSL

public enum CertificateType {
    case documentSigningCertificate
    case issuerSigningCertificate
}
        
public enum CertificateItem : String {
    case fingerprint = "Certificate fingerprint"
    case issuerName = "Issuer"
    case subjectName = "Subject"
    case serialNumber = "Serial number"
    case signatureAlgorithm = "Signature algorithm"
    case publicKeyAlgorithm = "Public key algorithm"
    case notBefore = "Valid from"
    case notAfter = "Valid to"
}

public class X509Wrapper {
    public let cert : UnsafeMutablePointer<X509>
    
    public init?( with cert: UnsafeMutablePointer<X509>? ) {
        guard let cert = cert else { return nil }
        
        self.cert = X509_dup(cert)
    }
    
    public func getItemsAsDict() -> [CertificateItem:String] {
        var item = [CertificateItem:String]()
        if let fingerprint = self.getFingerprint() {
            item[.fingerprint] = fingerprint
        }
        if let issuerName = self.getIssuerName() {
            item[.issuerName] = issuerName

        }
        if let subjectName = self.getSubjectName() {
            item[.subjectName] = subjectName
        }
        if let serialNr = self.getSerialNumber() {
            item[.serialNumber] = serialNr
        }
        if let signatureAlgorithm = self.getSignatureAlgorithm() {
            item[.signatureAlgorithm] = signatureAlgorithm
        }
        if let publicKeyAlgorithm = self.getPublicKeyAlgorithm() {
            item[.publicKeyAlgorithm] = publicKeyAlgorithm
        }
        if let notBefore = self.getNotBeforeDate() {
            item[.notBefore] = notBefore
        }
        if let notAfter = self.getNotAfterDate() {
            item[.notAfter] = notAfter
        }
        
        return item
    }
    public func certToPEM() -> String {
        return OpenSSLUtils.X509ToPEM( x509:cert )
    }
    
    public func getFingerprint( ) -> String? {
        let fdig = EVP_sha1();
        
        var n : UInt32 = 0
        let md = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(EVP_MAX_MD_SIZE))
        defer { md.deinitialize(count: Int(EVP_MAX_MD_SIZE)); md.deallocate() }

        X509_digest(cert, fdig, md, &n)
        let arr = UnsafeMutableBufferPointer(start: md, count: Int(n)).map({ binToHexRep($0) }).joined(separator: ":")
        return arr
    }
    
    public func getNotBeforeDate() -> String? {
        let notBefore = ASN1TimeToString( cert.pointee.cert_info.pointee.validity.pointee.notBefore )
        return notBefore

    }
    
    public func getNotAfterDate() -> String? {
        let notAfter = ASN1TimeToString( cert.pointee.cert_info.pointee.validity.pointee.notAfter )
        return notAfter
    }
    
    public func getSerialNumber() -> String? {
        let serialNr = String( ASN1_INTEGER_get(X509_get_serialNumber(cert)) )
        return serialNr
    }
    
    public func getSignatureAlgorithm() -> String? {
        let algo = getAlgorithm( cert.pointee.sig_alg.pointee.algorithm )
        return algo
    }
    
    public func getPublicKeyAlgorithm() -> String? {
        let algo = getAlgorithm( cert.pointee.cert_info.pointee.key?.pointee.algor.pointee.algorithm )
        return algo
    }
        
    public func getIssuerName() -> String? {
        return getName(for: X509_get_issuer_name(cert))
    }
    
    public func getSubjectName() -> String? {
        return getName(for: X509_get_subject_name(cert))
    }
    
    private func getName( for name: UnsafeMutablePointer<X509_NAME>? ) -> String? {
        guard let name = name else { return nil }
        
        var issuer: String = ""
        
        guard let out = BIO_new( BIO_s_mem()) else { return nil }
        defer { BIO_free(out) }

        X509_NAME_print_ex(out, name, 0, UInt(ASN1_STRFLGS_ESC_2253 |
                        ASN1_STRFLGS_ESC_CTRL |
                        ASN1_STRFLGS_ESC_MSB |
                        ASN1_STRFLGS_UTF8_CONVERT |
                        ASN1_STRFLGS_DUMP_UNKNOWN |
                        ASN1_STRFLGS_DUMP_DER | XN_FLAG_SEP_COMMA_PLUS |
                        XN_FLAG_DN_REV |
                        XN_FLAG_FN_SN |
                        XN_FLAG_DUMP_UNKNOWN_FIELDS))
        issuer = OpenSSLUtils.bioToString(bio: out)
        
        return issuer
    }

    private func getAlgorithm( _ algo:  UnsafeMutablePointer<ASN1_OBJECT>? ) -> String? {
        guard let algo = algo else { return nil }
        let len = OBJ_obj2nid(algo)
        var algoString : String? = nil
        if let sa = OBJ_nid2ln(len) {
            algoString = String(cString: sa )
        }
        return algoString
    }

    private func ASN1TimeToString( _ date: UnsafeMutablePointer<ASN1_TIME> ) -> String? {
        guard let b = BIO_new(BIO_s_mem()) else { return nil }
        defer { BIO_free(b) }

        ASN1_TIME_print(b, date)
        return OpenSSLUtils.bioToString(bio: b)
    }
    
}
