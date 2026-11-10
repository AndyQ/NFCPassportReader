//
//  PassiveAuthenticationTests.swift
//  NFCPassportReaderTests
//
//  SOD signature verification (RFC 5652 5.4 / ICAO 9303-10 4.6.2) and the DSC -> CSCA chain against a master list
//  (ICAO 9303-12), with SODs and certificates built here with OpenSSL.
//

import XCTest
import OpenSSL

@testable import NFCPassportReader

final class PassiveAuthenticationTests: XCTestCase {

    private static let rsaKey = generateKey(EVP_PKEY_RSA)
    private static let ecKey = generateKey(EVP_PKEY_EC)

    /// LDSSecurityObject-shaped content: version, SHA-256, one DataGroupHash
    private let content: [UInt8] = {
        let sha256 = tlv(0x30, [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01])
        let dgHash = tlv(0x30, [0x02, 0x01, 0x01] + tlv(0x04, [UInt8](repeating: 0xAB, count: 32)))
        return tlv(0x30, [0x02, 0x01, 0x00] + sha256 + tlv(0x30, dgHash))
    }()

    // MARK: - SOD signature

    /// The signature algorithms seen on documents. OpenSSL labels a PKCS#1 v1.5 CMS signature rsaEncryption, so its
    /// hash has to come from the SignerInfo's digestAlgorithm; RSASSA-PSS takes it from the PSS parameters.
    func testSODSignatureVerifiesForEachAlgorithm() throws {
        let cases: [(String, OpaquePointer, OpaquePointer?, Bool)] = [
            ("RSA PKCS#1 SHA-256", Self.rsaKey, EVP_sha256(), false),
            ("RSA PKCS#1 SHA-512", Self.rsaKey, EVP_sha512(), false),
            ("RSA-PSS SHA-256", Self.rsaKey, EVP_sha256(), true),
            ("RSA-PSS SHA-384", Self.rsaKey, EVP_sha384(), true),
            ("RSA-PSS SHA-512", Self.rsaKey, EVP_sha512(), true),
            ("ECDSA SHA-256", Self.ecKey, EVP_sha256(), false),
            ("ECDSA SHA-512", Self.ecKey, EVP_sha512(), false),
        ]
        for (label, key, digest, pss) in cases {
            let dsc = Self.makeCertificate(subject: "DSC", key: key, issuer: "DSC", issuerKey: key, ca: false)
            defer { X509_free(dsc) }
            let sod = try Self.makeSOD(content: content, signer: dsc, key: key, digest: digest, pss: pss)
            let algorithm = try sod.getSignatureAlgorithm()
            XCTAssertEqual([UInt8](try OpenSSLUtils.verifyAndReturnSODEncapsulatedData(sod: sod)), content, "\(label): \(algorithm)")
            XCTAssertEqual([UInt8](try OpenSSLUtils.verifyAndReturnSODEncapsulatedDataUsingCMS(sod: sod)), content, "\(label) (CMS)")
        }
    }

    func testPSSParametersAreRead() throws {
        let dsc = Self.makeCertificate(subject: "DSC", key: Self.rsaKey, issuer: "DSC", issuerKey: Self.rsaKey, ca: false)
        defer { X509_free(dsc) }
        let sod = try Self.makeSOD(content: content, signer: dsc, key: Self.rsaKey, digest: EVP_sha512(), pss: true)
        XCTAssertEqual(try sod.getSignatureAlgorithm(), "rsassaPss")
        XCTAssertEqual(sod.getPSSParameters().hash, "sha512")
        XCTAssertEqual(sod.getPSSParameters().mgf1Hash, "sha512")
        XCTAssertEqual(try sod.getSignerInfoDigestAlgorithm(), "sha512")
    }

    func testTamperedSODIsRejected() throws {
        let dsc = Self.makeCertificate(subject: "DSC", key: Self.rsaKey, issuer: "DSC", issuerKey: Self.rsaKey, ca: false)
        defer { X509_free(dsc) }
        let sod = try Self.makeSOD(content: content, signer: dsc, key: Self.rsaKey, digest: EVP_sha512(), pss: false)

        // Content changed after signing: the messageDigest no longer matches
        var changedContent = sod.data
        let at = try XCTUnwrap(changedContent.firstIndex(of: 0xAB))
        changedContent[at] = 0xAC
        XCTAssertThrowsError(try OpenSSLUtils.verifyAndReturnSODEncapsulatedData(sod: try SOD(changedContent)))

        // Signature changed: its last byte is the last byte of the SOD (no unsigned attributes)
        var changedSignature = sod.data
        changedSignature[changedSignature.count - 1] ^= 0x01
        XCTAssertThrowsError(try OpenSSLUtils.verifyAndReturnSODEncapsulatedData(sod: try SOD(changedSignature))) { error in
            XCTAssertTrue("\(error)".contains("Unable to verify signature for signed attributes"), "\(error)")
        }
    }

    // MARK: - DSC chain

    func testDSCChainsToItsCSCA() throws {
        let csca = Self.makeCertificate(subject: "CSCA", key: Self.ecKey, issuer: "CSCA", issuerKey: Self.ecKey, ca: true)
        let dsc = Self.makeCertificate(subject: "DSC", key: Self.rsaKey, issuer: "CSCA", issuerKey: Self.ecKey, ca: false)
        defer { X509_free(csca); X509_free(dsc) }
        let issuer = try verifyChain(dsc: dsc, masterList: [csca]).get()
        XCTAssertEqual(issuer.getSubjectName(), X509Wrapper(with: csca)?.getSubjectName())
    }

    /// A master list with the new CSCA and the link certificate for the old one (new CSCA signing the old CSCA's
    /// key), but not the old CSCA itself. Building on through the link certificate to the new CSCA would break its
    /// pathLenConstraint of 0 (error 25); the link certificate is a trust anchor in its own right.
    func testDSCChainsThroughALinkCertificate() throws {
        let oldKey = Self.generateKey(EVP_PKEY_EC)
        defer { EVP_PKEY_free(oldKey) }
        let newCSCA = Self.makeCertificate(subject: "CSCA 2", key: Self.ecKey, issuer: "CSCA 2", issuerKey: Self.ecKey, ca: true)
        let link = Self.makeCertificate(subject: "CSCA 1", key: oldKey, issuer: "CSCA 2", issuerKey: Self.ecKey, ca: true)
        let dsc = Self.makeCertificate(subject: "DSC", key: Self.rsaKey, issuer: "CSCA 1", issuerKey: oldKey, ca: false)
        defer { X509_free(newCSCA); X509_free(link); X509_free(dsc) }
        XCTAssertNoThrow(try verifyChain(dsc: dsc, masterList: [newCSCA, link]).get())
    }

    func testDSCFromAnUnknownCSCAFails() throws {
        let otherKey = Self.generateKey(EVP_PKEY_EC)
        defer { EVP_PKEY_free(otherKey) }
        let csca = Self.makeCertificate(subject: "CSCA", key: Self.ecKey, issuer: "CSCA", issuerKey: Self.ecKey, ca: true)
        let dsc = Self.makeCertificate(subject: "DSC", key: Self.rsaKey, issuer: "Other CSCA", issuerKey: otherKey, ca: false)
        defer { X509_free(csca); X509_free(dsc) }
        XCTAssertThrowsError(try verifyChain(dsc: dsc, masterList: [csca]).get())
    }

    // MARK: - Helpers

    private func verifyChain(dsc: OpaquePointer, masterList: [OpaquePointer]) throws -> Result<X509Wrapper, OpenSSLError> {
        let bio = try XCTUnwrap(BIO_new(BIO_s_mem()))
        defer { BIO_free(bio) }
        for cert in masterList {
            XCTAssertEqual(PEM_write_bio_X509(bio, cert), 1)
        }
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("masterList-\(UUID().uuidString).pem")
        try OpenSSLUtils.bioToString(bio: bio).write(to: url, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(at: url) }
        return OpenSSLUtils.verifyTrustAndGetIssuerCertificate(x509: try XCTUnwrap(X509Wrapper(with: dsc)), CAFile: url)
    }

    private static func tlv(_ tag: UInt8, _ value: [UInt8]) -> [UInt8] {
        let length: [UInt8]
        switch value.count {
            case ..<0x80: length = [UInt8(value.count)]
            case ..<0x100: length = [0x81, UInt8(value.count)]
            default: length = [0x82, UInt8(value.count >> 8), UInt8(value.count & 0xFF)]
        }
        return [tag] + length + value
    }

    /// An RSA 2048 or EC P-256 key pair
    private static func generateKey(_ type: Int32) -> OpaquePointer {
        let ctx = EVP_PKEY_CTX_new_id(type, nil)!
        defer { EVP_PKEY_CTX_free(ctx) }
        precondition(EVP_PKEY_keygen_init(ctx) == 1)
        if type == EVP_PKEY_RSA {
            precondition(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) == 1)
        } else {
            precondition(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) == 1)
        }
        var key: OpaquePointer?
        precondition(EVP_PKEY_keygen(ctx, &key) == 1)
        return key!
    }

    private static func name(_ commonName: String) -> OpaquePointer {
        let name = X509_NAME_new()!
        let bytes = [UInt8](commonName.utf8)
        precondition(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, bytes, Int32(bytes.count), -1, 0) == 1)
        return name
    }

    /// A v3 certificate; a CA one has basicConstraints CA:TRUE with pathLenConstraint 0, as ICAO 9303-12 has for CSCAs
    private static func makeCertificate(subject: String, key: OpaquePointer, issuer: String, issuerKey: OpaquePointer, ca: Bool) -> OpaquePointer {
        let cert = X509_new()!
        X509_set_version(cert, 2)
        ASN1_INTEGER_set(X509_get_serialNumber(cert), Int(arc4random_uniform(1_000_000)) + 1)
        X509_gmtime_adj(X509_getm_notBefore(cert), -3600)
        X509_gmtime_adj(X509_getm_notAfter(cert), 365 * 24 * 3600)
        X509_set_pubkey(cert, key)
        let subjectName = name(subject), issuerName = name(issuer)
        defer { X509_NAME_free(subjectName); X509_NAME_free(issuerName) }
        X509_set_subject_name(cert, subjectName)
        X509_set_issuer_name(cert, issuerName)
        if ca {
            var ctx = X509V3_CTX()
            X509V3_set_ctx(&ctx, nil, cert, nil, nil, 0)
            for (nid, value) in [(NID_basic_constraints, "critical,CA:TRUE,pathlen:0"), (NID_key_usage, "critical,keyCertSign,cRLSign")] {
                let ext = X509V3_EXT_conf_nid(nil, &ctx, nid, value)
                precondition(ext != nil && X509_add_ext(cert, ext, -1) == 1)
                X509_EXTENSION_free(ext)
            }
        }
        precondition(X509_sign(cert, issuerKey, EVP_sha256()) > 0)
        return cert
    }

    /// An EF.SOD: tag 77 around a CMS SignedData with signed attributes, signed by `signer`
    private static func makeSOD(content: [UInt8], signer: OpaquePointer, key: OpaquePointer, digest: OpaquePointer?, pss: Bool) throws -> SOD {
        let cms = try XCTUnwrap(CMS_sign(nil, nil, nil, nil, UInt32(CMS_PARTIAL | CMS_BINARY)))
        defer { CMS_ContentInfo_free(cms) }
        let ldsSecurityObject = OBJ_txt2obj("2.23.136.1.1.1", 1)
        defer { ASN1_OBJECT_free(ldsSecurityObject) }
        XCTAssertEqual(CMS_set1_eContentType(cms, ldsSecurityObject), 1)

        let signerInfo = try XCTUnwrap(CMS_add1_signer(cms, signer, key, digest, UInt32(CMS_NOSMIMECAP | CMS_BINARY | (pss ? CMS_KEY_PARAM : 0))))
        if pss {
            let pctx = CMS_SignerInfo_get0_pkey_ctx(signerInfo)
            XCTAssertEqual(EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING), 1)
            XCTAssertEqual(EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, digest), 1)
            XCTAssertEqual(EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, -1), 1)  // salt as long as the hash
        }

        let input = try XCTUnwrap(BIO_new_mem_buf(content, Int32(content.count)))
        defer { BIO_free(input) }
        XCTAssertEqual(CMS_final(cms, input, nil, UInt32(CMS_BINARY)), 1)

        let out = try XCTUnwrap(BIO_new(BIO_s_mem()))
        defer { BIO_free(out) }
        XCTAssertEqual(i2d_CMS_bio(out, cms), 1)
        var der = [UInt8](repeating: 0, count: Int(BIO_ctrl(out, BIO_CTRL_PENDING, 0, nil)))
        BIO_read(out, &der, Int32(der.count))
        return try SOD(tlv(0x77, der))
    }
}
