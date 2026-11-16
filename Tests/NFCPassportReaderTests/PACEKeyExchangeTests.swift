//
//  PACEKeyExchangeTests.swift
//  NFCPassportReaderTests
//
//  PACE step 3 (ephemeral key pair on the mapped parameters) and step 4 (shared secret), run locally for both
//  parties. PassportSim only simulates ECDH PACE, so this is the coverage for id-PACE-DH-* documents.
//

import XCTest
import OpenSSL

@testable import NFCPassportReader

final class PACEKeyExchangeTests: XCTestCase {

    /// id-PACE-DH-GM with parameterId 2 (RFC 5114 2048-bit MODP, 256-bit q), with a mapped generator as step 2 makes.
    func testDHKeyExchangeOnMappedParameters() throws {
        let params = try mappedDHParameters()
        defer { EVP_PKEY_free(params) }
        try assertKeyExchangeAgrees(params: params, expectedTypes: [EVP_PKEY_DH, EVP_PKEY_DHX])  // DHX: the key carries q
    }

    func testECDHKeyExchange() throws {
        guard let ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1) else { return XCTFail("EC_KEY") }
        defer { EC_KEY_free(ec) }
        let params = EVP_PKEY_new()!
        defer { EVP_PKEY_free(params) }
        XCTAssertEqual(EVP_PKEY_set1_EC_KEY(params, ec), 1)
        try assertKeyExchangeAgrees(params: params, expectedTypes: [EVP_PKEY_EC])
    }

    /// Two ephemeral key pairs from `params` agree on the secret (PCD and PICC sides of steps 3 and 4).
    private func assertKeyExchangeAgrees(params: OpaquePointer, expectedTypes: [Int32], file: StaticString = #filePath, line: UInt = #line) throws {
        let pcd = try PACEHandler.generateEphemeralKeyPair(params: params)
        let picc = try PACEHandler.generateEphemeralKeyPair(params: params)
        defer { EVP_PKEY_free(pcd); EVP_PKEY_free(picc) }
        XCTAssertTrue(expectedTypes.contains(EVP_PKEY_get_base_id(pcd)), "key type \(EVP_PKEY_get_base_id(pcd))", file: file, line: line)

        let pcdPublic = try XCTUnwrap(OpenSSLUtils.getPublicKeyData(from: pcd), file: file, line: line)
        let piccPublic = try XCTUnwrap(OpenSSLUtils.getPublicKeyData(from: picc), file: file, line: line)
        let piccKey = try XCTUnwrap(OpenSSLUtils.decodePublicKeyFromBytes(pubKeyData: piccPublic, params: pcd), file: file, line: line)
        let pcdKey = try XCTUnwrap(OpenSSLUtils.decodePublicKeyFromBytes(pubKeyData: pcdPublic, params: picc), file: file, line: line)
        defer { EVP_PKEY_free(piccKey); EVP_PKEY_free(pcdKey) }

        let pcdSecret = OpenSSLUtils.computeSharedSecret(privateKeyPair: pcd, publicKey: piccKey)
        let piccSecret = OpenSSLUtils.computeSharedSecret(privateKeyPair: picc, publicKey: pcdKey)
        XCTAssertFalse(pcdSecret.isEmpty, file: file, line: line)
        XCTAssertEqual(pcdSecret, piccSecret, file: file, line: line)
    }

    /// The RFC 5114 2048/256 group with g replaced by g^2 mod p, standing in for the step 2 mapped generator.
    private func mappedDHParameters() throws -> OpaquePointer {
        let dh = try XCTUnwrap(DH_get_2048_256())
        defer { DH_free(dh) }
        var p: OpaquePointer?, q: OpaquePointer?, g: OpaquePointer?
        DH_get0_pqg(dh, &p, &q, &g)
        let ctx = BN_CTX_new()
        defer { BN_CTX_free(ctx) }
        let mapped = BN_new()!
        XCTAssertEqual(BN_mod_sqr(mapped, g, p, ctx), 1)
        let mappedDH = try XCTUnwrap(DH_new())
        defer { DH_free(mappedDH) }
        XCTAssertEqual(DH_set0_pqg(mappedDH, BN_dup(p), BN_dup(q), mapped), 1)
        let params = EVP_PKEY_new()!
        XCTAssertEqual(EVP_PKEY_set1_DH(params, mappedDH), 1)
        return params
    }
}
