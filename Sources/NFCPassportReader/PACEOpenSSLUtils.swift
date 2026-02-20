//
//  PACEOpenSSLUtils.swift
//  NFCPassportReader
//
//  Created by Ugo Chirico on 20/02/26.
//

import Foundation
import OpenSSL

// Assumo tu abbia già importato OpenSSL nel bridging header:
// #include <openssl/evp.h>
// #include <openssl/core_names.h>
// #include <openssl/objects.h>

enum PaceOpenSSLError: Error {
    case openssl(String)
}

@inline(__always)
private func throwOpenSSLError(_ msg: String) throws -> Never {
    throw PaceOpenSSLError.openssl(msg)
}

/// Genera una EC ephemeral keypair sulla stessa curva descritta da `ephemeralParams`.
/// - Parameter ephemeralParams: EVP_PKEY* che contiene i parametri EC (anche params-only / provider-managed)
/// - Returns: EVP_PKEY* (EC keypair) da liberare con EVP_PKEY_free quando non serve più.
func generateEphemeralECKey(from ephemeralParams: OpaquePointer) throws -> OpaquePointer {
    // 1) Leggi group name (es: "prime256v1", "secp256r1", ecc.)
    var curveNameBuf = [CChar](repeating: 0, count: 128)
    var curveLen: Int = 0

    let okGroup: Int32 = curveNameBuf.withUnsafeMutableBufferPointer { buf in
        EVP_PKEY_get_utf8_string_param(
            ephemeralParams,
            OSSL_PKEY_PARAM_GROUP_NAME,
            buf.baseAddress,
            buf.count,
            &curveLen
        )
    }

    guard okGroup == 1, curveLen > 0 else {
        try throwOpenSSLError("Failed to get EC group name from ephemeralParams (OSSL_PKEY_PARAM_GROUP_NAME).")
    }

    // Converti in Swift String
    let curveName = String(cString: curveNameBuf)
    let nid = OBJ_txt2nid(curveName)
    guard nid != NID_undef else {
        try throwOpenSSLError("Unknown/unsupported curve name '\(curveName)' (OBJ_txt2nid returned NID_undef).")
    }

    // 2) Keygen EC via EVP (OpenSSL 3 style)
    guard let ctx = EVP_PKEY_CTX_new_from_name(nil, "EC", nil) else {
        try throwOpenSSLError("EVP_PKEY_CTX_new_from_name(\"EC\") failed.")
    }
    defer { EVP_PKEY_CTX_free(ctx) }

    guard EVP_PKEY_keygen_init(ctx) == 1 else {
        try throwOpenSSLError("EVP_PKEY_keygen_init failed.")
    }

    // Imposta curva
    guard EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid) == 1 else {
        try throwOpenSSLError("EVP_PKEY_CTX_set_ec_paramgen_curve_nid failed for curve '\(curveName)'.")
    }

    var ephKey: OpaquePointer? = nil
    guard EVP_PKEY_keygen(ctx, &ephKey) == 1, let ephKeyUnwrapped = ephKey else {
        try throwOpenSSLError("EVP_PKEY_keygen failed.")
    }

    return ephKeyUnwrapped
}
