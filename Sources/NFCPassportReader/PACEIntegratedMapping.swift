//
//  PACEIntegratedMapping.swift
//  NFCPassportReader
//
//  PACE ECDH Integrated Mapping (ICAO Doc 9303 Part 11, 4.4.3.3.2 and Appendix B).
//

import Foundation
import OpenSSL

/// PACE ECDH Integrated Mapping: the mapped generator is G^ = f_G(R_p(s, t)), where s is the chip's
/// (decrypted) nonce and t is a nonce chosen by the reader and sent in clear.
///
/// This follows the current ICAO definition: R_p is the block-cipher based pseudo-random function
/// and f_G is the simplified SWU point encoding of Brier et al. (requires p = 3 mod 4). The older
/// TR-SAC 1.0 variant (x = E(t, s) and Icart's encoding) is not interoperable with it.
@available(iOS 13, macOS 10.15, *)
public enum PACEIntegratedMapping {
    private static let c0_128 = hexRepToBin("a668892a7c41e3ca739f40b057d85904")
    private static let c1_128 = hexRepToBin("a4e136ac725f738b01c1f60217c188ad")
    private static let c0_256 = hexRepToBin("d463d65234124ef7897054986dca0a174e28df758cbaa03f240616414d5a1676")
    private static let c1_256 = hexRepToBin("54bd7255f0aaf831bec3423fcf39d69b6cbf066677d0faae5aadd99df8e53517")

    /// l: bit length of the chip nonce s (and of c0/c1). k: key size of E() and bit length of the reader nonce t.
    /// 3DES: l = 128, k is "considered" 128. AES-128: 128/128. AES-192: 256/192. AES-256: 256/256.
    public static func lengths(cipherAlg: String, keyLength: Int) throws -> (l: Int, k: Int) {
        if cipherAlg == "DESede" {
            return (128, 128)
        }
        if cipherAlg == "AES" {
            switch keyLength {
                case 128: return (128, 128)
                case 192: return (256, 192)
                case 256: return (256, 256)
                default: break
            }
        }
        throw NFCPassportReaderError.InvalidDataPassed("Integrated Mapping: unsupported cipher \(cipherAlg)-\(keyLength)")
    }

    /// R(s,t) = x1 || ... || xn (before reduction mod p), as in Figure 2 of 9303-11:
    /// CBC with IV = 0, k0 = E(t, s), then k(i+1) = E(k(i), c0) and x(i+1) = E(k(i), c1), keys truncated to
    /// k bits, for the smallest n with n * l >= log2(p) + 64.
    public static func pseudoRandom(s: [UInt8], t: [UInt8], pBitLength: Int, cipherAlg: String, keyLength: Int) throws -> [UInt8] {
        let (l, k) = try lengths(cipherAlg: cipherAlg, keyLength: keyLength)
        guard s.count * 8 == l else {
            throw NFCPassportReaderError.InvalidDataPassed("Integrated Mapping: nonce s must be \(l / 8) bytes, got \(s.count)")
        }
        guard t.count * 8 == k else {
            throw NFCPassportReaderError.InvalidDataPassed("Integrated Mapping: nonce t must be \(k / 8) bytes, got \(t.count)")
        }
        let (c0, c1) = l == 128 ? (c0_128, c1_128) : (c0_256, c1_256)

        func encrypt(_ key: [UInt8], _ message: [UInt8]) -> [UInt8] {
            if cipherAlg == "DESede" {
                return tripleDESEncrypt(key: key, message: message, iv: [UInt8](repeating: 0, count: 8))
            }
            return AESEncrypt(key: key, message: message, iv: [UInt8](repeating: 0, count: 16))
        }

        var key = encrypt(t, s)
        var output: [UInt8] = []
        var n = 0
        while n * l < pBitLength + 64 {
            guard key.count >= k / 8 else {
                throw NFCPassportReaderError.InvalidDataPassed("Integrated Mapping: block cipher failed")
            }
            let ki = [UInt8](key[0 ..< k / 8])
            key = encrypt(ki, c0)
            output += encrypt(ki, c1)
            n += 1
        }
        return output
    }

    /// The result of mapping a nonce. Owns the mapped EC_GROUP (the base curve with generator G^).
    public final class Mapping {
        /// R(s,t) before reduction.
        public let pseudoRandom: [UInt8]
        /// R_p(s,t) = int(R(s,t)) mod p, padded to the field length.
        public let rp: [UInt8]
        /// Affine coordinates of G^, padded to the field length.
        public let generatorX: [UInt8]
        public let generatorY: [UInt8]
        /// EC_GROUP with the mapped generator. Freed with the Mapping.
        public let group: OpaquePointer
        let curveName: Int32

        init(pseudoRandom: [UInt8], rp: [UInt8], generatorX: [UInt8], generatorY: [UInt8], group: OpaquePointer, curveName: Int32) {
            self.pseudoRandom = pseudoRandom
            self.rp = rp
            self.generatorX = generatorX
            self.generatorY = generatorY
            self.group = group
            self.curveName = curveName
        }

        deinit { EC_GROUP_free(group) }

        /// An EVP_PKEY holding an EC_KEY (no key pair yet) on the mapped group, in the same form as the
        /// Generic Mapping's ephemeral parameters, for PACE step 3. Caller frees.
        public func ephemeralParameters() throws -> OpaquePointer {
            guard let ecKey = EC_KEY_new_by_curve_name(curveName) else {
                throw NFCPassportReaderError.PACEError("Step2IM", "Unable to create EC key")
            }
            defer { EC_KEY_free(ecKey) }
            guard EC_KEY_set_group(ecKey, group) == 1 else {
                throw NFCPassportReaderError.PACEError("Step2IM", "Unable to set mapped group")
            }
            guard let params = EVP_PKEY_new() else {
                throw NFCPassportReaderError.PACEError("Step2IM", "Unable to create ephemeral params")
            }
            guard EVP_PKEY_set1_EC_KEY(params, ecKey) == 1 else {
                EVP_PKEY_free(params)
                throw NFCPassportReaderError.PACEError("Step2IM", "Unable to set ephemeral params")
            }
            return params
        }
    }

    /// Computes G^ = f_G(R_p(s, t)) on the named curve [curveName] (an OpenSSL NID).
    public static func map(s: [UInt8], t: [UInt8], curveName: Int32, cipherAlg: String, keyLength: Int) throws -> Mapping {
        guard let base = EC_GROUP_new_by_curve_name(curveName) else {
            throw NFCPassportReaderError.InvalidDataPassed("Integrated Mapping: unknown curve \(curveName)")
        }
        guard let group = EC_GROUP_dup(base) else {
            EC_GROUP_free(base)
            throw NFCPassportReaderError.InvalidDataPassed("Integrated Mapping: unable to copy curve")
        }
        EC_GROUP_free(base)
        var keepGroup = false
        defer { if !keepGroup { EC_GROUP_free(group) } }

        let ctx = BN_CTX_new()
        defer { BN_CTX_free(ctx) }
        let p = BN_new(), a = BN_new(), b = BN_new(), rp = BN_new(), x = BN_new(), y = BN_new()
        defer { [p, a, b, rp, x, y].forEach { BN_free($0) } }
        guard EC_GROUP_get_curve(group, p, a, b, ctx) == 1 else {
            throw NFCPassportReaderError.InvalidDataPassed("Integrated Mapping: unable to read curve parameters")
        }
        let fieldLength = (Int(BN_num_bits(p)) + 7) / 8

        let raw = try pseudoRandom(s: s, t: t, pBitLength: Int(BN_num_bits(p)), cipherAlg: cipherAlg, keyLength: keyLength)
        guard BN_bin2bn(raw, Int32(raw.count), rp) != nil, BN_nnmod(rp, rp, p, ctx) == 1 else {
            throw NFCPassportReaderError.InvalidDataPassed("Integrated Mapping: unable to reduce R(s,t)")
        }

        let generator = try pointEncode(t: rp!, group: group)
        defer { EC_POINT_free(generator) }
        // Copies, because set_generator overwrites the group's own order and cofactor.
        let order = BN_dup(EC_GROUP_get0_order(group)), cofactor = BN_dup(EC_GROUP_get0_cofactor(group))
        defer { BN_free(order); BN_free(cofactor) }
        guard EC_POINT_get_affine_coordinates(group, generator, x, y, ctx) == 1,
              EC_GROUP_set_generator(group, generator, order, cofactor) == 1 else {
            throw NFCPassportReaderError.InvalidDataPassed("Integrated Mapping: unable to set the mapped generator")
        }
        keepGroup = true
        return Mapping(
            pseudoRandom: raw, rp: bnToBytes(rp!, length: fieldLength),
            generatorX: bnToBytes(x!, length: fieldLength), generatorY: bnToBytes(y!, length: fieldLength),
            group: group, curveName: curveName
        )
    }

    /// f_G, 9303-11 Appendix B.2 (affine coordinates). Maps 0 < t < p to a point of the prime-order
    /// subgroup of [group]. Returns a new EC_POINT; the caller frees it.
    public static func pointEncode(t: OpaquePointer, group: OpaquePointer) throws -> OpaquePointer {
        guard let ctx = BN_CTX_new() else {
            throw NFCPassportReaderError.InvalidDataPassed("Integrated Mapping: out of memory")
        }
        defer { BN_CTX_free(ctx) }
        var bns: [OpaquePointer] = []
        defer { bns.forEach { BN_clear_free($0) } }
        func bn() -> OpaquePointer {
            let v = BN_new()!
            bns.append(v)
            return v
        }
        let p = bn(), a = bn(), b = bn(), zero = bn(), one = bn()
        guard EC_GROUP_get_curve(group, p, a, b, ctx) == 1, BN_set_word(zero, 0) == 1, BN_set_word(one, 1) == 1 else {
            throw NFCPassportReaderError.InvalidDataPassed("Integrated Mapping: unable to read curve parameters")
        }
        guard BN_mod_word(p, 4) == 3 else {
            throw NFCPassportReaderError.InvalidDataPassed("Integrated Mapping: point encoding needs p = 3 (mod 4)")
        }

        let tmp = bn(), tmp2 = bn()
        let alpha = bn(), alphaSum = bn(), numerator = bn(), denominator = bn(), pMinus2 = bn()
        let x2 = bn(), x3 = bn(), h2 = bn(), u = bn(), exponent = bn(), bigA = bn(), check = bn()
        let x = bn(), y = bn()
        var ok = true
        // 1. alpha = -t^2 mod p
        ok = ok && BN_mod_sqr(tmp, t, p, ctx) == 1 && BN_mod_sub(alpha, zero, tmp, p, ctx) == 1
        // 2. X2 = -b (1 + alpha + alpha^2) (a (alpha + alpha^2))^(p-2) mod p
        ok = ok && BN_mod_sqr(tmp, alpha, p, ctx) == 1 && BN_mod_add(alphaSum, alpha, tmp, p, ctx) == 1
        ok = ok && BN_mod_add(numerator, one, alphaSum, p, ctx) == 1
        ok = ok && BN_mod_mul(denominator, a, alphaSum, p, ctx) == 1
        ok = ok && BN_sub(pMinus2, p, one) == 1 && BN_sub(pMinus2, pMinus2, one) == 1
        ok = ok && BN_mod_exp(tmp, denominator, pMinus2, p, ctx) == 1
        ok = ok && BN_mod_mul(tmp, tmp, numerator, p, ctx) == 1 && BN_mod_mul(tmp, tmp, b, p, ctx) == 1
        ok = ok && BN_mod_sub(x2, zero, tmp, p, ctx) == 1
        // 3. X3 = alpha X2 mod p
        ok = ok && BN_mod_mul(x3, alpha, x2, p, ctx) == 1
        // 4. h2 = X2^3 + a X2 + b mod p
        ok = ok && BN_mod_sqr(tmp, x2, p, ctx) == 1 && BN_mod_mul(tmp, tmp, x2, p, ctx) == 1
        ok = ok && BN_mod_mul(tmp2, a, x2, p, ctx) == 1 && BN_mod_add(h2, tmp, tmp2, p, ctx) == 1
        ok = ok && BN_mod_add(h2, h2, b, p, ctx) == 1
        // 6. U = t^3 h2 mod p
        ok = ok && BN_mod_sqr(tmp, t, p, ctx) == 1 && BN_mod_mul(tmp, tmp, t, p, ctx) == 1
        ok = ok && BN_mod_mul(u, tmp, h2, p, ctx) == 1
        // 7. A = h2^(p - 1 - (p + 1) / 4) mod p
        ok = ok && BN_add(tmp, p, one) == 1 && BN_rshift(tmp, tmp, 2) == 1
        ok = ok && BN_sub(exponent, p, one) == 1 && BN_sub(exponent, exponent, tmp) == 1
        ok = ok && BN_mod_exp(bigA, h2, exponent, p, ctx) == 1
        // 8./9. If A^2 h2 = 1 then (X2, A h2) else (X3, A U)
        ok = ok && BN_mod_sqr(check, bigA, p, ctx) == 1 && BN_mod_mul(check, check, h2, p, ctx) == 1
        guard ok else {
            throw NFCPassportReaderError.InvalidDataPassed("Integrated Mapping: point encoding arithmetic failed")
        }
        if BN_is_one(check) == 1 {
            ok = BN_copy(x, x2) != nil && BN_mod_mul(y, bigA, h2, p, ctx) == 1
        } else {
            ok = BN_copy(x, x3) != nil && BN_mod_mul(y, bigA, u, p, ctx) == 1
        }

        guard ok, let point = EC_POINT_new(group) else {
            throw NFCPassportReaderError.InvalidDataPassed("Integrated Mapping: point encoding failed")
        }
        guard EC_POINT_set_affine_coordinates(group, point, x, y, ctx) == 1, EC_POINT_is_on_curve(group, point, ctx) == 1 else {
            EC_POINT_free(point)
            throw NFCPassportReaderError.InvalidDataPassed("Integrated Mapping: encoded point is not on the curve")
        }
        // 10. Multiply by the cofactor (a no-op for the standardized curves, which all have cofactor 1).
        if let cofactor = EC_GROUP_get0_cofactor(group), BN_is_one(cofactor) != 1 {
            guard EC_POINT_mul(group, point, nil, point, cofactor, ctx) == 1 else {
                EC_POINT_free(point)
                throw NFCPassportReaderError.InvalidDataPassed("Integrated Mapping: cofactor multiplication failed")
            }
        }
        return point
    }

    private static func bnToBytes(_ bn: OpaquePointer, length: Int) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: length)
        _ = BN_bn2binpad(bn, &out, Int32(length))
        return out
    }
}
