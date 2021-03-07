//
//  PaceInfo.swift
//  NFCPassportReader
//
//  Created by Andy Qua on 03/03/2021.
//

import Foundation
import OpenSSL

public enum PACEMappingType {
    case GM  // Generic Mapping
    case IM  // Integrated Mapping
    case CAM // Chip Authentication Mapping
}

/** Standardized domain parameters. Based on Table 6. */


@available(iOS 13, macOS 10.15, *)
public class PACEInfo : SecurityInfo {
    
    // Standardized domain parameters. Based on Table 6.
    public static let PARAM_ID_GFP_1024_160 = 0
    public static let PARAM_ID_GFP_2048_224 = 1
    public static let PARAM_ID_GFP_2048_256 = 2
    public static let PARAM_ID_ECP_NIST_P192_R1 = 8
    public static let PARAM_ID_ECP_BRAINPOOL_P192_R1 = 9
    public static let PARAM_ID_ECP_NIST_P224_R1 = 10
    public static let PARAM_ID_ECP_BRAINPOOL_P224_R1 = 11
    public static let PARAM_ID_ECP_NIST_P256_R1 = 12
    public static let PARAM_ID_ECP_BRAINPOOL_P256_R1 = 13
    public static let PARAM_ID_ECP_BRAINPOOL_P320_R1 = 14
    public static let PARAM_ID_ECP_NIST_P384_R1 = 15
    public static let PARAM_ID_ECP_BRAINPOOL_P384_R1 = 16
    public static let PARAM_ID_ECP_BRAINPOOL_P512_R1 = 17
    public static let PARAM_ID_ECP_NIST_P521_R1 = 18

    static let allowedIdentifiers = [
        ID_PACE_DH_GM_3DES_CBC_CBC,
        ID_PACE_DH_GM_AES_CBC_CMAC_128,
        ID_PACE_DH_GM_AES_CBC_CMAC_192,
        ID_PACE_DH_GM_AES_CBC_CMAC_256,
        ID_PACE_DH_IM_3DES_CBC_CBC,
        ID_PACE_DH_IM_AES_CBC_CMAC_128,
        ID_PACE_DH_IM_AES_CBC_CMAC_192,
        ID_PACE_DH_IM_AES_CBC_CMAC_256,
        ID_PACE_ECDH_GM_3DES_CBC_CBC,
        ID_PACE_ECDH_GM_AES_CBC_CMAC_128,
        ID_PACE_ECDH_GM_AES_CBC_CMAC_192,
        ID_PACE_ECDH_GM_AES_CBC_CMAC_256,
        ID_PACE_ECDH_IM_3DES_CBC_CBC,
        ID_PACE_ECDH_IM_AES_CBC_CMAC_128,
        ID_PACE_ECDH_IM_AES_CBC_CMAC_192,
        ID_PACE_ECDH_IM_AES_CBC_CMAC_256,
        ID_PACE_ECDH_CAM_AES_CBC_CMAC_128,
        ID_PACE_ECDH_CAM_AES_CBC_CMAC_192,
        ID_PACE_ECDH_CAM_AES_CBC_CMAC_256]

    var oid : String
    var version : Int
    var parameterId : Int?
    
    static func checkRequiredIdentifier(_ oid : String) -> Bool {
        return allowedIdentifiers.contains( oid )
    }
    
    init(oid: String, version: Int, parameterId: Int?) {
        self.oid = oid
        self.version = version
        self.parameterId = parameterId
    }
    
    public override func getObjectIdentifier() -> String {
        return oid
    }
    
    public func getVersion() -> Int {
        return version
    }
    
    public func getParameterId() -> Int? {
        return parameterId
    }
    
    public  func getParameterSpec() throws -> Int32 {
        
        return try PACEInfo.getParameterSpec(stdDomainParam: self.parameterId ?? -1 )
    }

    
    public override func getProtocolOIDString() -> String {
        return PACEInfo.toProtocolOIDString(oid:oid)
    }

    public static func getParameterSpec(stdDomainParam : Int) throws -> Int32 {
        switch (stdDomainParam) {
            case PARAM_ID_GFP_1024_160:
                return 0 // "rfc5114_1024_160";
            case PARAM_ID_GFP_2048_224:
                return 1 // "rfc5114_2048_224";
            case PARAM_ID_GFP_2048_256:
                return 2 // "rfc5114_2048_256";
            case PARAM_ID_ECP_NIST_P192_R1:
                return NID_X9_62_prime192v1 // "secp192r1";
            case PARAM_ID_ECP_NIST_P224_R1:
                return NID_secp224r1 // "secp224r1";
            case PARAM_ID_ECP_NIST_P256_R1:
                return NID_X9_62_prime256v1 //"secp256r1";
            case PARAM_ID_ECP_NIST_P384_R1:
                return NID_secp384r1 // "secp384r1";
            case PARAM_ID_ECP_BRAINPOOL_P192_R1:
                return NID_brainpoolP192r1 //"brainpoolp192r1";
            case PARAM_ID_ECP_BRAINPOOL_P224_R1:
                return NID_brainpoolP224r1 // "brainpoolp224r1";
            case PARAM_ID_ECP_BRAINPOOL_P256_R1:
                return NID_brainpoolP256r1 // "brainpoolp256r1";
            case PARAM_ID_ECP_BRAINPOOL_P320_R1:
                return NID_brainpoolP320r1 //"brainpoolp320r1";
            case PARAM_ID_ECP_BRAINPOOL_P384_R1:
                return NID_brainpoolP384r1 //"brainpoolp384r1";
            case PARAM_ID_ECP_BRAINPOOL_P512_R1:
                return NID_brainpoolP512r1 //"";
            case PARAM_ID_ECP_NIST_P521_R1:
                return NID_secp521r1 //"secp224r1";
            default:
                throw NFCPassportReaderError.InvalidDataPassed( "Unable to lookup p arameterSpec - invalid oid" )
        }
    }
    
    public static func toMappingType( oid : String ) throws -> PACEMappingType {
        if ID_PACE_DH_GM_3DES_CBC_CBC == oid
                || ID_PACE_DH_GM_AES_CBC_CMAC_128 == oid
                || ID_PACE_DH_GM_AES_CBC_CMAC_192 == oid
                || ID_PACE_DH_GM_AES_CBC_CMAC_256 == oid
                || ID_PACE_ECDH_GM_3DES_CBC_CBC == oid
                || ID_PACE_ECDH_GM_AES_CBC_CMAC_128 == oid
                || ID_PACE_ECDH_GM_AES_CBC_CMAC_192 == oid
                || ID_PACE_ECDH_GM_AES_CBC_CMAC_256 == oid {
            return PACEMappingType.GM
        } else if ID_PACE_DH_IM_3DES_CBC_CBC == oid
                    || ID_PACE_DH_IM_AES_CBC_CMAC_128 == oid
                    || ID_PACE_DH_IM_AES_CBC_CMAC_192 == oid
                    || ID_PACE_DH_IM_AES_CBC_CMAC_256 == oid
                    || ID_PACE_ECDH_IM_3DES_CBC_CBC == oid
                    || ID_PACE_ECDH_IM_AES_CBC_CMAC_128 == oid
                    || ID_PACE_ECDH_IM_AES_CBC_CMAC_192 == oid
                    || ID_PACE_ECDH_IM_AES_CBC_CMAC_256 == oid {
            return PACEMappingType.IM
        } else if ID_PACE_ECDH_CAM_AES_CBC_CMAC_128 == oid
                    || ID_PACE_ECDH_CAM_AES_CBC_CMAC_192 == oid
                    || ID_PACE_ECDH_CAM_AES_CBC_CMAC_256 == oid {
            return PACEMappingType.CAM
        }
        
        throw NFCPassportReaderError.InvalidDataPassed( "Unable to lookup mapping type - invalid oid" )
    }

    
    /// Returns the key agreement algorithm - DH or ECDH for the given Chip Authentication oid
    /// - Parameter oid: the object identifier
    /// - Returns: key agreement algorithm
    /// - Throws: InvalidDataPassed error if invalid oid specified
    public static func toKeyAgreementAlgorithm( oid : String ) throws -> String {
        if ID_PACE_DH_GM_3DES_CBC_CBC == oid
                || ID_PACE_DH_GM_AES_CBC_CMAC_128 == oid
                || ID_PACE_DH_GM_AES_CBC_CMAC_192 == oid
                || ID_PACE_DH_GM_AES_CBC_CMAC_256 == oid
                || ID_PACE_DH_IM_3DES_CBC_CBC == oid
                || ID_PACE_DH_IM_AES_CBC_CMAC_128 == oid
                || ID_PACE_DH_IM_AES_CBC_CMAC_192 == oid
                || ID_PACE_DH_IM_AES_CBC_CMAC_256 == oid {
            return "DH"
        } else if ID_PACE_ECDH_GM_3DES_CBC_CBC == oid
                    || ID_PACE_ECDH_GM_AES_CBC_CMAC_128 == oid
                    || ID_PACE_ECDH_GM_AES_CBC_CMAC_192 == oid
                    || ID_PACE_ECDH_GM_AES_CBC_CMAC_256 == oid
                    || ID_PACE_ECDH_IM_3DES_CBC_CBC == oid
                    || ID_PACE_ECDH_IM_AES_CBC_CMAC_128 == oid
                    || ID_PACE_ECDH_IM_AES_CBC_CMAC_192 == oid
                    || ID_PACE_ECDH_IM_AES_CBC_CMAC_256 == oid
                    || ID_PACE_ECDH_CAM_AES_CBC_CMAC_128 == oid
                    || ID_PACE_ECDH_CAM_AES_CBC_CMAC_192 == oid
                    || ID_PACE_ECDH_CAM_AES_CBC_CMAC_256 == oid {
            return "ECDH"
        }
        throw NFCPassportReaderError.InvalidDataPassed( "Unable to lookup key agreement algorithm - invalid oid" )
    }
    
    /// Returns the cipher algorithm - DESede or AES for the given Chip Authentication oid
    /// - Parameter oid: the object identifier
    /// - Returns: the cipher algorithm type
    /// - Throws: InvalidDataPassed error if invalid oid specified
    public static func toCipherAlgorithm( oid : String ) throws -> String {
        if ID_PACE_DH_GM_3DES_CBC_CBC == oid
                || ID_PACE_DH_IM_3DES_CBC_CBC == oid
                || ID_PACE_ECDH_GM_3DES_CBC_CBC == oid
                || ID_PACE_ECDH_IM_3DES_CBC_CBC == oid {
            return "DESede"
        } else if ID_PACE_DH_GM_AES_CBC_CMAC_128 == oid
                    || ID_PACE_DH_GM_AES_CBC_CMAC_192 == oid
                    || ID_PACE_DH_GM_AES_CBC_CMAC_256 == oid
                    || ID_PACE_DH_IM_AES_CBC_CMAC_128 == oid
                    || ID_PACE_DH_IM_AES_CBC_CMAC_192 == oid
                    || ID_PACE_DH_IM_AES_CBC_CMAC_256 == oid
                    || ID_PACE_ECDH_GM_AES_CBC_CMAC_128 == oid
                    || ID_PACE_ECDH_GM_AES_CBC_CMAC_192 == oid
                    || ID_PACE_ECDH_GM_AES_CBC_CMAC_256 == oid
                    || ID_PACE_ECDH_IM_AES_CBC_CMAC_128 == oid
                    || ID_PACE_ECDH_IM_AES_CBC_CMAC_192 == oid
                    || ID_PACE_ECDH_IM_AES_CBC_CMAC_256 == oid
                    || ID_PACE_ECDH_CAM_AES_CBC_CMAC_128 == oid
                    || ID_PACE_ECDH_CAM_AES_CBC_CMAC_192 == oid
                    || ID_PACE_ECDH_CAM_AES_CBC_CMAC_256 == oid {
            return "AES"
        }
        throw NFCPassportReaderError.InvalidDataPassed( "Unable to lookup cipher algorithm - invalid oid" )
    }
    
    public static func toDigestAlgorithm( oid : String ) throws -> String {
        if ID_PACE_DH_GM_3DES_CBC_CBC == oid
                || ID_PACE_DH_IM_3DES_CBC_CBC == oid
                || ID_PACE_ECDH_GM_3DES_CBC_CBC == oid
                || ID_PACE_ECDH_IM_3DES_CBC_CBC == oid
                || ID_PACE_DH_GM_AES_CBC_CMAC_128 == oid
                || ID_PACE_DH_IM_AES_CBC_CMAC_128 == oid
                || ID_PACE_ECDH_GM_AES_CBC_CMAC_128 == oid
                || ID_PACE_ECDH_IM_AES_CBC_CMAC_128 == oid
                || ID_PACE_ECDH_CAM_AES_CBC_CMAC_128 == oid {
            return "SHA-1"
        } else if ID_PACE_DH_GM_AES_CBC_CMAC_192 == oid
                    || ID_PACE_DH_IM_AES_CBC_CMAC_192 == oid
                    || ID_PACE_ECDH_GM_AES_CBC_CMAC_192 == oid
                    || ID_PACE_ECDH_IM_AES_CBC_CMAC_192 == oid
                    || ID_PACE_ECDH_CAM_AES_CBC_CMAC_192 == oid
                    || ID_PACE_DH_GM_AES_CBC_CMAC_256 == oid
                    || ID_PACE_DH_IM_AES_CBC_CMAC_256 == oid
                    || ID_PACE_ECDH_GM_AES_CBC_CMAC_256 == oid
                    || ID_PACE_ECDH_IM_AES_CBC_CMAC_256 == oid
                    || ID_PACE_ECDH_CAM_AES_CBC_CMAC_256 == oid {
            return "SHA-256"
        }

        throw NFCPassportReaderError.InvalidDataPassed( "Unable to lookup digest algorithm - invalid oid" )

    }
    /// Returns the key length in bits (128, 192, or 256) for the given Chip Authentication oid
    /// - Parameter oid: the object identifier
    /// - Returns: the key length in bits
    /// - Throws: InvalidDataPassed error if invalid oid specified
    public static func toKeyLength( oid : String ) throws -> Int {
        if ID_PACE_DH_GM_3DES_CBC_CBC == oid
                || ID_PACE_DH_IM_3DES_CBC_CBC == oid
                || ID_PACE_ECDH_GM_3DES_CBC_CBC == oid
                || ID_PACE_ECDH_IM_3DES_CBC_CBC == oid
                || ID_PACE_DH_GM_AES_CBC_CMAC_128 == oid
                || ID_PACE_DH_IM_AES_CBC_CMAC_128 == oid
                || ID_PACE_ECDH_GM_AES_CBC_CMAC_128 == oid
                || ID_PACE_ECDH_IM_AES_CBC_CMAC_128 == oid
                || ID_PACE_ECDH_CAM_AES_CBC_CMAC_128 == oid {
            return 128
        } else if ID_PACE_DH_GM_AES_CBC_CMAC_192 == oid
                    || ID_PACE_ECDH_GM_AES_CBC_CMAC_192 == oid
                    || ID_PACE_DH_IM_AES_CBC_CMAC_192 == oid
                    || ID_PACE_ECDH_IM_AES_CBC_CMAC_192 == oid
                    || ID_PACE_ECDH_CAM_AES_CBC_CMAC_192 == oid {
            return 192
        } else if ID_PACE_DH_GM_AES_CBC_CMAC_256 == oid
                    || ID_PACE_DH_IM_AES_CBC_CMAC_256 == oid
                    || ID_PACE_ECDH_GM_AES_CBC_CMAC_256 == oid
                    || ID_PACE_ECDH_IM_AES_CBC_CMAC_256 == oid
                    || ID_PACE_ECDH_CAM_AES_CBC_CMAC_256 == oid {
            return 256
        }
        throw NFCPassportReaderError.InvalidDataPassed( "Unable to get key length - invalid oid" )
    }
    
    private static func toProtocolOIDString(oid : String) -> String {
        if ID_PACE_DH_GM_3DES_CBC_CBC == oid {
            return "id-PACE-DH-GM-3DES-CBC-CBC"
        }
        if ID_PACE_DH_GM_AES_CBC_CMAC_128 == oid {
            return "id-PACE-DH-GM-AES-CBC-CMAC-128"
        }
        if ID_PACE_DH_GM_AES_CBC_CMAC_192 == oid {
            return "id-PACE-DH-GM-AES-CBC-CMAC-192"
        }
        if ID_PACE_DH_GM_AES_CBC_CMAC_256 == oid {
            return "id-PACE-DH-GM-AES-CBC-CMAC-256"
        }
        if ID_PACE_DH_IM_3DES_CBC_CBC == oid {
            return "id-PACE-DH-IM-3DES-CBC-CBC"
        }
        if ID_PACE_DH_IM_AES_CBC_CMAC_128 == oid {
            return "id-PACE-DH-IM-AES-CBC-CMAC-128"
        }
        if ID_PACE_DH_IM_AES_CBC_CMAC_192 == oid {
            return "id-PACE-DH-IM-AES-CBC-CMAC-192"
        }
        if ID_PACE_DH_IM_AES_CBC_CMAC_256 == oid {
            return "id-PACE_DH-IM-AES-CBC-CMAC-256"
        }
        if ID_PACE_ECDH_GM_3DES_CBC_CBC == oid {
            return "id-PACE-ECDH-GM-3DES-CBC-CBC"
        }
        if ID_PACE_ECDH_GM_AES_CBC_CMAC_128 == oid {
            return "id-PACE-ECDH-GM-AES-CBC-CMAC-128"
        }
        if ID_PACE_ECDH_GM_AES_CBC_CMAC_192 == oid {
            return "id-PACE-ECDH-GM-AES-CBC-CMAC-192"
        }
        if ID_PACE_ECDH_GM_AES_CBC_CMAC_256 == oid {
            return "id-PACE-ECDH-GM-AES-CBC-CMAC-256"
        }
        if ID_PACE_ECDH_IM_3DES_CBC_CBC == oid {
            return "id-PACE-ECDH-IM_3DES-CBC-CBC"
        }
        if ID_PACE_ECDH_IM_AES_CBC_CMAC_128 == oid {
            return "id-PACE-ECDH-IM-AES-CBC-CMAC-128"
        }
        if ID_PACE_ECDH_IM_AES_CBC_CMAC_192 == oid {
            return "id-PACE-ECDH-IM-AES-CBC-CMAC-192"
        }
        if ID_PACE_ECDH_IM_AES_CBC_CMAC_256 == oid {
            return "id-PACE-ECDH-IM-AES-CBC-CMAC-256"
        }
        if ID_PACE_ECDH_CAM_AES_CBC_CMAC_128 == oid {
            return "id-PACE-ECDH-CAM-AES-CBC-CMAC-128"
        }
        if ID_PACE_ECDH_CAM_AES_CBC_CMAC_192 == oid {
            return "id-PACE-ECDH-CAM-AES-CBC-CMAC-192"
        }
        if ID_PACE_ECDH_CAM_AES_CBC_CMAC_256 == oid {
            return "id-PACE-ECDH-CAM-AES-CBC-CMAC-256"
        }
        
        return oid
    }
}
