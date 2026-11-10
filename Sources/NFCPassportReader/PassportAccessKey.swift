//
//  PassportAccessKey.swift
//  NFCPassportReader
//

import Foundation

/// The password used to unlock the chip (ICAO 9303-11, 4.2 to 4.4).
///
/// - `mrz`: the MRZ information (document number, date of birth and date of expiry, each followed by its
///   check digit), as returned by `PassportUtils.getMRZKey`. Works with PACE and with BAC, so the reader can
///   fall back to BAC if PACE fails or isn't supported.
/// - `can`: the Card Access Number printed on the document (usually 6 digits). It can only be used with PACE,
///   and chips aren't required to accept it, so there is no BAC fallback.
public enum PassportAccessKey: Sendable, Equatable {
    case mrz(String)
    case can(String)

    /// The PACE password reference sent in DO'83' of MSE:Set AT.
    var paceKeyReference: UInt8 {
        switch self {
            case .mrz: return 0x01
            case .can: return 0x02
        }
    }

    /// "MRZ" or "CAN", for logs and traces.
    var passwordName: String {
        switch self {
            case .mrz: return "MRZ"
            case .can: return "CAN"
        }
    }

    /// The MRZ key, if this is one: the only password BAC can use.
    var mrzKey: String? {
        if case .mrz(let key) = self { return key }
        return nil
    }
}
