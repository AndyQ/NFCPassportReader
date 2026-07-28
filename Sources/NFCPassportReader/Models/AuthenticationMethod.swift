//
//  AuthenticationMethod.swift
//  NFCPassportReader
//
//  Created by Prem Eide on 11/11/2024.
//

public enum AuthenticationMethod: CustomStringConvertible {
    case BAC
    case PACE

    public var description: String {
        switch self {
        case .BAC: return "BAC"
        case .PACE: return "PACE"
        }
    }
}
