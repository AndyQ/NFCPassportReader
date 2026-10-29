//
//  ReaderTrace.swift
//  NFCPassportReader
//
//  An APDU-level trace of a passport read, for debugging readers and chips.
//

import Foundation

public enum ReaderTraceKind: String, Codable, Sendable {
    /// A command sent to the chip.
    case command
    /// The chip's response.
    case response
    /// A protocol milestone (BAC, PACE steps, CA, AA, data group reads).
    case info
    /// Something failed.
    case error
}

/// One trace entry. Hex strings are upper case, bytes separated by spaces.
public struct ReaderTraceEvent: Codable, Identifiable, Sendable {
    public let id: Int
    public let timestamp: Date
    /// Increments for every readPassport call.
    public let session: Int
    public let kind: ReaderTraceKind
    /// One line, for example "SELECT DG2", "READ BINARY DG2 offset=160 len=160" or "9000 OK (SM)".
    public let summary: String
    /// The bytes on the wire (secure messaging protected, if active).
    public let wire: String?
    /// The plain command or response, when secure messaging is active.
    public let plain: String?
    /// Extra information, such as PACE intermediate values or session keys.
    public let detail: String?
}

/// Numbers and forwards trace events. One per PassportReader; shared with the handlers it creates.
final class ReaderTracer {
    private let lock = NSLock()
    private var nextId = 0
    private(set) var session = 0
    var handler: ((ReaderTraceEvent) -> Void)?

    var isEnabled: Bool { handler != nil }

    func startSession() {
        lock.lock(); session += 1; lock.unlock()
    }

    func emit(_ kind: ReaderTraceKind, _ summary: String, wire: [UInt8]? = nil, plain: [UInt8]? = nil, detail: String? = nil) {
        guard let handler = handler else { return }
        lock.lock()
        let event = ReaderTraceEvent(
            id: nextId, timestamp: Date(), session: session, kind: kind, summary: summary,
            wire: wire.map { ReaderTracer.hex($0) }, plain: plain.map { ReaderTracer.hex($0) }, detail: detail
        )
        nextId += 1
        lock.unlock()
        handler(event)
    }

    static func hex(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02X", $0) }.joined(separator: " ")
    }

    /// eMRTD file names for SELECT / READ BINARY summaries.
    static func fileName(_ fid: [UInt8]) -> String {
        guard fid.count == 2 else { return binToHexRep(fid) }
        switch (fid[0], fid[1]) {
            case (0x3F, 0x00): return "MF"
            case (0x01, 0x1C): return "EF.CardAccess"
            case (0x01, 0x1D): return "EF.SOD"
            case (0x01, 0x1E): return "EF.COM"
            case (0x01, 0x01...0x10): return "DG\(fid[1])"
            default: return "EF " + binToHexRep(fid)
        }
    }

    /// Short description of a status word, e.g. "9000 OK" or "6A82 File not found".
    static func describe(sw1: UInt8, sw2: UInt8) -> String {
        let sw = String(format: "%02X%02X", sw1, sw2)
        switch (sw1, sw2) {
            case (0x90, 0x00): return "\(sw) OK"
            case (0x61, _): return "\(sw) \(sw2 == 0 ? "256+" : "\(sw2)") bytes remaining"
            case (0x62, 0x82): return "\(sw) End of file"
            case (0x63, 0x00): return "\(sw) Authentication failed"
            case (0x67, 0x00): return "\(sw) Wrong length"
            case (0x69, 0x82): return "\(sw) Security status not satisfied"
            case (0x69, 0x85): return "\(sw) Conditions of use not satisfied"
            case (0x69, 0x86): return "\(sw) Command not allowed (no EF)"
            case (0x69, 0x87): return "\(sw) SM data objects missing"
            case (0x69, 0x88): return "\(sw) SM data objects incorrect"
            case (0x6A, 0x80): return "\(sw) Wrong data"
            case (0x6A, 0x82): return "\(sw) File not found"
            case (0x6A, 0x86): return "\(sw) Incorrect P1/P2"
            case (0x6A, 0x88): return "\(sw) Referenced data not found"
            case (0x6B, 0x00): return "\(sw) Wrong P1/P2"
            case (0x6D, 0x00): return "\(sw) INS not supported"
            case (0x6E, 0x00): return "\(sw) CLA not supported"
            default: return sw
        }
    }
}
