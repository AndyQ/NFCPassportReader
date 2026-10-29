//
//  PassportSimTag.swift
//  NFCPassportReaderApp
//
//  An NFCISO7816Tag backed by a TCP connection to PassportSim's APDU server
//  (`./gradlew :tools:apduServer`), so the reader can be exercised in the iOS simulator without NFC.
//  Frames: 4-byte big-endian length + payload. Each connection is one card session.
//

import Foundation
import CoreNFC

final class PassportSimTag: NSObject, NFCISO7816Tag {
    enum SimError: LocalizedError {
        case connectFailed(String)
        case connectionClosed
        case profileRejected(String)

        var errorDescription: String? {
            switch self {
                case .connectFailed(let target): return "Couldn't connect to PassportSim at \(target). Is `./gradlew :tools:apduServer` running?"
                case .connectionClosed: return "PassportSim closed the connection"
                case .profileRejected(let reason): return "PassportSim: \(reason)"
            }
        }
    }

    private let fd: Int32

    init(host: String, port: UInt16) throws {
        let sock = socket(AF_INET, SOCK_STREAM, 0)
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        inet_pton(AF_INET, host, &addr.sin_addr)
        let result = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(sock, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        guard result == 0 else {
            close(sock)
            throw SimError.connectFailed("\(host):\(port)")
        }
        fd = sock
        super.init()
    }

    deinit { close(fd) }

    /// Chooses the PassportSim preset for this session and returns its MRZ key.
    func selectProfile(_ preset: String) throws -> String {
        let reply = String(decoding: try exchange([UInt8]("PROFILE \(preset)".utf8)), as: UTF8.self)
        guard reply.hasPrefix("OK ") else { throw SimError.profileRejected(reply) }
        return String(reply.dropFirst(3))
    }

    private func exchange(_ payload: [UInt8]) throws -> [UInt8] {
        try write(withUnsafeBytes(of: UInt32(payload.count).bigEndian, Array.init) + payload)
        let header = try read(4)
        return try read(header.reduce(0) { ($0 << 8) | Int($1) })
    }

    private func write(_ bytes: [UInt8]) throws {
        var sent = 0
        while sent < bytes.count {
            let n = bytes[sent...].withUnsafeBytes { Darwin.write(fd, $0.baseAddress, $0.count) }
            guard n > 0 else { throw SimError.connectionClosed }
            sent += n
        }
    }

    private func read(_ count: Int) throws -> [UInt8] {
        var out = [UInt8](repeating: 0, count: count)
        var got = 0
        while got < count {
            let n = out[got...].withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress, $0.count) }
            guard n > 0 else { throw SimError.connectionClosed }
            got += n
        }
        return out
    }

    private static func encode(_ apdu: NFCISO7816APDU) -> [UInt8] {
        let data = [UInt8](apdu.data ?? Data())
        let le = apdu.expectedResponseLength
        var out: [UInt8] = [apdu.instructionClass, apdu.instructionCode, apdu.p1Parameter, apdu.p2Parameter]
        let extended = data.count > 255 || le > 256
        if !data.isEmpty {
            out += extended ? [0x00, UInt8(data.count >> 8), UInt8(data.count & 0xFF)] : [UInt8(data.count)]
            out += data
        }
        if le > 0 {
            if extended {
                if data.isEmpty { out.append(0x00) }
                let v = le >= 65536 ? 0 : le
                out += [UInt8((v >> 8) & 0xFF), UInt8(v & 0xFF)]
            } else {
                out.append(le >= 256 ? 0x00 : UInt8(le))
            }
        }
        return out
    }

    func sendCommand(apdu: NFCISO7816APDU, completionHandler: @escaping (Data, UInt8, UInt8, Error?) -> Void) {
        DispatchQueue.global().async {
            do {
                let response = try self.exchange(Self.encode(apdu))
                guard response.count >= 2 else { throw SimError.connectionClosed }
                completionHandler(Data(response.dropLast(2)), response[response.count - 2], response[response.count - 1], nil)
            } catch {
                completionHandler(Data(), 0x6F, 0x00, error)
            }
        }
    }

    // Remaining NFCISO7816Tag / NFCTag / NFCNDEFTag requirements, unused by the reader.
    var initialSelectedAID: String { "A0000002471001" }
    var identifier: Data { Data([0x08, 0x50, 0x53, 0x4D]) }
    var historicalBytes: Data? { nil }
    var applicationData: Data? { nil }
    var proprietaryApplicationDataCoding: Bool { false }
    var supportsPACE: Bool { false }
    var type: __NFCTagType { .iso7816Compatible }
    weak var session: NFCReaderSessionProtocol? { nil }
    var isAvailable: Bool { true }
    func asNFCISO15693Tag() -> NFCISO15693Tag? { nil }
    func asNFCISO7816Tag() -> NFCISO7816Tag? { self }
    func asNFCFeliCaTag() -> NFCFeliCaTag? { nil }
    func asNFCMiFareTag() -> NFCMiFareTag? { nil }
    func queryNDEFStatus(completionHandler: @escaping (NFCNDEFStatus, Int, Error?) -> Void) { completionHandler(.notSupported, 0, nil) }
    func readNDEF(completionHandler: @escaping (NFCNDEFMessage?, Error?) -> Void) { completionHandler(nil, nil) }
    func writeNDEF(_ ndefMessage: NFCNDEFMessage, completionHandler: @escaping (Error?) -> Void) { completionHandler(nil) }
    func writeLock(completionHandler: @escaping (Error?) -> Void) { completionHandler(nil) }
    static var supportsSecureCoding: Bool { false }
    func encode(with coder: NSCoder) {}
    required init?(coder: NSCoder) { nil }
    func copy(with zone: NSZone? = nil) -> Any { self }
}
