//
//  PACELiveSimulatorTests.swift
//  NFCPassportReaderTests
//
//  End-to-end PACE (GM and IM), Chip Authentication and secure messaging against the PassportSim
//  chip simulator over TCP, using the real TagReader / PACEHandler code paths.
//
//  Skipped unless PASSPORTSIM_PORT is set. To run:
//    (PassportSim)        ./gradlew :tools:apduServer
//    (NFCPassportReader)  TEST_RUNNER_PASSPORTSIM_PORT=9077 xcodebuild test -scheme NFCPassportReader \
//                           -destination 'platform=iOS Simulator,name=iPhone 17' \
//                           -only-testing:NFCPassportReaderTests/PACELiveSimulatorTests
//

import XCTest
import CoreNFC

@testable import NFCPassportReader

final class PACELiveSimulatorTests: XCTestCase {

    private func connect(preset: String) throws -> (SocketISO7816Tag, String) {
        guard let port = ProcessInfo.processInfo.environment["PASSPORTSIM_PORT"].flatMap({ UInt16($0) }) else {
            throw XCTSkip("Set PASSPORTSIM_PORT (TEST_RUNNER_PASSPORTSIM_PORT for xcodebuild) and run PassportSim's apduServer")
        }
        let host = ProcessInfo.processInfo.environment["PASSPORTSIM_HOST"] ?? "127.0.0.1"
        let tag = try SocketISO7816Tag(host: host, port: port)
        let mrzKey = try tag.selectProfile(preset)
        return (tag, mrzKey)
    }

    /// Mirrors PassportReader.startReading: CardAccess, PACE, re-select the applet, then read under PACE SM.
    private func readWithPACE(preset: String, mrzKey override: String? = nil) async throws -> (TagReader, String) {
        let (tag, mrzKey) = try connect(preset: preset)
        let tagReader = TagReader(tag: tag)
        let cardAccess = try CardAccess(try await tagReader.readCardAccess())
        let pace = try PACEHandler(cardAccess: cardAccess, tagReader: tagReader)
        try await pace.doPACE(mrzKey: override ?? mrzKey)
        _ = try await tagReader.selectPassportApplication()
        XCTAssertNotNil(tagReader.secureMessaging, "\(preset): PACE should start secure messaging")

        let com = try await tagReader.readDataGroup(dataGroup: .COM)
        XCTAssertEqual(com.first, 0x60, "\(preset): EF.COM")
        let dg1 = try DataGroupParser().parseDG(data: try await tagReader.readDataGroup(dataGroup: .DG1)) as! DataGroup1
        let documentNumber = (dg1.elements["5A"] ?? "").replacingOccurrences(of: "<", with: "")
        XCTAssertFalse(documentNumber.isEmpty, "\(preset): DG1 document number")
        return (tagReader, documentNumber)
    }

    func testPACEIntegratedMapping() async throws {
        for preset in ["pace-im", "pace-im-3des", "pace-im-aes256"] {
            _ = try await readWithPACE(preset: preset)
        }
    }

    func testPACEGenericMapping() async throws {
        for preset in ["pace-gm", "pace-gm-3des", "pace-gm-aes256"] {
            _ = try await readWithPACE(preset: preset)
        }
    }

    func testPACEIntegratedMappingWithWrongMRZKeyFails() async throws {
        do {
            _ = try await readWithPACE(preset: "pace-im", mrzKey: "L898902C<369080619406236")
            XCTFail("PACE should fail with the wrong MRZ key")
        } catch let error as XCTSkip {
            throw error
        } catch {
            // Expected: the chip rejects T_PCD (6300) and the token check fails
        }
    }

    /// PACE followed by Chip Authentication (ECDH, AES-128) and Active Authentication's DG15 read.
    func testPACEThenChipAuthentication() async throws {
        let (tagReader, _) = try await readWithPACE(preset: "pace-full")
        let dg14 = try DataGroupParser().parseDG(data: try await tagReader.readDataGroup(dataGroup: .DG14)) as! DataGroup14
        let ca = ChipAuthenticationHandler(dg14: dg14, tagReader: tagReader)
        XCTAssertTrue(ca.isChipAuthenticationSupported)
        try await ca.doChipAuthentication()
        // Reading under the new CA keys proves both sides switched to the same AES session keys.
        let dg1 = try await tagReader.readDataGroup(dataGroup: .DG1)
        XCTAssertEqual(dg1.first, 0x61)
        _ = try await tagReader.readDataGroup(dataGroup: .DG15)
    }

    /// Full PassportReader flow: CA status as reported to the app.
    private func readPassport(preset: String) async throws -> NFCPassportModel {
        let (tag, mrzKey) = try connect(preset: preset)
        return try await PassportReader().readPassport(tag: tag, mrzKey: mrzKey)
    }

    func testChipAuthenticationReportedAsSuccess() async throws {
        for preset in ["full", "bac-ca-aes", "pace-full"] {
            let passport = try await readPassport(preset: preset)
            XCTAssertEqual(passport.chipAuthenticationStatus, .success, preset)
        }
    }

    /// The chip accepts MSE:Set KAT but derives its keys from a corrupted shared secret, so the first
    /// command under the new keys fails its MAC check (6988). CA must be reported as failed, and the
    /// reader should fall back to BAC and still read the passport.
    func testChipAuthenticationWithWrongChipSecretIsReportedAsFailed() async throws {
        let passport = try await readPassport(preset: "neg-ca-wrong-secret")
        XCTAssertEqual(passport.chipAuthenticationStatus, .failed)
        XCTAssertEqual(passport.BACStatus, .success)
        XCTAssertFalse(passport.documentNumber.isEmpty)
    }

    /// The chip rejects MSE:Set KAT outright (6A80); already reported as failed before this fix.
    func testChipAuthenticationRejectedIsReportedAsFailed() async throws {
        let passport = try await readPassport(preset: "neg-ca-rejected")
        XCTAssertEqual(passport.chipAuthenticationStatus, .failed)
        XCTAssertFalse(passport.documentNumber.isEmpty)
    }
}

// MARK: - A CoreNFC ISO 7816 tag backed by a TCP connection to PassportSim's apduServer

/// Frames: 4-byte big-endian length + payload. Each connection is one card session.
final class SocketISO7816Tag: NSObject, NFCISO7816Tag {
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
            throw XCTSkip("PassportSim apduServer not reachable on \(host):\(port)")
        }
        fd = sock
        super.init()
    }

    deinit { close(fd) }

    /// Chooses the PassportSim preset for this session and returns its MRZ key.
    func selectProfile(_ preset: String) throws -> String {
        let reply = String(decoding: try exchange([UInt8]("PROFILE \(preset)".utf8)), as: UTF8.self)
        guard reply.hasPrefix("OK ") else { throw NFCPassportReaderError.UnexpectedError }
        return String(reply.dropFirst(3))
    }

    private func exchange(_ payload: [UInt8]) throws -> [UInt8] {
        try write(withUnsafeBytes(of: UInt32(payload.count).bigEndian, Array.init) + payload)
        let header = try read(4)
        let length = header.reduce(0) { ($0 << 8) | Int($1) }
        return try read(length)
    }

    private func write(_ bytes: [UInt8]) throws {
        var sent = 0
        while sent < bytes.count {
            let n = bytes[sent...].withUnsafeBytes { Darwin.write(fd, $0.baseAddress, $0.count) }
            guard n > 0 else { throw NFCPassportReaderError.ConnectionError }
            sent += n
        }
    }

    private func read(_ count: Int) throws -> [UInt8] {
        var out = [UInt8](repeating: 0, count: count)
        var got = 0
        while got < count {
            let n = out[got...].withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress, $0.count) }
            guard n > 0 else { throw NFCPassportReaderError.ConnectionError }
            got += n
        }
        return out
    }

    /// ISO 7816-4 encoding, short or extended as needed (expectedResponseLength -1 means no Le).
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
                guard response.count >= 2 else { throw NFCPassportReaderError.ResponseError("Short response", 0, 0) }
                completionHandler(Data(response.dropLast(2)), response[response.count - 2], response[response.count - 1], nil)
            } catch {
                completionHandler(Data(), 0x6F, 0x00, error)
            }
        }
    }

    // MARK: Remaining NFCISO7816Tag / NFCTag / NFCNDEFTag requirements (unused by TagReader)

    var initialSelectedAID: String { "A0000002471001" }
    var identifier: Data { Data([0x08, 0x01, 0x02, 0x03]) }
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
