import XCTest
import CoreNFC
@testable import NFCPassportReader

final class PassportLoggingTests: XCTestCase {

    func testSensitiveLogIsRedactedFromHandlerByDefault() {
        let logger = PassportLogger()
        logger.configuration = PassportLogConfiguration(minimumLevel: .debug)
        var received: PassportLogEvent?
        logger.handler = { received = $0 }

        logger.log(.debug, component: .pace, message: { "KSenc=secret" }, sensitive: true, redactedMessage: "PACE key derived")

        XCTAssertEqual(received?.summary, "PACE key derived")
        XCTAssertEqual(received?.component, .pace)
        XCTAssertEqual(received?.level, .debug)
        XCTAssertTrue(received?.isSensitive == true)
    }

    func testSensitiveLogCanBeEnabledForHandler() {
        let logger = PassportLogger()
        logger.configuration = PassportLogConfiguration(minimumLevel: .debug, includeSensitiveDataInHandler: true)
        var received: PassportLogEvent?
        logger.handler = { received = $0 }

        logger.log(.debug, component: .pace, message: { "KSenc=secret" }, sensitive: true)

        XCTAssertEqual(received?.summary, "KSenc=secret")
        XCTAssertTrue(received?.isSensitive == true)
    }

    func testLogContentBecomesTraceDetail() {
        let logger = PassportLogger()
        logger.configuration = PassportLogConfiguration(minimumLevel: .debug)
        var received: PassportLogEvent?
        logger.handler = { received = $0 }

        logger.log(
            .debug,
            component: .pace,
            message: { "PACE parameters" },
            content: { "OID=1.2.3\nmapping=IM" }
        )

        XCTAssertEqual(received?.summary, "PACE parameters")
        XCTAssertEqual(received?.detail, "OID=1.2.3\nmapping=IM")
    }

    func testSensitiveLogContentIsRedactedWithoutHidingTitle() {
        let logger = PassportLogger()
        logger.configuration = PassportLogConfiguration(minimumLevel: .debug)
        var received: PassportLogEvent?
        logger.handler = { received = $0 }

        logger.log(
            .debug,
            component: .pace,
            message: { "MRZ key" },
            content: { "secret credential" },
            sensitive: true,
            redactedMessage: "PACE MRZ credential derived"
        )

        XCTAssertEqual(received?.summary, "MRZ key")
        XCTAssertEqual(received?.detail, "PACE MRZ credential derived")
        XCTAssertTrue(received?.isSensitive == true)
    }

    func testLevelAndComponentFiltersApplyBeforeFormatting() {
        let logger = PassportLogger()
        logger.configuration = PassportLogConfiguration(minimumLevel: .warning, enabledComponents: [.pace])
        logger.handler = { _ in XCTFail("Filtered events must not reach the handler") }
        var messageWasEvaluated = false

        logger.log(.debug, component: .pace, message: {
            messageWasEvaluated = true
            return "debug"
        })
        logger.log(.warning, component: .tagReader, message: {
            messageWasEvaluated = true
            return "other component"
        })

        XCTAssertFalse(messageWasEvaluated)
    }

    func testSensitiveTraceDetailsAreRedactedByDefault() {
        let logger = PassportLogger()
        var received: PassportLogEvent?
        logger.handler = { received = $0 }

        logger.emitTrace(
            .response,
            component: .tagReader,
            "9000 OK",
            wire: [0xAA],
            plain: [0xBB],
            detail: "passport data",
            sensitive: true
        )

        XCTAssertEqual(received?.summary, "9000 OK")
        XCTAssertNil(received?.wire)
        XCTAssertNil(received?.plain)
        XCTAssertNil(received?.detail)
        XCTAssertTrue(received?.isSensitive == true)
    }

    func testSecureMessagingProtectEmitsOneGroupedTraceEvent() throws {
        let logger = PassportLogger()
        logger.configuration = PassportLogConfiguration(minimumLevel: .debug, includeSensitiveDataInHandler: true)
        var received: [PassportLogEvent] = []
        logger.handler = { received.append($0) }

        let secureMessaging = SecureMessaging(
            ksenc: [UInt8](repeating: 0x11, count: 16),
            ksmac: [UInt8](repeating: 0x22, count: 16),
            ssc: [UInt8](repeating: 0, count: 8)
        )
        let apdu = NFCISO7816APDU(
            instructionClass: 0,
            instructionCode: 0xA4,
            p1Parameter: 0x02,
            p2Parameter: 0x0C,
            data: Data([0x01, 0x02]),
            expectedResponseLength: 256
        )

        try PassportLogger.withCurrent(logger) {
            _ = try secureMessaging.protect(apdu: apdu)
        }

        let secureMessagingEvents = received.filter { $0.component == .secureMessaging }
        XCTAssertEqual(secureMessagingEvents.count, 1)
        XCTAssertEqual(secureMessagingEvents.first?.summary, "Protect secure-messaging command")
        XCTAssertTrue(secureMessagingEvents.first?.detail?.contains("N (MAC input)") == true)
        XCTAssertTrue(secureMessagingEvents.first?.detail?.contains("Protected APDU") == true)
    }

    func testCategoryLogsUseReaderScopedHandler() async {
        let logger = PassportLogger()
        var received: PassportLogEvent?
        logger.handler = { received = $0 }

        await PassportLogger.withCurrent(logger) {
            PassportLog.pace.info("PACE started")
        }

        XCTAssertEqual(received?.component, .pace)
        XCTAssertEqual(received?.level, .info)
        XCTAssertEqual(received?.summary, "PACE started")
    }

    func testOSLogCategoryNamesRemainStable() {
        XCTAssertEqual(PassportLogComponent.passportReader.rawValue, "passportReader")
        XCTAssertEqual(PassportLogComponent.tagReader.rawValue, "tagReader")
        XCTAssertEqual(PassportLogComponent.secureMessaging.rawValue, "secureMessaging")
        XCTAssertEqual(PassportLogComponent.openSSL.rawValue, "openSSL")
        XCTAssertEqual(PassportLogComponent.bac.rawValue, "BAC")
        XCTAssertEqual(PassportLogComponent.chipAuthentication.rawValue, "chipAuthentication")
        XCTAssertEqual(PassportLogComponent.pace.rawValue, "PACE")
    }
}
