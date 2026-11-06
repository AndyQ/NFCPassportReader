import XCTest
import CoreNFC
@testable import NFCPassportReader

/// Collects events from a `@Sendable` handler.
private final class EventRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [PassportLogEvent] = []

    var events: [PassportLogEvent] {
        lock.lock()
        defer { lock.unlock() }
        return storage
    }

    var last: PassportLogEvent? { events.last }

    lazy var handler: PassportLogHandler = { [unowned self] event in
        self.lock.lock()
        self.storage.append(event)
        self.lock.unlock()
    }
}

final class PassportLoggingTests: XCTestCase {

    private func log(
        _ logger: PassportLogger,
        level: PassportLogLevel = .debug,
        component: PassportLogComponent = .pace,
        _ message: @autoclosure () -> String,
        content: @autoclosure () -> String? = nil,
        sensitive: Bool = false,
        redactedMessage: String? = nil
    ) {
        PassportLogger.withCurrent(logger) {
            let category = PassportLogCategory(component: component)
            switch level {
                case .debug: category.debug(message(), content: content(), sensitive: sensitive, redactedMessage: redactedMessage)
                case .info: category.info(message(), content: content(), sensitive: sensitive, redactedMessage: redactedMessage)
                case .warning: category.warning(message(), content: content(), sensitive: sensitive, redactedMessage: redactedMessage)
                case .error: category.error(message(), content: content(), sensitive: sensitive, redactedMessage: redactedMessage)
                case .fault: category.fault(message(), content: content(), sensitive: sensitive, redactedMessage: redactedMessage)
            }
        }
    }

    func testSensitiveLogIsRedactedFromHandlerByDefault() {
        let logger = PassportLogger()
        logger.configuration = PassportLogConfiguration(minimumLevel: .debug)
        let recorder = EventRecorder()
        logger.handler = recorder.handler

        log(logger, "KSenc=secret", sensitive: true, redactedMessage: "PACE key derived")

        XCTAssertEqual(recorder.last?.summary, "PACE key derived")
        XCTAssertEqual(recorder.last?.component, .pace)
        XCTAssertEqual(recorder.last?.level, .debug)
        XCTAssertEqual(recorder.last?.kind, .log)
        XCTAssertTrue(recorder.last?.isSensitive == true)
    }

    func testSensitiveLogCanBeEnabledForHandler() {
        let logger = PassportLogger()
        logger.configuration = PassportLogConfiguration(minimumLevel: .debug, includeSensitiveDataInHandler: true)
        let recorder = EventRecorder()
        logger.handler = recorder.handler

        log(logger, "KSenc=secret", sensitive: true)

        XCTAssertEqual(recorder.last?.summary, "KSenc=secret")
        XCTAssertTrue(recorder.last?.isSensitive == true)
    }

    func testLogContentBecomesTraceDetail() {
        let logger = PassportLogger()
        logger.configuration = PassportLogConfiguration(minimumLevel: .debug)
        let recorder = EventRecorder()
        logger.handler = recorder.handler

        log(logger, "PACE parameters", content: "OID=1.2.3\nmapping=IM")

        XCTAssertEqual(recorder.last?.summary, "PACE parameters")
        XCTAssertEqual(recorder.last?.detail, "OID=1.2.3\nmapping=IM")
    }

    func testSensitiveLogContentIsRedactedWithoutHidingTitle() {
        let logger = PassportLogger()
        logger.configuration = PassportLogConfiguration(minimumLevel: .debug)
        let recorder = EventRecorder()
        logger.handler = recorder.handler

        log(logger, "MRZ key", content: "secret credential", sensitive: true, redactedMessage: "PACE MRZ credential derived")

        XCTAssertEqual(recorder.last?.summary, "MRZ key")
        XCTAssertEqual(recorder.last?.detail, "PACE MRZ credential derived")
        XCTAssertTrue(recorder.last?.isSensitive == true)
    }

    func testErrorLevelLogsUseErrorKind() {
        let logger = PassportLogger()
        let recorder = EventRecorder()
        logger.handler = recorder.handler

        log(logger, level: .error, "failed")

        XCTAssertEqual(recorder.last?.kind, .error)
    }

    func testLevelAndComponentFiltersApplyBeforeFormatting() {
        let logger = PassportLogger()
        logger.configuration = PassportLogConfiguration(minimumLevel: .warning, enabledComponents: [.pace])
        logger.handler = { _ in XCTFail("Filtered events must not reach the handler") }
        var messageWasEvaluated = false

        log(logger, level: .debug, component: .pace, { messageWasEvaluated = true; return "debug" }())
        log(logger, level: .warning, component: .tagReader, { messageWasEvaluated = true; return "other component" }())

        XCTAssertFalse(messageWasEvaluated)
    }

    func testNoHandlerSkipsFormatting() {
        let logger = PassportLogger()
        logger.configuration = PassportLogConfiguration(minimumLevel: .debug)
        let tracer = ReaderTracer(logger: logger)
        var evaluated = false

        log(logger, { evaluated = true; return "message" }(), content: { evaluated = true; return "content" }())
        tracer.emit(.command, { evaluated = true; return "SELECT" }(), wire: { evaluated = true; return [0x00] }())

        XCTAssertFalse(evaluated)
        XCTAssertFalse(PassportLogger.withCurrent(logger) { PassportLog.pace.isDebugEnabled })
    }

    func testSensitiveTraceDetailsAreRedactedByDefault() {
        let logger = PassportLogger()
        logger.configuration = PassportLogConfiguration(minimumLevel: .debug)
        let recorder = EventRecorder()
        logger.handler = recorder.handler
        let tracer = ReaderTracer(logger: logger)

        tracer.emit(.response, "9000 OK", wire: [0xAA], plain: [0xBB], detail: "passport data",
                    component: .tagReader, sensitive: true)

        XCTAssertEqual(recorder.last?.summary, "9000 OK")
        XCTAssertNil(recorder.last?.wire)
        XCTAssertNil(recorder.last?.plain)
        XCTAssertEqual(recorder.last?.detail, "Sensitive details redacted")
        XCTAssertTrue(recorder.last?.isSensitive == true)
    }

    func testSensitiveTraceWireIsIncludedWhenEnabled() {
        let logger = PassportLogger()
        logger.configuration = PassportLogConfiguration(minimumLevel: .debug, includeSensitiveDataInHandler: true)
        let recorder = EventRecorder()
        logger.handler = recorder.handler
        let tracer = ReaderTracer(logger: logger)

        tracer.emit(.command, "SELECT", wire: [0x00, 0xA4], plain: [0x0C], component: .tagReader, sensitive: true)

        XCTAssertEqual(recorder.last?.summary, "SELECT")
        XCTAssertEqual(recorder.last?.wire, "00 A4")
        XCTAssertEqual(recorder.last?.plain, "0C")
    }

    func testAPDUTraceRespectsMinimumLevel() {
        let logger = PassportLogger()
        logger.configuration = PassportLogConfiguration(minimumLevel: .info)
        let recorder = EventRecorder()
        logger.handler = recorder.handler
        let tracer = ReaderTracer(logger: logger)

        tracer.emit(.command, "SELECT", wire: [0x00], component: .tagReader)
        tracer.emit(.response, "9000 OK", wire: [0x90, 0x00], component: .tagReader)
        tracer.emit(.info, "BAC started")
        tracer.emit(.command, "forced", component: .tagReader, level: .info)

        XCTAssertEqual(recorder.events.map(\.summary), ["BAC started", "forced"])
    }

    func testDefaultLogHandlerReceivesLogsOutsideARead() {
        let recorder = EventRecorder()
        let previousHandler = PassportReader.defaultLogHandler
        let previousConfiguration = PassportReader.defaultLogConfiguration
        defer {
            PassportReader.defaultLogHandler = previousHandler
            PassportReader.defaultLogConfiguration = previousConfiguration
        }
        PassportReader.defaultLogConfiguration = PassportLogConfiguration(minimumLevel: .debug)
        PassportReader.defaultLogHandler = recorder.handler

        PassportLog.passportReader.info("Outside a read")

        XCTAssertEqual(recorder.last?.summary, "Outside a read")
        XCTAssertEqual(recorder.last?.component, .passportReader)
    }

    func testReaderLogHandlerDoesNotReceiveDefaultLogs() {
        let reader = PassportReader()
        let readerRecorder = EventRecorder()
        reader.logHandler = readerRecorder.handler

        PassportLog.passportReader.info("Outside a read")

        XCTAssertTrue(readerRecorder.events.isEmpty)
    }

    func testSecureMessagingProtectEmitsOneGroupedTraceEvent() throws {
        let logger = PassportLogger()
        logger.configuration = PassportLogConfiguration(minimumLevel: .debug, includeSensitiveDataInHandler: true)
        let recorder = EventRecorder()
        logger.handler = recorder.handler

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

        let secureMessagingEvents = recorder.events.filter { $0.component == .secureMessaging }
        XCTAssertEqual(secureMessagingEvents.count, 1)
        XCTAssertEqual(secureMessagingEvents.first?.summary, "Protect secure-messaging command")
        XCTAssertTrue(secureMessagingEvents.first?.detail?.contains("N (MAC input)") == true)
        XCTAssertTrue(secureMessagingEvents.first?.detail?.contains("Protected APDU") == true)
    }

    func testCategoryLogsUseReaderScopedHandler() async {
        let logger = PassportLogger()
        let recorder = EventRecorder()
        logger.handler = recorder.handler

        await PassportLogger.withCurrent(logger) {
            PassportLog.pace.info("PACE started")
        }

        XCTAssertEqual(recorder.last?.component, .pace)
        XCTAssertEqual(recorder.last?.level, .info)
        XCTAssertEqual(recorder.last?.summary, "PACE started")
    }

    func testCombineFansOutToAllHandlers() {
        let first = EventRecorder()
        let second = EventRecorder()
        let logger = PassportLogger()
        logger.handler = PassportLogHandlers.combine(first.handler, second.handler)

        log(logger, level: .info, "hello")

        XCTAssertEqual(first.last?.summary, "hello")
        XCTAssertEqual(second.last?.summary, "hello")
    }

    func testOSLogHandlerAcceptsEvents() {
        let logger = PassportLogger()
        logger.configuration = PassportLogConfiguration(minimumLevel: .debug)
        logger.handler = PassportLogHandlers.osLog(subsystem: "NFCPassportReaderTests")

        log(logger, level: .debug, "plain")
        log(logger, level: .info, "with content", content: "detail")
        log(logger, level: .error, "sensitive", content: "secret", sensitive: true)
        ReaderTracer(logger: logger).emit(.command, "SELECT", wire: [0x00], component: .tagReader)
    }

    func testOSLogLevelMapping() {
        XCTAssertEqual(PassportLogHandlers.osLogType(for: .debug), .debug)
        XCTAssertEqual(PassportLogHandlers.osLogType(for: .info), .info)
        XCTAssertEqual(PassportLogHandlers.osLogType(for: .warning), .default)
        XCTAssertEqual(PassportLogHandlers.osLogType(for: .error), .error)
        XCTAssertEqual(PassportLogHandlers.osLogType(for: .fault), .fault)
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
