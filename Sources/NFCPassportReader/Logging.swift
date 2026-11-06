//
//  Logging.swift
//  NFCPassportReader
//

import Foundation
import OSLog

public enum PassportLogLevel: Int, CaseIterable, Comparable, Codable, Sendable {
    case debug
    case info
    case warning
    case error
    case fault

    public static func < (lhs: PassportLogLevel, rhs: PassportLogLevel) -> Bool {
        lhs.rawValue < rhs.rawValue
    }
}

public enum PassportLogComponent: String, CaseIterable, Codable, Sendable {
    case passportReader
    case tagReader
    case secureMessaging
    case openSSL
    case bac = "BAC"
    case chipAuthentication
    case pace = "PACE"
}

public struct PassportLogConfiguration: Sendable {
    public var minimumLevel: PassportLogLevel
    public var enabledComponents: Set<PassportLogComponent>
    /// Sensitive details are always private in OSLog and are redacted from the handler by default.
    public var includeSensitiveDataInHandler: Bool

    public init(
        minimumLevel: PassportLogLevel = .info,
        enabledComponents: Set<PassportLogComponent> = Set(PassportLogComponent.allCases),
        includeSensitiveDataInHandler: Bool = false
    ) {
        self.minimumLevel = minimumLevel
        self.enabledComponents = enabledComponents
        self.includeSensitiveDataInHandler = includeSensitiveDataInHandler
    }
}

/// One structured event delivered to the configured logging handler.
public struct PassportLogEvent: Codable, Identifiable, Sendable {
    public let id: Int
    public let timestamp: Date
    public let session: Int
    public let kind: ReaderTraceKind
    public let level: PassportLogLevel
    public let component: PassportLogComponent
    /// Main/title text shown in the trace list.
    public let summary: String
    public let wire: String?
    public let plain: String?
    /// Optional expanded content for a log event or protocol trace.
    public let detail: String?
    public let isSensitive: Bool
}

/// Contextual logger for one reader. OSLog remains the default sink; a handler can observe the
/// same filtered events for a UI trace or application-specific logging.
final class PassportLogger {
    private static let subsystem = Bundle.main.bundleIdentifier ?? "NFCPassportReader"
    private static let passportReaderOSLog = Logger(subsystem: subsystem, category: "passportReader")
    private static let tagReaderOSLog = Logger(subsystem: subsystem, category: "tagReader")
    private static let secureMessagingOSLog = Logger(subsystem: subsystem, category: "secureMessaging")
    private static let openSSLOSLog = Logger(subsystem: subsystem, category: "openSSL")
    private static let bacOSLog = Logger(subsystem: subsystem, category: "BAC")
    private static let chipAuthenticationOSLog = Logger(subsystem: subsystem, category: "chipAuthentication")
    private static let paceOSLog = Logger(subsystem: subsystem, category: "PACE")
    static let shared = PassportLogger()

    private let lock = NSLock()
    private var nextId = 0
    private var currentSession = 0
    private var currentConfiguration = PassportLogConfiguration()
    private var currentHandler: ((PassportLogEvent) -> Void)?

    var session: Int {
        lock.lock()
        defer { lock.unlock() }
        return currentSession
    }

    var configuration: PassportLogConfiguration {
        get {
            lock.lock()
            defer { lock.unlock() }
            return currentConfiguration
        }
        set {
            lock.lock()
            currentConfiguration = newValue
            lock.unlock()
        }
    }

    var handler: ((PassportLogEvent) -> Void)? {
        get {
            lock.lock()
            defer { lock.unlock() }
            return currentHandler
        }
        set {
            lock.lock()
            currentHandler = newValue
            lock.unlock()
        }
    }

    func startSession() {
        lock.lock()
        currentSession += 1
        lock.unlock()
    }

    func isEnabled(_ level: PassportLogLevel, component: PassportLogComponent) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return level >= currentConfiguration.minimumLevel && currentConfiguration.enabledComponents.contains(component)
    }

    func log(
        _ level: PassportLogLevel,
        component: PassportLogComponent,
        message: () -> String,
        content: () -> String? = { nil },
        sensitive: Bool = false,
        redactedMessage: String? = nil
    ) {
        lock.lock()
        let configuration = currentConfiguration
        let handler = currentHandler
        guard level >= configuration.minimumLevel, configuration.enabledComponents.contains(component) else {
            lock.unlock()
            return
        }
        let id = nextId
        let session = currentSession
        nextId += 1
        lock.unlock()

        let title = message()
        let detail = content()
        logToOSLog(title, content: detail, level: level, component: component, sensitive: sensitive)

        guard let handler else { return }
        let visibleTitle: String
        let visibleDetail: String?
        if sensitive && !configuration.includeSensitiveDataInHandler {
            if detail == nil {
                visibleTitle = redactedMessage ?? "Sensitive \(component.rawValue) log redacted"
                visibleDetail = nil
            } else {
                // Structured entries keep their safe title visible while redacting the content.
                visibleTitle = title
                visibleDetail = redactedMessage ?? "Sensitive details redacted"
            }
        } else {
            visibleTitle = title
            visibleDetail = detail
        }
        handler(PassportLogEvent(
            id: id,
            timestamp: Date(),
            session: session,
            kind: level == .error || level == .fault ? .error : .log,
            level: level,
            component: component,
            summary: visibleTitle,
            wire: nil,
            plain: nil,
            detail: visibleDetail,
            isSensitive: sensitive
        ))
    }

    func emitTrace(
        _ kind: ReaderTraceKind,
        component: PassportLogComponent,
        _ summary: String,
        wire: [UInt8]? = nil,
        plain: [UInt8]? = nil,
        detail: String? = nil,
        sensitive: Bool = false
    ) {
        let level: PassportLogLevel
        switch kind {
            case .error: level = .error
            case .command, .response: level = .info
            case .info, .log: level = .info
        }

        lock.lock()
        let configuration = currentConfiguration
        let handler = currentHandler
        guard level >= configuration.minimumLevel, configuration.enabledComponents.contains(component) else {
            lock.unlock()
            return
        }
        let id = nextId
        let session = currentSession
        nextId += 1
        lock.unlock()

        if kind != .command && kind != .response {
            logToOSLog(summary, content: nil, level: level, component: component, sensitive: sensitive)
        }

        let includeSensitive = !sensitive || configuration.includeSensitiveDataInHandler
        let event = PassportLogEvent(
            id: id,
            timestamp: Date(),
            session: session,
            kind: kind,
            level: level,
            component: component,
            summary: summary,
            wire: includeSensitive ? wire.map(ReaderTracer.hex) : nil,
            plain: includeSensitive ? plain.map(ReaderTracer.hex) : nil,
            detail: includeSensitive ? detail : nil,
            isSensitive: sensitive
        )
        handler?(event)
    }

    private func logToOSLog(
        _ message: String,
        content: String?,
        level: PassportLogLevel,
        component: PassportLogComponent,
        sensitive: Bool
    ) {
        let logger: Logger
        switch component {
            case .passportReader: logger = Self.passportReaderOSLog
            case .tagReader: logger = Self.tagReaderOSLog
            case .secureMessaging: logger = Self.secureMessagingOSLog
            case .openSSL: logger = Self.openSSLOSLog
            case .bac: logger = Self.bacOSLog
            case .chipAuthentication: logger = Self.chipAuthenticationOSLog
            case .pace: logger = Self.paceOSLog
        }
        if sensitive, let content = content {
            switch level {
                case .debug: logger.debug("\(message, privacy: .public)\n\(content, privacy: .private)")
                case .info: logger.info("\(message, privacy: .public)\n\(content, privacy: .private)")
                case .warning: logger.warning("\(message, privacy: .public)\n\(content, privacy: .private)")
                case .error: logger.error("\(message, privacy: .public)\n\(content, privacy: .private)")
                case .fault: logger.fault("\(message, privacy: .public)\n\(content, privacy: .private)")
            }
            return
        }
        let osLogMessage = content.map { "\(message)\n\($0)" } ?? message
        switch (level, sensitive) {
            case (.debug, true): logger.debug("\(osLogMessage, privacy: .private)")
            case (.info, true): logger.info("\(osLogMessage, privacy: .private)")
            case (.warning, true): logger.warning("\(osLogMessage, privacy: .private)")
            case (.error, true): logger.error("\(osLogMessage, privacy: .private)")
            case (.fault, true): logger.fault("\(osLogMessage, privacy: .private)")
            case (.debug, false): logger.debug("\(osLogMessage, privacy: .public)")
            case (.info, false): logger.info("\(osLogMessage, privacy: .public)")
            case (.warning, false): logger.warning("\(osLogMessage, privacy: .public)")
            case (.error, false): logger.error("\(osLogMessage, privacy: .public)")
            case (.fault, false): logger.fault("\(osLogMessage, privacy: .public)")
        }
    }
}

private enum PassportLogContext {
    @TaskLocal static var current = PassportLogger.shared
}

enum PassportLog {
    static let passportReader = PassportLogCategory(component: .passportReader)
    static let tagReader = PassportLogCategory(component: .tagReader)
    static let secureMessaging = PassportLogCategory(component: .secureMessaging)
    static let openSSL = PassportLogCategory(component: .openSSL)
    static let bac = PassportLogCategory(component: .bac)
    static let chipAuth = PassportLogCategory(component: .chipAuthentication)
    static let pace = PassportLogCategory(component: .pace)
}

struct PassportLogCategory {
    let component: PassportLogComponent

    var isDebugEnabled: Bool {
        PassportLogContext.current.isEnabled(.debug, component: component)
    }

    func debug(
        _ message: @autoclosure () -> String,
        content: @autoclosure () -> String? = nil,
        sensitive: Bool = false,
        redactedMessage: String? = nil
    ) {
        PassportLogContext.current.log(
            .debug, component: component, message: message, content: content,
            sensitive: sensitive, redactedMessage: redactedMessage
        )
    }

    func info(
        _ message: @autoclosure () -> String,
        content: @autoclosure () -> String? = nil,
        sensitive: Bool = false,
        redactedMessage: String? = nil
    ) {
        PassportLogContext.current.log(
            .info, component: component, message: message, content: content,
            sensitive: sensitive, redactedMessage: redactedMessage
        )
    }

    func warning(
        _ message: @autoclosure () -> String,
        content: @autoclosure () -> String? = nil,
        sensitive: Bool = false,
        redactedMessage: String? = nil
    ) {
        PassportLogContext.current.log(
            .warning, component: component, message: message, content: content,
            sensitive: sensitive, redactedMessage: redactedMessage
        )
    }

    func error(
        _ message: @autoclosure () -> String,
        content: @autoclosure () -> String? = nil,
        sensitive: Bool = false,
        redactedMessage: String? = nil
    ) {
        PassportLogContext.current.log(
            .error, component: component, message: message, content: content,
            sensitive: sensitive, redactedMessage: redactedMessage
        )
    }

    func fault(
        _ message: @autoclosure () -> String,
        content: @autoclosure () -> String? = nil,
        sensitive: Bool = false,
        redactedMessage: String? = nil
    ) {
        PassportLogContext.current.log(
            .fault, component: component, message: message, content: content,
            sensitive: sensitive, redactedMessage: redactedMessage
        )
    }
}

extension PassportLogger {
    static func withCurrent<T>(_ logger: PassportLogger, operation: () throws -> T) rethrows -> T {
        try PassportLogContext.$current.withValue(logger, operation: operation)
    }

    static func withCurrent<T>(_ logger: PassportLogger, operation: () async throws -> T) async rethrows -> T {
        try await PassportLogContext.$current.withValue(logger, operation: operation)
    }
}
