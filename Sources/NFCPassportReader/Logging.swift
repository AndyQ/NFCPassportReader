//
//  Logging.swift
//  NFCPassportReader
//

import Foundation

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
    /// Sensitive details are redacted from the handler unless this is enabled.
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

/// Receives library log and trace events.
public typealias PassportLogHandler = @Sendable (PassportLogEvent) -> Void

/// Contextual logger for one reader. The handler is the only output; with no handler nothing is formatted.
final class PassportLogger: @unchecked Sendable {
    /// Used for logs emitted outside a reader-scoped context, e.g. `NFCPassportModel(from:)`.
    static let shared = PassportLogger()

    private let lock = NSLock()
    private var nextId = 0
    private var currentSession = 0
    private var currentConfiguration = PassportLogConfiguration()
    private var currentHandler: PassportLogHandler?

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

    var handler: PassportLogHandler? {
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
        return currentHandler != nil
            && level >= currentConfiguration.minimumLevel
            && currentConfiguration.enabledComponents.contains(component)
    }

    /// Single entry point for log messages and protocol traces: filter, redact, then call the handler.
    func emit(
        kind: ReaderTraceKind,
        level: PassportLogLevel,
        component: PassportLogComponent,
        summary: () -> String,
        detail: () -> String? = { nil },
        wire: () -> [UInt8]? = { nil },
        plain: () -> [UInt8]? = { nil },
        sensitive: Bool = false,
        redactedMessage: String? = nil
    ) {
        lock.lock()
        guard let handler = currentHandler,
              level >= currentConfiguration.minimumLevel,
              currentConfiguration.enabledComponents.contains(component) else {
            lock.unlock()
            return
        }
        let configuration = currentConfiguration
        let id = nextId
        let session = currentSession
        nextId += 1
        lock.unlock()

        var title = summary()
        var detail = detail()
        var wire = wire().map(ReaderTracer.hex)
        var plain = plain().map(ReaderTracer.hex)

        if sensitive && !configuration.includeSensitiveDataInHandler {
            if detail == nil && wire == nil && plain == nil {
                title = redactedMessage ?? "Sensitive \(component.rawValue) log redacted"
            } else if detail != nil {
                // Structured entries keep their safe title visible while redacting the content.
                detail = redactedMessage ?? "Sensitive details redacted"
            }
            wire = nil
            plain = nil
        }

        handler(PassportLogEvent(
            id: id,
            timestamp: Date(),
            session: session,
            kind: kind,
            level: level,
            component: component,
            summary: title,
            wire: wire,
            plain: plain,
            detail: detail,
            isSensitive: sensitive
        ))
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
        log(.debug, message, content, sensitive, redactedMessage)
    }

    func info(
        _ message: @autoclosure () -> String,
        content: @autoclosure () -> String? = nil,
        sensitive: Bool = false,
        redactedMessage: String? = nil
    ) {
        log(.info, message, content, sensitive, redactedMessage)
    }

    func warning(
        _ message: @autoclosure () -> String,
        content: @autoclosure () -> String? = nil,
        sensitive: Bool = false,
        redactedMessage: String? = nil
    ) {
        log(.warning, message, content, sensitive, redactedMessage)
    }

    func error(
        _ message: @autoclosure () -> String,
        content: @autoclosure () -> String? = nil,
        sensitive: Bool = false,
        redactedMessage: String? = nil
    ) {
        log(.error, message, content, sensitive, redactedMessage)
    }

    func fault(
        _ message: @autoclosure () -> String,
        content: @autoclosure () -> String? = nil,
        sensitive: Bool = false,
        redactedMessage: String? = nil
    ) {
        log(.fault, message, content, sensitive, redactedMessage)
    }

    private func log(
        _ level: PassportLogLevel,
        _ message: () -> String,
        _ content: () -> String?,
        _ sensitive: Bool,
        _ redactedMessage: String?
    ) {
        PassportLogContext.current.emit(
            kind: level >= .error ? .error : .log,
            level: level,
            component: component,
            summary: message,
            detail: content,
            sensitive: sensitive,
            redactedMessage: redactedMessage
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
