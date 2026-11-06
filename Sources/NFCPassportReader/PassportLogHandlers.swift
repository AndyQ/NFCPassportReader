//
//  PassportLogHandlers.swift
//  NFCPassportReader
//

import Foundation
import OSLog

/// Ready-made handlers for `PassportReader.logHandler`.
public enum PassportLogHandlers {
    /// Writes events to the unified system log, one category per `PassportLogComponent`.
    ///
    /// For sensitive events, detail, wire and plain content are `.private` (or the summary itself when
    /// there is no content); everything else is `.public`. Sensitive content only reaches this handler when `includeSensitiveDataInHandler`
    /// is enabled, so by default the redacted placeholders are logged.
    public static func osLog(subsystem: String = Bundle.main.bundleIdentifier ?? "NFCPassportReader")
        -> PassportLogHandler {
        var loggers: [PassportLogComponent: Logger] = [:]
        for component in PassportLogComponent.allCases {
            loggers[component] = Logger(subsystem: subsystem, category: component.rawValue)
        }
        let cached = loggers
        return { event in
            guard let logger = cached[event.component] else { return }
            let type = osLogType(for: event.level)
            let content = [
                event.detail,
                event.wire.map { "Wire: \($0)" },
                event.plain.map { "Plain: \($0)" },
            ].compactMap { $0 }.joined(separator: "\n")

            if content.isEmpty {
                // A sensitive event without content carries its sensitive text in the summary.
                if event.isSensitive {
                    logger.log(level: type, "\(event.summary, privacy: .private)")
                } else {
                    logger.log(level: type, "\(event.summary, privacy: .public)")
                }
            } else if event.isSensitive {
                logger.log(level: type, "\(event.summary, privacy: .public)\n\(content, privacy: .private)")
            } else {
                logger.log(level: type, "\(event.summary, privacy: .public)\n\(content, privacy: .public)")
            }
        }
    }

    /// Fans each event out to several handlers, in order.
    public static func combine(_ handlers: PassportLogHandler...) -> PassportLogHandler {
        { event in
            for handler in handlers {
                handler(event)
            }
        }
    }

    static func osLogType(for level: PassportLogLevel) -> OSLogType {
        switch level {
            case .debug: return .debug
            case .info: return .info
            case .warning: return .default
            case .error: return .error
            case .fault: return .fault
        }
    }
}
