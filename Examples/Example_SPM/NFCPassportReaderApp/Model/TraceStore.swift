//
//  TraceStore.swift
//  NFCPassportReaderApp
//
//  Collects the APDU trace from PassportReader.traceHandler for TraceView.
//

import Foundation
import NFCPassportReader

final class TraceStore: ObservableObject {
    @Published private(set) var events: [ReaderTraceEvent] = []

    /// Keeps memory bounded on long sessions.
    private let maxEvents = 20_000

    /// Hand this to PassportReader.traceHandler. Safe to call from any thread.
    lazy var handler: (ReaderTraceEvent) -> Void = { [weak self] event in
        DispatchQueue.main.async {
            guard let self = self else { return }
            self.events.append(event)
            if self.events.count > self.maxEvents {
                self.events.removeFirst(self.events.count - self.maxEvents)
            }
        }
    }

    func clear() {
        events.removeAll()
    }

    /// Writes the trace as JSON to a temporary file for sharing.
    func exportFile() throws -> URL {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("nfcpassportreader-trace-\(Int(Date().timeIntervalSince1970)).json")
        try encoder.encode(events).write(to: url)
        return url
    }
}
