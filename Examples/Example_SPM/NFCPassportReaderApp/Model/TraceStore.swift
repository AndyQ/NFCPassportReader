//
//  TraceStore.swift
//  NFCPassportReaderApp
//
//  Collects log and APDU events from PassportReader.logHandler for TraceView.
//

import Foundation
import NFCPassportReader

final class TraceStore: ObservableObject {
    @Published private(set) var events: [ReaderTraceEvent] = []

    /// Keeps memory bounded on long sessions.
    private let maxEvents = 20_000
    private let generationLock = NSLock()
    private var generation = 0

    /// Hand this to PassportReader.logHandler. Safe to call from any thread.
    lazy var handler: (ReaderTraceEvent) -> Void = { [weak self] event in
        guard let self = self else { return }
        let eventGeneration = self.currentGeneration()
        DispatchQueue.main.async {
            guard self.currentGeneration() == eventGeneration else { return }
            self.events.append(event)
            if self.events.count > self.maxEvents {
                self.events.removeFirst(self.events.count - self.maxEvents)
            }
        }
    }

    func clear() {
        generationLock.lock()
        generation += 1
        generationLock.unlock()
        events.removeAll()
    }

    private func currentGeneration() -> Int {
        generationLock.lock()
        defer { generationLock.unlock() }
        return generation
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
