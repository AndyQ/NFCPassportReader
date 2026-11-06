//
//  TraceView.swift
//  NFCPassportReaderApp
//
//  APDU trace of passport reads: commands, responses (wire and, under secure messaging, plain) and
//  protocol milestones. Tap a row for its bytes and details.
//

import SwiftUI
import NFCPassportReader

struct TraceView: View {
    @EnvironmentObject var trace: TraceStore

    @AppStorage("trace.showApdus") private var showApdus = true
    @AppStorage("trace.expandAll") private var expandAll = false
    @AppStorage("trace.follow") private var follow = true
    @State private var exportURL: URL?
    @State private var showShare = false

    private var visible: [ReaderTraceEvent] {
        showApdus ? trace.events : trace.events.filter { $0.kind != .command && $0.kind != .response }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 8) {
                    ToggleChip(title: "APDUs", isOn: $showApdus)
                    ToggleChip(title: "Expand all", isOn: $expandAll)
                    ToggleChip(title: "Auto-scroll", isOn: $follow)
                }
                .padding(.horizontal)
                .padding(.vertical, 8)
            }
            Text("\(trace.events.count) events")
                .font(.caption)
                .foregroundColor(.secondary)
                .padding(.horizontal)
                .padding(.bottom, 4)
            Divider()

            if visible.isEmpty {
                VStack(spacing: 8) {
                    Spacer()
                    Image(systemName: "waveform.path.ecg").font(.largeTitle).foregroundColor(.secondary)
                    Text("No trace yet").font(.headline)
                    Text("Scan a passport and every APDU and protocol step appears here.")
                        .font(.footnote).foregroundColor(.secondary).multilineTextAlignment(.center)
                    Spacer()
                }
                .frame(maxWidth: .infinity)
                .padding()
            } else {
                ScrollViewReader { proxy in
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 0) {
                            ForEach(visible) { event in
                                TraceRow(event: event, expandAll: expandAll)
                                    .id(event.id)
                                Divider().opacity(0.4)
                            }
                        }
                    }
                    .onChange(of: visible.count) { _ in
                        if follow, let last = visible.last { proxy.scrollTo(last.id, anchor: .bottom) }
                    }
                    .onAppear {
                        if follow, let last = visible.last { proxy.scrollTo(last.id, anchor: .bottom) }
                    }
                }
            }
        }
        .navigationTitle("Trace")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItemGroup(placement: .navigationBarTrailing) {
                Button {
                    exportURL = try? trace.exportFile()
                    showShare = exportURL != nil
                } label: {
                    Image(systemName: "square.and.arrow.up")
                }
                .disabled(trace.events.isEmpty)
                Button(role: .destructive) {
                    trace.clear()
                } label: {
                    Image(systemName: "trash")
                }
                .disabled(trace.events.isEmpty)
            }
        }
        .sheet(isPresented: $showShare) {
            if let url = exportURL {
                ShareSheet(items: [url])
            }
        }
    }
}

private struct TraceRow: View {
    let event: ReaderTraceEvent
    let expandAll: Bool
    @State private var expandedOverride: Bool?

    private static let timeFormat: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss.SSS"
        return f
    }()

    private var marker: (String, Color)? {
        switch event.kind {
            case .command: return ("→", .accentColor)
            case .response: return ("←", .teal)
            case .info: return ("•", .secondary)
            case .error: return ("✖", .red)
            case .log: return nil
        }
    }

    private var levelColor: Color {
        switch event.level {
            case .debug: return .gray
            case .info: return .blue
            case .warning: return .orange
            case .error: return .red
            case .fault: return .purple
        }
    }

    private var hasMoreInfo: Bool {
        event.detail != nil || event.wire != nil || event.plain != nil
    }

    private var isExpanded: Bool {
        expandedOverride ?? expandAll
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(alignment: .firstTextBaseline, spacing: 4) {
                Text(Self.timeFormat.string(from: event.timestamp))
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundColor(.secondary)
                if event.kind == .log {
                    Circle()
                        .fill(levelColor)
                        .frame(width: 7, height: 7)
                        .frame(width: 12, height: 16)
                        .accessibilityLabel("\(event.level) log level")
                } else if let marker = marker {
                    Text(marker.0)
                        .font(.system(.body, design: .monospaced))
                        .foregroundColor(marker.1)
                }
                if hasMoreInfo {
                    Image(systemName: isExpanded ? "chevron.down" : "chevron.right")
                        .font(.system(size: 8, weight: .semibold))
                        .foregroundColor(.secondary)
                        .accessibilityLabel(isExpanded ? "Hide details" : "Show details")
                }
                Text(event.kind == .log ? "\(event.component.rawValue): \(event.summary)" : event.summary)
                    .font(.footnote)
                    .foregroundColor(summaryColor)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            if isExpanded {
                if let plain = event.plain { Mono("plain: \(plain)") }
                if let wire = event.wire { Mono("wire:  \(wire)") }
            }
            if isExpanded, let detail = event.detail {
                Mono(detail)
            }
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 3)
        .contentShape(Rectangle())
        .onTapGesture { expandedOverride = !(expandedOverride ?? expandAll) }
        .onChange(of: expandAll) { _ in expandedOverride = nil }
        .contextMenu {
            Button {
                UIPasteboard.general.string = [event.summary, event.plain.map { "plain: \($0)" }, event.wire.map { "wire: \($0)" }, event.detail]
                    .compactMap { $0 }.joined(separator: "\n")
            } label: {
                Label("Copy", systemImage: "doc.on.doc")
            }
        }
    }

    private var summaryColor: Color {
        if event.kind == .log {
            return event.level < .warning ? .primary : levelColor
        }
        if event.kind == .info {
            return .primary
        }
        return marker?.1 ?? .primary
    }
}

private struct Mono: View {
    let text: String
    init(_ text: String) { self.text = text }
    var body: some View {
        Text(text)
            .font(.system(size: 10, design: .monospaced))
            .foregroundColor(.secondary)
            .textSelection(.enabled)
            .frame(maxWidth: .infinity, alignment: .leading)
    }
}

private struct ToggleChip: View {
    let title: String
    @Binding var isOn: Bool
    var body: some View {
        Button {
            isOn.toggle()
        } label: {
            HStack(spacing: 4) {
                if isOn { Image(systemName: "checkmark").font(.caption2.weight(.bold)) }
                Text(title).font(.footnote)
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 6)
            .background(isOn ? Color.accentColor.opacity(0.15) : Color.clear)
            .overlay(Capsule().stroke(isOn ? Color.accentColor : Color.secondary.opacity(0.5)))
            .clipShape(Capsule())
        }
        .buttonStyle(.plain)
    }
}

struct ShareSheet: UIViewControllerRepresentable {
    let items: [Any]
    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: items, applicationActivities: nil)
    }
    func updateUIViewController(_ uiViewController: UIActivityViewController, context: Context) {}
}
