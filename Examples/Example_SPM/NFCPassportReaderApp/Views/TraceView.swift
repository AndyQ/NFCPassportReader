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
    @AppStorage("trace.showWire") private var showWire = false
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
                    ToggleChip(title: "Wire bytes", isOn: $showWire)
                    ToggleChip(title: "Follow", isOn: $follow)
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
                                TraceRow(event: event, showWire: showWire)
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
    let showWire: Bool
    @State private var expanded = false

    private static let timeFormat: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss.SSS"
        return f
    }()

    private var marker: (String, Color) {
        switch event.kind {
            case .command: return ("→", .accentColor)
            case .response: return ("←", .teal)
            case .info: return ("•", .secondary)
            case .error: return ("✖", .red)
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(alignment: .firstTextBaseline, spacing: 4) {
                Text(Self.timeFormat.string(from: event.timestamp))
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundColor(.secondary)
                Text(marker.0)
                    .font(.system(.body, design: .monospaced))
                    .foregroundColor(marker.1)
                Text(event.summary)
                    .font(.footnote)
                    .foregroundColor(event.kind == .info ? .primary : marker.1)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            if showWire || expanded {
                if let plain = event.plain { Mono("plain: \(plain)") }
                if let wire = event.wire { Mono("wire:  \(wire)") }
            }
            if expanded, let detail = event.detail {
                Mono(detail)
            }
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 3)
        .contentShape(Rectangle())
        .onTapGesture { expanded.toggle() }
        .contextMenu {
            Button {
                UIPasteboard.general.string = [event.summary, event.plain.map { "plain: \($0)" }, event.wire.map { "wire: \($0)" }, event.detail]
                    .compactMap { $0 }.joined(separator: "\n")
            } label: {
                Label("Copy", systemImage: "doc.on.doc")
            }
        }
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
