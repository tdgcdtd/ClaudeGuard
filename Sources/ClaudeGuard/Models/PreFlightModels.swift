import Foundation

enum CheckStatus: String, Sendable, Equatable {
    case pending
    case checking
    case passed
    case warning
    case failed
}

enum PreFlightCheckKind: Int, CaseIterable, Identifiable, Sendable {
    case localPort = 1
    case exitIp = 2
    case regionPolicy = 3
    case dnsAndIpv6 = 4
    case processAndTimezone = 5
    case anthropicTls = 6

    var id: Int { rawValue }

    var title: String {
        switch self {
        case .localPort:
            return "本地监听端口"
        case .exitIp:
            return "出口 IP 精确锁死"
        case .regionPolicy:
            return "地区与受限区核验"
        case .dnsAndIpv6:
            return "远程 DNS 与 IPv6 穿透"
        case .processAndTimezone:
            return "进程干净度与时区"
        case .anthropicTls:
            return "Anthropic TLS 握手"
        }
    }
}

struct PreFlightItemResult: Identifiable, Equatable, Sendable {
    let kind: PreFlightCheckKind
    var status: CheckStatus
    var summary: String
    var detail: String
    var latencyMs: Int?
    var hasResidualClaudeProcess: Bool
    var checkedAt: Date?

    var id: Int { kind.rawValue }

    static func pending(_ kind: PreFlightCheckKind) -> PreFlightItemResult {
        PreFlightItemResult(
            kind: kind,
            status: .pending,
            summary: "待检测",
            detail: "",
            latencyMs: nil,
            hasResidualClaudeProcess: false,
            checkedAt: nil
        )
    }

    static func checking(_ kind: PreFlightCheckKind) -> PreFlightItemResult {
        PreFlightItemResult(
            kind: kind,
            status: .checking,
            summary: "检测中...",
            detail: "",
            latencyMs: nil,
            hasResidualClaudeProcess: false,
            checkedAt: nil
        )
    }
}

struct PreFlightReport: Equatable, Sendable {
    var presetId: String
    var items: [PreFlightItemResult]
    var completedAt: Date?

    static func initial(presetId: String) -> PreFlightReport {
        PreFlightReport(
            presetId: presetId,
            items: PreFlightCheckKind.allCases.map { PreFlightItemResult.pending($0) },
            completedAt: nil
        )
    }

    static func checking(presetId: String) -> PreFlightReport {
        PreFlightReport(
            presetId: presetId,
            items: PreFlightCheckKind.allCases.map { PreFlightItemResult.checking($0) },
            completedAt: nil
        )
    }

    var hasAnyFailure: Bool {
        items.contains(where: { $0.status == .failed })
    }

    var hasWarning: Bool {
        !hasAnyFailure && items.contains(where: { $0.status == .warning })
    }

    var isAllGreen: Bool {
        items.count == PreFlightCheckKind.allCases.count && items.allSatisfy { $0.status == .passed }
    }

    var hasResidualProcess: Bool {
        items.contains(where: { $0.hasResidualClaudeProcess })
    }

    var canPassGate: Bool {
        guard items.count == PreFlightCheckKind.allCases.count else { return false }
        let mandatoryKinds: Set<PreFlightCheckKind> = [.localPort, .exitIp, .regionPolicy, .anthropicTls]
        for item in items {
            if item.hasResidualClaudeProcess { return false }
            if mandatoryKinds.contains(item.kind) {
                if item.status != .passed { return false }
            } else {
                if item.status != .passed && item.status != .warning { return false }
            }
        }
        return true
    }

    var firstFailureSummary: String? {
        items.first(where: { $0.status == .failed }).map { "\($0.kind.title)：\($0.summary)" }
    }

    var firstWarningSummary: String? {
        items.first(where: { $0.status == .warning }).map { "\($0.kind.title)：\($0.summary)" }
    }
}

struct CdnTraceInfo: Equatable, Sendable {
    var ip: String?
    var loc: String?
    var colo: String?
    var tls: String?
    var rawFields: [String: String]

    static func parse(_ text: String) -> CdnTraceInfo {
        var fields: [String: String] = [:]
        for line in text.split(whereSeparator: \.isNewline) {
            let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty, let eqIndex = trimmed.firstIndex(of: "=") else { continue }
            let key = String(trimmed[..<eqIndex]).trimmingCharacters(in: .whitespaces)
            let value = String(trimmed[trimmed.index(after: eqIndex)...]).trimmingCharacters(in: .whitespaces)
            if !key.isEmpty {
                fields[key] = value
            }
        }
        return CdnTraceInfo(
            ip: fields["ip"]?.isEmpty == false ? fields["ip"] : nil,
            loc: fields["loc"]?.isEmpty == false ? fields["loc"]?.uppercased() : nil,
            colo: fields["colo"]?.isEmpty == false ? fields["colo"] : nil,
            tls: fields["tls"]?.isEmpty == false ? fields["tls"] : nil,
            rawFields: fields
        )
    }
}

struct PresetPortHealth: Identifiable, Equatable, Sendable {
    var presetId: String
    var shortLabel: String
    var port: Int
    var isAlive: Bool?
    var latencyMs: Int?
    var checkedAt: Date?

    var id: String { presetId }
}
