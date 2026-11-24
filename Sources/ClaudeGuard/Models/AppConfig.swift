import Foundation

struct ProxyPreset: Codable, Identifiable, Equatable, Sendable {
    var id: String
    var name: String
    var proxyHost: String
    var proxyPort: Int
    var expectedExitIp: String
    var expectedCountry: String
    var expectedTimezone: String
    var strictTimezoneCheck: Bool

    var socks5Endpoint: String {
        "\(proxyHost):\(proxyPort)"
    }

    var expectedProxyFlag: String {
        "--proxy-server=socks5://\(proxyHost):\(proxyPort)"
    }

    var shortLabel: String {
        let trimmed = id.uppercased()
        if trimmed.hasPrefix("JP") { return "JP" }
        if trimmed.hasPrefix("US") { return "US" }
        if let firstWord = name.split(separator: " ").first {
            return String(firstWord.prefix(6))
        }
        return String(id.prefix(6))
    }

    func sanitized() -> ProxyPreset {
        let cleanedHost = proxyHost.trimmingCharacters(in: .whitespacesAndNewlines)
        let cleanedIp = expectedExitIp.trimmingCharacters(in: .whitespacesAndNewlines)
        let cleanedCountry = expectedCountry.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
        let cleanedTz = expectedTimezone.trimmingCharacters(in: .whitespacesAndNewlines)
        return ProxyPreset(
            id: id.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? UUID().uuidString : id.trimmingCharacters(in: .whitespacesAndNewlines),
            name: name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? "未命名预设" : name.trimmingCharacters(in: .whitespacesAndNewlines),
            proxyHost: cleanedHost.isEmpty ? "127.0.0.1" : cleanedHost,
            proxyPort: (1...65535).contains(proxyPort) ? proxyPort : 17892,
            expectedExitIp: cleanedIp,
            expectedCountry: cleanedCountry,
            expectedTimezone: cleanedTz,
            strictTimezoneCheck: strictTimezoneCheck
        )
    }
}

struct AppConfig: Codable, Equatable, Sendable {
    var activeDesktopPresetId: String
    var lastLaunchedDesktopPresetId: String
    var presets: [ProxyPreset]
    var blockedCountries: [String]
    var claudeAppPath: String
    var killDesktopOnSleep: Bool
    var killDonutOnSleep: Bool
    var guardRogueLaunch: Bool
    var fastProbeIntervalSec: Int
    var socketAuditIntervalSec: Int
    var exitIpVerifyIntervalSec: Int

    static let defaultPresets: [ProxyPreset] = [
        ProxyPreset(
            id: "jp-static",
            name: "JP 静态代理 (主力)",
            proxyHost: "127.0.0.1",
            proxyPort: 17892,
            expectedExitIp: "203.0.113.10",
            expectedCountry: "JP",
            expectedTimezone: "Asia/Tokyo",
            strictTimezoneCheck: false
        ),
        ProxyPreset(
            id: "us-static",
            name: "US 静态代理 (备用)",
            proxyHost: "127.0.0.1",
            proxyPort: 17891,
            expectedExitIp: "198.51.100.20",
            expectedCountry: "US",
            expectedTimezone: "America/Los_Angeles",
            strictTimezoneCheck: false
        )
    ]

    static let defaultConfig = AppConfig(
        activeDesktopPresetId: "jp-static",
        lastLaunchedDesktopPresetId: "jp-static",
        presets: defaultPresets,
        blockedCountries: ["CN", "HK", "MO", "RU", "KP", "IR", "SY"],
        claudeAppPath: "/Applications/Claude.app",
        killDesktopOnSleep: true,
        killDonutOnSleep: false,
        guardRogueLaunch: true,
        fastProbeIntervalSec: 2,
        socketAuditIntervalSec: 3,
        exitIpVerifyIntervalSec: 25
    )

    var activePreset: ProxyPreset {
        presets.first(where: { $0.id == activeDesktopPresetId }) ?? presets.first ?? Self.defaultPresets[0]
    }

    func preset(for id: String) -> ProxyPreset? {
        presets.first(where: { $0.id == id })
    }

    func requiresCrossRegionConfirmation(for targetPresetId: String) -> Bool {
        let last = lastLaunchedDesktopPresetId.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !last.isEmpty else { return false }
        return last != targetPresetId
    }

    func sanitized() -> AppConfig {
        var copy = self
        var cleanedPresets = presets.map { $0.sanitized() }
        if cleanedPresets.isEmpty {
            cleanedPresets = Self.defaultPresets
        }
        copy.presets = cleanedPresets
        if !cleanedPresets.contains(where: { $0.id == copy.activeDesktopPresetId }) {
            copy.activeDesktopPresetId = cleanedPresets[0].id
        }
        copy.blockedCountries = blockedCountries
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines).uppercased() }
            .filter { !$0.isEmpty }
        let trimmedApp = claudeAppPath.trimmingCharacters(in: .whitespacesAndNewlines)
        copy.claudeAppPath = trimmedApp.isEmpty ? "/Applications/Claude.app" : trimmedApp
        copy.fastProbeIntervalSec = max(1, fastProbeIntervalSec)
        copy.socketAuditIntervalSec = max(1, socketAuditIntervalSec)
        copy.exitIpVerifyIntervalSec = max(5, exitIpVerifyIntervalSec)
        return copy
    }
}
