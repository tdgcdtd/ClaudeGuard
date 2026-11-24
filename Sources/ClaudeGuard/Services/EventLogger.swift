import Foundation
import AppKit
import UserNotifications

enum EventLevel: String, Sendable {
    case info = "INFO"
    case warning = "WARN"
    case killSwitch = "KILL-SWITCH"
    case sleepGuard = "SLEEP-GUARD"
    case launch = "LAUNCH"
}

final class EventLogger: @unchecked Sendable {
    let logFileURL: URL
    private let maxBytes: Int
    private let keepBytes: Int
    private let queue = DispatchQueue(label: "com.claudeguard.eventlogger", qos: .utility)

    private static let formatter: DateFormatter = {
        let df = DateFormatter()
        df.locale = Locale(identifier: "en_US_POSIX")
        df.dateFormat = "yyyy-MM-dd HH:mm:ss.SSS"
        return df
    }()

    init(logFileURL: URL? = nil, maxBytes: Int = 524_288, keepBytes: Int = 262_144) {
        if let logFileURL {
            self.logFileURL = logFileURL
        } else {
            let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
                ?? URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("Library/Application Support", isDirectory: true)
            let dir = appSupport.appendingPathComponent("ClaudeGuard", isDirectory: true)
            self.logFileURL = dir.appendingPathComponent("events.log", isDirectory: false)
        }
        self.maxBytes = max(1024, maxBytes)
        self.keepBytes = min(max(512, keepBytes), self.maxBytes)
    }

    func log(level: EventLevel, presetName: String?, reason: String, detail: String = "") {
        let timestamp = Self.formatter.string(from: Date())
        let presetPart = presetName.map { " [\($0)]" } ?? ""
        let detailPart = detail.isEmpty ? "" : " | 详情: \(detail)"
        let line = "[\(timestamp)] [\(level.rawValue)]\(presetPart) \(reason)\(detailPart)\n"

        queue.sync {
            do {
                let dir = logFileURL.deletingLastPathComponent()
                try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
                let lineData = Data(line.utf8)
                if FileManager.default.fileExists(atPath: logFileURL.path) {
                    let handle = try FileHandle(forWritingTo: logFileURL)
                    defer { try? handle.close() }
                    try handle.seekToEnd()
                    try handle.write(contentsOf: lineData)
                } else {
                    try lineData.write(to: logFileURL, options: [.atomic])
                }
                trimIfNeededLocked()
            } catch {
                // 日志写入失败不应阻塞安全主流程
            }
        }
    }

    func readRecentLogs(maxCharacters: Int = 20_000) -> String {
        queue.sync {
            guard let data = try? Data(contentsOf: logFileURL),
                  let text = String(data: data, encoding: .utf8) else {
                return "暂无安全事件记录。"
            }
            if text.isEmpty {
                return "暂无安全事件记录。"
            }
            if text.count <= maxCharacters {
                return text
            }
            let start = text.index(text.endIndex, offsetBy: -maxCharacters)
            return "... (仅显示最近记录)\n" + String(text[start...])
        }
    }

    func clearLogs() {
        queue.sync {
            try? Data().write(to: logFileURL, options: [.atomic])
        }
    }

    private func trimIfNeededLocked() {
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: logFileURL.path),
              let fileSize = attrs[.size] as? NSNumber,
              fileSize.intValue > maxBytes,
              let data = try? Data(contentsOf: logFileURL),
              data.count > keepBytes else {
            return
        }

        let startOffset = data.count - keepBytes
        var slice = data.subdata(in: startOffset..<data.count)
        if let newlineIndex = slice.firstIndex(of: 0x0A), newlineIndex + 1 < slice.count {
            slice = slice.subdata(in: (newlineIndex + 1)..<slice.count)
        }
        try? slice.write(to: logFileURL, options: [.atomic])
    }

    private var canUseUserNotifications: Bool {
        Bundle.main.bundleURL.pathExtension == "app" && Bundle.main.bundleIdentifier != nil
    }

    func requestNotificationPermissionIfPossible() {
        guard canUseUserNotifications else { return }
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in }
    }

    func sendNotification(title: String, body: String) {
        guard canUseUserNotifications else { return }
        let center = UNUserNotificationCenter.current()
        center.getNotificationSettings { settings in
            let deliver = {
                let content = UNMutableNotificationContent()
                content.title = title
                content.body = body
                content.sound = .defaultCritical
                let request = UNNotificationRequest(
                    identifier: "claudeguard-\(UUID().uuidString)",
                    content: content,
                    trigger: nil
                )
                center.add(request, withCompletionHandler: nil)
            }

            if settings.authorizationStatus == .notDetermined {
                center.requestAuthorization(options: [.alert, .sound]) { granted, _ in
                    if granted { deliver() }
                }
            } else if settings.authorizationStatus == .authorized || settings.authorizationStatus == .provisional {
                deliver()
            }
        }
    }

    func triggerKillSwitchAlert(reason: String, detail: String) {
        DispatchQueue.main.async {
            if let sound = NSSound(named: NSSound.Name("Basso")) ?? NSSound(named: NSSound.Name("Sosumi")) {
                sound.play()
            } else {
                NSSound.beep()
            }
        }
        let body = detail.isEmpty ? reason : "\(reason)（\(detail)）"
        sendNotification(title: "⛔ ClaudeGuard 紧急熔断", body: body)
    }
}
