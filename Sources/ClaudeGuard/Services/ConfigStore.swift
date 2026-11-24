import Foundation

final class ConfigStore: @unchecked Sendable {
    let supportDirectoryURL: URL
    let configFileURL: URL

    init(directoryURL: URL? = nil) {
        if let directoryURL {
            self.supportDirectoryURL = directoryURL
        } else {
            let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
                ?? URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("Library/Application Support", isDirectory: true)
            self.supportDirectoryURL = appSupport.appendingPathComponent("ClaudeGuard", isDirectory: true)
        }
        self.configFileURL = self.supportDirectoryURL.appendingPathComponent("config.json", isDirectory: false)
    }

    func ensureDirectoryExists() throws {
        try FileManager.default.createDirectory(at: supportDirectoryURL, withIntermediateDirectories: true)
    }

    func load() -> AppConfig {
        do {
            try ensureDirectoryExists()
            if !FileManager.default.fileExists(atPath: configFileURL.path) {
                let initial = AppConfig.defaultConfig.sanitized()
                try save(initial)
                return initial
            }
            let data = try Data(contentsOf: configFileURL)
            let decoded = try JSONDecoder().decode(AppConfig.self, from: data)
            return decoded.sanitized()
        } catch {
            return AppConfig.defaultConfig.sanitized()
        }
    }

    func save(_ config: AppConfig) throws {
        try ensureDirectoryExists()
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(config.sanitized())
        try data.write(to: configFileURL, options: [.atomic])
    }
}
