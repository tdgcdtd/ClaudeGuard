import Foundation
import AppKit

enum SafeLaunchError: LocalizedError {
    case appBundleMissing(String)
    case launchFailed(String)
    case verificationFailed(String)

    var errorDescription: String? {
        switch self {
        case .appBundleMissing(let path):
            return "未找到 Claude Desktop 应用或可执行文件：\(path)"
        case .launchFailed(let msg):
            return "启动 Claude Desktop 失败：\(msg)"
        case .verificationFailed(let msg):
            return "启动后参数复核未通过（已立即强杀防泄露）：\(msg)"
        }
    }
}

enum SafeLauncher {
    private static let lowercaseUuidRegex = try! NSRegularExpression(pattern: "^[a-f0-9-]{36}$")

    static func defaultClaudeConfigLibraryDir() -> URL {
        let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("Library/Application Support", isDirectory: true)
        return appSupport
            .appendingPathComponent("Claude-3p", isDirectory: true)
            .appendingPathComponent("configLibrary", isDirectory: true)
    }

    static func isValidLowercaseConfigId(_ id: String) -> Bool {
        let range = NSRange(location: 0, length: id.utf16.count)
        return lowercaseUuidRegex.firstMatch(in: id, options: [], range: range) != nil
    }

    static func probeHttpConnectProxySupport(preset: ProxyPreset) async -> Bool {
        let resp = await PreFlightChecker.runCurl(arguments: [
            "-sS",
            "-x", "http://\(preset.proxyHost):\(preset.proxyPort)",
            "--connect-timeout", "3",
            "--max-time", "5",
            "https://claude.ai/cdn-cgi/trace"
        ])
        return resp.exitCode == 0 && resp.stdout.contains("ip=")
    }

    /// 同步官方本地策略库（~/Library/Application Support/Claude-3p/configLibrary）：
    /// - disableAutoUpdates: true 关闭内置 Squirrel/NSURLSession 自动更新检查（阻断其绕过代理走系统 TUN 直连）
    /// - egressProxyUrl: http://<host>:<port> 锁定 Electron defaultSession 出口代理并向子进程注入代理环境变量
    static func syncClaudeLocalConfigLibrary(
        preset: ProxyPreset,
        supportsHttpProxy: Bool,
        configLibraryDir: URL? = nil
    ) throws {
        let dir = configLibraryDir ?? defaultClaudeConfigLibraryDir()
        let fm = FileManager.default
        try fm.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try? fm.setAttributes([.posixPermissions: 0o700], ofItemAtPath: dir.path)

        let metaURL = dir.appendingPathComponent("_meta.json", isDirectory: false)
        var metaDict: [String: Any] = [:]
        if let metaData = try? Data(contentsOf: metaURL),
           let parsed = try? JSONSerialization.jsonObject(with: metaData) as? [String: Any] {
            metaDict = parsed
        }

        let appliedId: String
        if let existingId = metaDict["appliedId"] as? String, isValidLowercaseConfigId(existingId) {
            appliedId = existingId
        } else {
            appliedId = UUID().uuidString.lowercased()
            metaDict["appliedId"] = appliedId
        }

        var entries = (metaDict["entries"] as? [[String: Any]]) ?? []
        if !entries.contains(where: { ($0["id"] as? String) == appliedId }) {
            entries.append(["id": appliedId, "name": "ClaudeGuard"])
        }
        metaDict["entries"] = entries

        let metaOut = try JSONSerialization.data(withJSONObject: metaDict, options: [.prettyPrinted, .sortedKeys])
        try metaOut.write(to: metaURL, options: [.atomic])
        try? fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: metaURL.path)

        let configURL = dir.appendingPathComponent("\(appliedId).json", isDirectory: false)
        var configDict: [String: Any] = [:]
        if let cfgData = try? Data(contentsOf: configURL),
           let parsed = try? JSONSerialization.jsonObject(with: cfgData) as? [String: Any] {
            configDict = parsed
        }

        configDict["disableAutoUpdates"] = true
        if supportsHttpProxy {
            configDict["egressProxyUrl"] = "http://\(preset.proxyHost):\(preset.proxyPort)"
        } else {
            configDict.removeValue(forKey: "egressProxyUrl")
        }

        let cfgOut = try JSONSerialization.data(withJSONObject: configDict, options: [.prettyPrinted, .sortedKeys])
        try cfgOut.write(to: configURL, options: [.atomic])
        try? fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: configURL.path)
    }

    @MainActor
    static func launch(preset: ProxyPreset, config: AppConfig) async throws -> [ClaudeProcessInfo] {
        let cleanAppPath = config.claudeAppPath.trimmingCharacters(in: .whitespacesAndNewlines)
        let normalizedApp = cleanAppPath.hasSuffix("/") ? String(cleanAppPath.dropLast()) : cleanAppPath
        let appURL = URL(fileURLWithPath: normalizedApp, isDirectory: true)
        let executablePath = "\(normalizedApp)/Contents/MacOS/Claude"

        guard FileManager.default.fileExists(atPath: appURL.path),
              FileManager.default.isExecutableFile(atPath: executablePath) else {
            throw SafeLaunchError.appBundleMissing(executablePath)
        }

        let httpSupported = await probeHttpConnectProxySupport(preset: preset)
        try syncClaudeLocalConfigLibrary(preset: preset, supportsHttpProxy: httpSupported)

        // 兼容 Claude Desktop 6.6395.1+（该版本拦截 --host-resolver-rules 等调试开关导致立即 exit(1)）
        // 使用官方原生支持的 --proxy-server=socks5:// + --proxy-bypass-list + 禁用非代理 UDP WebRTC
        let proxyArg = "--proxy-server=socks5://\(preset.proxyHost):\(preset.proxyPort)"
        let bypassArg = "--proxy-bypass-list=127.0.0.1;[::1];localhost"
        let webrtcArg = "--force-webrtc-ip-handling-policy=disable_non_proxied_udp"

        let openConfig = NSWorkspace.OpenConfiguration()
        openConfig.activates = true
        openConfig.addsToRecentItems = false
        openConfig.createsNewApplicationInstance = false
        openConfig.arguments = [proxyArg, bypassArg, webrtcArg]

        do {
            _ = try await NSWorkspace.shared.openApplication(at: appURL, configuration: openConfig)
        } catch {
            throw SafeLaunchError.launchFailed(error.localizedDescription)
        }

        // 启动后延迟 1.5 秒复核主进程确实存活且携带目标 --proxy-server 参数
        try? await Task.sleep(nanoseconds: 1_500_000_000)

        let running = await Task.detached(priority: .userInitiated) {
            ProcessManager.findClaudeProcesses(claudeAppPath: config.claudeAppPath)
        }.value

        let validMain = running.first { proc in
            proc.isMainProcess && ProcessManager.hasExpectedProxyArgument(
                commandLine: proc.commandLine,
                arguments: proc.arguments,
                proxyHost: preset.proxyHost,
                proxyPort: preset.proxyPort
            )
        }

        if validMain == nil {
            ProcessManager.killAllClaudeImmediately(claudeAppPath: config.claudeAppPath)
            if running.isEmpty {
                throw SafeLaunchError.verificationFailed("1.5 秒后未检测到存活的 Claude 主进程")
            } else {
                throw SafeLaunchError.verificationFailed("主进程未携带 \(proxyArg)")
            }
        }

        // 若存在任何未带参数的多余主进程，一并强杀
        let rogueMains = running.filter { proc in
            proc.isMainProcess && !ProcessManager.hasExpectedProxyArgument(
                commandLine: proc.commandLine,
                arguments: proc.arguments,
                proxyHost: preset.proxyHost,
                proxyPort: preset.proxyPort
            )
        }
        if !rogueMains.isEmpty {
            ProcessManager.killAllClaudeImmediately(claudeAppPath: config.claudeAppPath)
            throw SafeLaunchError.verificationFailed("检测到未带代理参数的混入主进程")
        }

        return running
    }
}
