import Foundation
import Testing
@testable import ClaudeGuard

@Suite("ClaudeGuard 核心安全逻辑测试")
struct ClaudeGuardCoreTests {

    // MARK: - 1. cdn-cgi/trace 解析测试

    @Test("cdn-cgi/trace 标准响应与空白字段解析")
    func parseCdnTrace() {
        let sample = """
        fl=21f123
        h=claude.ai
        ip=203.0.113.10
        ts=1732450000.123
        visit_scheme=https
        uag=curl/8.7.1
        colo=NRT
        sliver=none
        http=http/2
        loc=jp
        tls=TLSv1.3
        """
        let trace = CdnTraceInfo.parse(sample)
        #expect(trace.ip == "203.0.113.10")
        #expect(trace.loc == "JP")
        #expect(trace.colo == "NRT")
        #expect(trace.tls == "TLSv1.3")
    }

    @Test("cdn-cgi/trace 空值与异常文本处理")
    func parseMalformedCdnTrace() {
        let malformed = "<html><body>502 Bad Gateway</body></html>\nip=\nloc=  "
        let trace = CdnTraceInfo.parse(malformed)
        #expect(trace.ip == nil)
        #expect(trace.loc == nil)
    }

    // MARK: - 2. IP 不匹配与受限国家拦截测试

    @Test("出口 IP 精确锁死判定")
    func exitIpMatching() {
        let ok = PreFlightChecker.evaluateExitIp(actualIp: "203.0.113.10", expectedIp: "203.0.113.10")
        #expect(ok.passed)

        let drifted = PreFlightChecker.evaluateExitIp(actualIp: "198.51.100.20", expectedIp: "203.0.113.10")
        #expect(!drifted.passed)
        #expect(drifted.summary.contains("IP 不匹配"))

        let missing = PreFlightChecker.evaluateExitIp(actualIp: nil, expectedIp: "203.0.113.10")
        #expect(!missing.passed)
    }

    @Test("受限国家列表拦截与跨区拦截")
    func regionPolicyFiltering() {
        let blocked = ["CN", "HK", "MO", "RU", "KP", "IR", "SY"]

        let jpPass = PreFlightChecker.evaluateRegion(actualLoc: "jp", expectedCountry: "JP", blockedCountries: blocked)
        #expect(jpPass.passed)

        let hkBlocked = PreFlightChecker.evaluateRegion(actualLoc: "hk", expectedCountry: "JP", blockedCountries: blocked)
        #expect(!hkBlocked.passed)
        #expect(hkBlocked.summary.contains("受限地区"))

        let cnBlocked = PreFlightChecker.evaluateRegion(actualLoc: "CN", expectedCountry: "US", blockedCountries: blocked)
        #expect(!cnBlocked.passed)

        let wrongRegion = PreFlightChecker.evaluateRegion(actualLoc: "SG", expectedCountry: "JP", blockedCountries: blocked)
        #expect(!wrongRegion.passed)
        #expect(wrongRegion.summary.contains("地区不符"))
    }

    // MARK: - 3. 非回环 Socket 字符串解析与直连泄露判定

    @Test("回环连接与监听状态放行，非回环直连外网零容忍拦截")
    func socketLeakDetection() {
        // 合法回环代理连接 (IPv4 / IPv6 / IPv4-mapped IPv6)
        let validV4 = SocketAuditor.parseSocketNameField("127.0.0.1:52341->127.0.0.1:17892 (ESTABLISHED)", pid: 100, proto: "TCP")
        #expect(validV4 != nil)
        #expect(!SocketAuditor.isExternalLeak(validV4!))

        let validV6 = SocketAuditor.parseSocketNameField("[::1]:52342->[::1]:17892 (ESTABLISHED)", pid: 100, proto: "TCP")
        #expect(validV6 != nil)
        #expect(!SocketAuditor.isExternalLeak(validV6!))

        let validMapped = SocketAuditor.parseSocketNameField("[::ffff:127.0.0.1]:52343->[::ffff:127.0.0.1]:17892 (ESTABLISHED)", pid: 100, proto: "TCP")
        #expect(validMapped != nil)
        #expect(!SocketAuditor.isExternalLeak(validMapped!))

        let validDualStack = SocketAuditor.parseSocketNameField("[::7f00:1]:52344->[::7f00:1]:17892 (ESTABLISHED)", pid: 100, proto: "TCP")
        #expect(validDualStack != nil)
        #expect(!SocketAuditor.isExternalLeak(validDualStack!))

        // 合法监听与未连接 UDP
        let listen = SocketAuditor.parseSocketNameField("127.0.0.1:9229 (LISTEN)", pid: 100, proto: "TCP")
        #expect(listen != nil)
        #expect(!SocketAuditor.isExternalLeak(listen!))

        let wildcardUdp = SocketAuditor.parseSocketNameField("*:*", pid: 100, proto: "UDP")
        #expect(wildcardUdp != nil)
        #expect(!SocketAuditor.isExternalLeak(wildcardUdp!))

        // 违规直连外网（公网 IP、TUN fake-ip、直连 UDP DNS、IPv6 外网）
        let leakTcp = SocketAuditor.parseSocketNameField("192.168.1.5:52345->160.79.104.10:443 (ESTABLISHED)", pid: 100, proto: "TCP")
        #expect(leakTcp != nil)
        #expect(SocketAuditor.isExternalLeak(leakTcp!))

        let leakFakeIp = SocketAuditor.parseSocketNameField("198.18.0.1:52346->198.18.0.55:443 (SYN_SENT)", pid: 100, proto: "TCP")
        #expect(leakFakeIp != nil)
        #expect(SocketAuditor.isExternalLeak(leakFakeIp!))

        let leakUdpDns = SocketAuditor.parseSocketNameField("192.168.1.5:55111->8.8.8.8:53", pid: 100, proto: "UDP")
        #expect(leakUdpDns != nil)
        #expect(SocketAuditor.isExternalLeak(leakUdpDns!))

        let leakIpv6 = SocketAuditor.parseSocketNameField("[2400:4050::1]:55112->[2606:4700::6810]:443 (ESTABLISHED)", pid: 100, proto: "TCP")
        #expect(leakIpv6 != nil)
        #expect(SocketAuditor.isExternalLeak(leakIpv6!))
    }

    @Test("完整 lsof -nP 输出批量解析")
    func parseLsofOutputLines() {
        let lsofText = """
        COMMAND     PID    USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
        Claude    12345 alice   42u  IPv4 0x1234567890abcdef      0t0  TCP 127.0.0.1:51000->127.0.0.1:17892 (ESTABLISHED)
        Claude\\x20 12346 alice   51u  IPv4 0x2234567890abcdef      0t0  TCP 192.168.1.8:51001->104.18.0.1:443 (ESTABLISHED)
        Claude    12345 alice   55u  IPv4 0x3234567890abcdef      0t0  UDP *:*
        """
        let records = SocketAuditor.parseLsofOutput(lsofText)
        #expect(records.count == 3)
        let leaks = records.filter(SocketAuditor.isExternalLeak)
        #expect(leaks.count == 1)
        #expect(leaks[0].pid == 12346)
        #expect(leaks[0].remoteHost == "104.18.0.1")
        #expect(leaks[0].remotePort == 443)
    }

    // MARK: - 4. 防自杀进程路径过滤与命令行参数检查

    @Test("防误杀进程识别逻辑：仅匹配 Claude Desktop，绝不误杀 ClaudeGuard 或终端 CLI")
    func processSelfProtectionFilter() {
        let selfPid: pid_t = 9999

        // 合法目标：主进程与 Helper
        #expect(ProcessManager.isTargetClaudeProcess(
            pid: 2001,
            executablePath: "/Applications/Claude.app/Contents/MacOS/Claude",
            bundleIdentifier: "com.anthropic.claudefordesktop",
            selfPid: selfPid
        ))
        #expect(ProcessManager.isTargetClaudeProcess(
            pid: 2002,
            executablePath: "/Applications/Claude.app/Contents/Frameworks/Claude Helper (Renderer).app/Contents/MacOS/Claude Helper (Renderer)",
            bundleIdentifier: nil,
            selfPid: selfPid
        ))

        // 绝对禁止误杀：ClaudeGuard 自身 / 同 PID / 终端 claude CLI / 其他同名路径
        #expect(!ProcessManager.isTargetClaudeProcess(
            pid: selfPid,
            executablePath: "/Applications/Claude.app/Contents/MacOS/Claude",
            bundleIdentifier: nil,
            selfPid: selfPid
        ))
        #expect(!ProcessManager.isTargetClaudeProcess(
            pid: 3001,
            executablePath: "/Applications/ClaudeGuard.app/Contents/MacOS/ClaudeGuard",
            bundleIdentifier: "com.claudeguard.app",
            selfPid: selfPid
        ))
        #expect(!ProcessManager.isTargetClaudeProcess(
            pid: 3002,
            executablePath: "/opt/homebrew/bin/claude",
            bundleIdentifier: nil,
            selfPid: selfPid
        ))
        #expect(!ProcessManager.isTargetClaudeProcess(
            pid: 3003,
            executablePath: "/Users/alice/Claudeguard/.build/release/ClaudeGuard",
            bundleIdentifier: nil,
            selfPid: selfPid
        ))
        // 防止配置恶意根路径导致通配误杀
        #expect(ProcessManager.normalizedAppPrefix("/") == nil)
        #expect(ProcessManager.normalizedAppPrefix("/Applications") == nil)
        #expect(ProcessManager.normalizedAppPrefix("/Applications/Claude.app/") == "/Applications/Claude.app/")
    }

    @Test("代理启动参数精确校验与 KERN_PROCARGS2 二进制解析")
    func proxyArgumentAndKernProcArgs() {
        let ok = ProcessManager.hasExpectedProxyArgument(
            commandLine: "/Applications/Claude.app/Contents/MacOS/Claude --proxy-server=socks5://127.0.0.1:17892 --proxy-bypass-list=127.0.0.1;[::1];localhost --force-webrtc-ip-handling-policy=disable_non_proxied_udp",
            arguments: [
                "/Applications/Claude.app/Contents/MacOS/Claude",
                "--proxy-server=socks5://127.0.0.1:17892",
                "--proxy-bypass-list=127.0.0.1;[::1];localhost",
                "--force-webrtc-ip-handling-policy=disable_non_proxied_udp"
            ],
            proxyHost: "127.0.0.1",
            proxyPort: 17892
        )
        #expect(ok)

        // 防止端口前缀误匹配 (178920 != 17892)
        let prefixMismatch = ProcessManager.hasExpectedProxyArgument(
            commandLine: "/Applications/Claude.app/Contents/MacOS/Claude --proxy-server=socks5://127.0.0.1:178920",
            arguments: [
                "/Applications/Claude.app/Contents/MacOS/Claude",
                "--proxy-server=socks5://127.0.0.1:178920"
            ],
            proxyHost: "127.0.0.1",
            proxyPort: 17892
        )
        #expect(!prefixMismatch)

        // 构造模拟 KERN_PROCARGS2 数据（argc = 2 + execPath + \0\0 + argv[0] + argv[1]）
        var raw = Data()
        var argc: Int32 = 2
        withUnsafeBytes(of: &argc) { raw.append(contentsOf: $0) }
        raw.append(contentsOf: "/Applications/Claude.app/Contents/MacOS/Claude\0\0\0".utf8)
        raw.append(contentsOf: "/Applications/Claude.app/Contents/MacOS/Claude\0".utf8)
        raw.append(contentsOf: "--proxy-server=socks5://127.0.0.1:17892\0".utf8)

        let parsed = ProcessManager.parseKernProcArgs2(raw)
        #expect(parsed == [
            "/Applications/Claude.app/Contents/MacOS/Claude",
            "--proxy-server=socks5://127.0.0.1:17892"
        ])
    }

    // MARK: - 5. 配置存储、防串区锁、体检放行规则与日志轮转

    @Test("ConfigStore 默认预置参数与持久化读写")
    func configStorePersistence() throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("ClaudeGuardTests-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let store = ConfigStore(directoryURL: tempDir)
        let loaded = store.load()
        #expect(loaded.activeDesktopPresetId == "jp-static")
        #expect(loaded.presets.count == 2)
        #expect(loaded.presets[0].proxyPort == 17892)
        #expect(loaded.presets[0].expectedExitIp == "203.0.113.10")
        #expect(loaded.presets[1].proxyPort == 17891)
        #expect(loaded.presets[1].expectedExitIp == "198.51.100.20")
        #expect(loaded.requiresCrossRegionConfirmation(for: "us-static"))
        #expect(!loaded.requiresCrossRegionConfirmation(for: "jp-static"))

        var modified = loaded
        modified.activeDesktopPresetId = "us-static"
        try store.save(modified)

        let reloaded = store.load()
        #expect(reloaded.activeDesktopPresetId == "us-static")
    }

    @Test("PreFlightReport 放行门禁规则（含时区非阻断警告放行）")
    func preFlightGateRules() {
        let warningPass = PreFlightReport(
            presetId: "jp-static",
            items: [
                PreFlightItemResult(kind: .localPort, status: .passed, summary: "OK", detail: "", latencyMs: 1, hasResidualClaudeProcess: false, checkedAt: Date()),
                PreFlightItemResult(kind: .exitIp, status: .passed, summary: "OK", detail: "", latencyMs: 50, hasResidualClaudeProcess: false, checkedAt: Date()),
                PreFlightItemResult(kind: .regionPolicy, status: .passed, summary: "OK", detail: "", latencyMs: nil, hasResidualClaudeProcess: false, checkedAt: Date()),
                PreFlightItemResult(kind: .dnsAndIpv6, status: .passed, summary: "OK", detail: "", latencyMs: nil, hasResidualClaudeProcess: false, checkedAt: Date()),
                PreFlightItemResult(kind: .processAndTimezone, status: .warning, summary: "时区不同", detail: "", latencyMs: nil, hasResidualClaudeProcess: false, checkedAt: Date()),
                PreFlightItemResult(kind: .anthropicTls, status: .passed, summary: "OK", detail: "", latencyMs: 120, hasResidualClaudeProcess: false, checkedAt: Date())
            ],
            completedAt: Date()
        )
        #expect(warningPass.canPassGate)

        var residualBlock = warningPass
        residualBlock.items[4] = PreFlightItemResult(
            kind: .processAndTimezone,
            status: .failed,
            summary: "残留进程",
            detail: "",
            latencyMs: nil,
            hasResidualClaudeProcess: true,
            checkedAt: Date()
        )
        #expect(!residualBlock.canPassGate)
    }

    @Test("EventLogger 日志大小自动截断")
    func eventLoggerAutoTrim() {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("ClaudeGuardLogTests-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let logFile = tempDir.appendingPathComponent("events.log")
        let logger = EventLogger(logFileURL: logFile, maxBytes: 2048, keepBytes: 1024)

        for idx in 0..<80 {
            logger.log(level: .info, presetName: "JP", reason: "测试事件 #\(idx)", detail: String(repeating: "A", count: 40))
        }

        let attrs = try? FileManager.default.attributesOfItem(atPath: logFile.path)
        let size = (attrs?[.size] as? NSNumber)?.intValue ?? 0
        #expect(size > 0 && size <= 2048)
    }

    @Test("SafeLauncher 本地策略库写入 disableAutoUpdates 与 egressProxyUrl 并保留已有字段")
    func claudeLocalConfigLibrarySync() throws {
        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("ClaudeConfigLibTest-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let jpPreset = AppConfig.defaultPresets[0]
        try SafeLauncher.syncClaudeLocalConfigLibrary(preset: jpPreset, supportsHttpProxy: true, configLibraryDir: tempDir)

        let metaData = try Data(contentsOf: tempDir.appendingPathComponent("_meta.json"))
        let meta = try #require(try JSONSerialization.jsonObject(with: metaData) as? [String: Any])
        let appliedId = try #require(meta["appliedId"] as? String)
        #expect(appliedId.count == 36)
        #expect(appliedId == appliedId.lowercased())
        #expect(SafeLauncher.isValidLowercaseConfigId(appliedId))

        let cfgURL = tempDir.appendingPathComponent("\(appliedId).json")
        var cfg = try #require(try JSONSerialization.jsonObject(with: Data(contentsOf: cfgURL)) as? [String: Any])
        #expect(cfg["disableAutoUpdates"] as? Bool == true)
        #expect(cfg["egressProxyUrl"] as? String == "http://127.0.0.1:17892")

        // 模拟已有用户字段，切换到 US 预设再次同步应保留自定义字段且更新 egressProxyUrl
        cfg["customUserFlag"] = "keep-me"
        try JSONSerialization.data(withJSONObject: cfg, options: [.prettyPrinted]).write(to: cfgURL)

        let usPreset = AppConfig.defaultPresets[1]
        try SafeLauncher.syncClaudeLocalConfigLibrary(preset: usPreset, supportsHttpProxy: true, configLibraryDir: tempDir)

        let meta2 = try #require(try JSONSerialization.jsonObject(with: Data(contentsOf: tempDir.appendingPathComponent("_meta.json"))) as? [String: Any])
        #expect(meta2["appliedId"] as? String == appliedId)

        let cfg2 = try #require(try JSONSerialization.jsonObject(with: Data(contentsOf: cfgURL)) as? [String: Any])
        #expect(cfg2["disableAutoUpdates"] as? Bool == true)
        #expect(cfg2["egressProxyUrl"] as? String == "http://127.0.0.1:17891")
        #expect(cfg2["customUserFlag"] as? String == "keep-me")
    }
}
