import Foundation
import Network

enum ExitVerifyOutcome: Equatable, Sendable {
    case matched(ip: String)
    case drifted(reason: String, detail: String)
    case transientError(String)
}

enum PreFlightChecker {
    private final class ResumeOnceBox<T>: @unchecked Sendable {
        private let lock = NSLock()
        private var continuation: CheckedContinuation<T, Never>?

        init(_ continuation: CheckedContinuation<T, Never>) {
            self.continuation = continuation
        }

        func resume(returning value: T) {
            lock.lock()
            let cont = continuation
            continuation = nil
            lock.unlock()
            cont?.resume(returning: value)
        }
    }

    struct CurlResponse: Sendable {
        var exitCode: Int32
        var stdout: String
        var stderr: String
        var elapsedMs: Int
    }

    // MARK: - 纯判断逻辑（供单元测试直接覆盖）

    static func evaluateExitIp(actualIp: String?, expectedIp: String) -> (passed: Bool, summary: String, detail: String) {
        let expected = expectedIp.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let actual = actualIp?.trimmingCharacters(in: .whitespacesAndNewlines), !actual.isEmpty else {
            return (false, "未获取到出口 IP", "期望: \(expected)")
        }
        guard !expected.isEmpty else {
            return (false, "预设未配置期望出口 IP", "实际出口 IP: \(actual)")
        }
        if actual == expected {
            return (true, actual, "与预设 \(expected) 完全一致")
        }
        return (false, "IP 不匹配: \(actual)", "期望 \(expected)，实际 \(actual)")
    }

    static func evaluateRegion(
        actualLoc: String?,
        expectedCountry: String,
        blockedCountries: [String]
    ) -> (passed: Bool, summary: String, detail: String) {
        let expected = expectedCountry.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
        let blockedSet = Set(blockedCountries.map { $0.trimmingCharacters(in: .whitespacesAndNewlines).uppercased() })

        guard let loc = actualLoc?.trimmingCharacters(in: .whitespacesAndNewlines).uppercased(), !loc.isEmpty else {
            return (false, "未获取到地区码", "期望地区: \(expected)")
        }
        if blockedSet.contains(loc) {
            return (false, "命中受限地区: \(loc)", "该地区位于 blockedCountries 拦截列表中")
        }
        if !expected.isEmpty && loc != expected {
            return (false, "地区不符: \(loc)", "期望 \(expected)，实际 \(loc)")
        }
        return (true, loc, "符合预期地区 \(expected) 且不在受限列表")
    }

    // MARK: - 本地代理端口探活 (NWConnection)

    static func probeLocalPort(
        host: String,
        port: Int,
        timeoutSec: Double = 2.0
    ) async -> (alive: Bool, latencyMs: Int?, error: String?) {
        guard (1...65535).contains(port), let nwPort = NWEndpoint.Port(rawValue: UInt16(port)) else {
            return (false, nil, "无效端口号 \(port)")
        }
        let start = DispatchTime.now()

        return await withCheckedContinuation { continuation in
            let box = ResumeOnceBox<(alive: Bool, latencyMs: Int?, error: String?)>(continuation)
            let queue = DispatchQueue(label: "com.claudeguard.portprobe.\(port)", qos: .userInitiated)
            let connection = NWConnection(host: NWEndpoint.Host(host), port: nwPort, using: .tcp)

            let timeoutWork = DispatchWorkItem {
                connection.cancel()
                box.resume(returning: (false, nil, "连接超时"))
            }
            queue.asyncAfter(deadline: .now() + timeoutSec, execute: timeoutWork)

            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    timeoutWork.cancel()
                    let elapsedNs = DispatchTime.now().uptimeNanoseconds - start.uptimeNanoseconds
                    let ms = max(1, Int(elapsedNs / 1_000_000))
                    connection.cancel()
                    box.resume(returning: (true, ms, nil))
                case .failed(let error):
                    timeoutWork.cancel()
                    connection.cancel()
                    box.resume(returning: (false, nil, error.localizedDescription))
                case .cancelled:
                    break
                default:
                    break
                }
            }

            connection.start(queue: queue)
        }
    }

    static func probeAllPresetPorts(presets: [ProxyPreset]) async -> [PresetPortHealth] {
        await withTaskGroup(of: (Int, PresetPortHealth).self) { group in
            for (index, preset) in presets.enumerated() {
                group.addTask {
                    let result = await probeLocalPort(host: preset.proxyHost, port: preset.proxyPort, timeoutSec: 1.8)
                    let health = PresetPortHealth(
                        presetId: preset.id,
                        shortLabel: preset.shortLabel,
                        port: preset.proxyPort,
                        isAlive: result.alive,
                        latencyMs: result.latencyMs,
                        checkedAt: Date()
                    )
                    return (index, health)
                }
            }
            var ordered = Array<PresetPortHealth?>(repeating: nil, count: presets.count)
            for await (index, health) in group {
                ordered[index] = health
            }
            return ordered.compactMap { $0 }
        }
    }

    // MARK: - 异步 /usr/bin/curl 执行器（强制走 --socks5-hostname 零本地 DNS 泄露）

    static func runCurl(arguments: [String]) async -> CurlResponse {
        let start = DispatchTime.now()
        return await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .utility).async {
                let process = Process()
                process.executableURL = URL(fileURLWithPath: "/usr/bin/curl")
                process.arguments = arguments

                let stdoutPipe = Pipe()
                let stderrPipe = Pipe()
                process.standardOutput = stdoutPipe
                process.standardError = stderrPipe

                do {
                    try process.run()
                    var stdoutData = Data()
                    var stderrData = Data()
                    let ioGroup = DispatchGroup()

                    ioGroup.enter()
                    DispatchQueue.global(qos: .utility).async {
                        stdoutData = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
                        ioGroup.leave()
                    }

                    ioGroup.enter()
                    DispatchQueue.global(qos: .utility).async {
                        stderrData = stderrPipe.fileHandleForReading.readDataToEndOfFile()
                        ioGroup.leave()
                    }

                    process.waitUntilExit()
                    ioGroup.wait()

                    let elapsedNs = DispatchTime.now().uptimeNanoseconds - start.uptimeNanoseconds
                    let ms = max(1, Int(elapsedNs / 1_000_000))
                    let out = String(data: stdoutData, encoding: .utf8) ?? ""
                    let err = String(data: stderrData, encoding: .utf8) ?? ""
                    continuation.resume(returning: CurlResponse(
                        exitCode: process.terminationStatus,
                        stdout: out,
                        stderr: err,
                        elapsedMs: ms
                    ))
                } catch {
                    let elapsedNs = DispatchTime.now().uptimeNanoseconds - start.uptimeNanoseconds
                    let ms = max(1, Int(elapsedNs / 1_000_000))
                    continuation.resume(returning: CurlResponse(
                        exitCode: -1,
                        stdout: "",
                        stderr: error.localizedDescription,
                        elapsedMs: ms
                    ))
                }
            }
        }
    }

    private static func baseSocksArgs(for preset: ProxyPreset, maxTime: Int = 10, connectTimeout: Int = 6) -> [String] {
        [
            "-sS",
            "--socks5-hostname", preset.socks5Endpoint,
            "--connect-timeout", "\(connectTimeout)",
            "--max-time", "\(maxTime)"
        ]
    }

    // MARK: - 6 项全量并发体检引擎

    static func runFullCheck(preset: ProxyPreset, config: AppConfig) async -> PreFlightReport {
        let now = Date()

        // 第 1 项：先快速验证本地代理端口是否存活
        let portProbe = await probeLocalPort(host: preset.proxyHost, port: preset.proxyPort, timeoutSec: 2.0)
        let localPortItem = PreFlightItemResult(
            kind: .localPort,
            status: portProbe.alive ? .passed : .failed,
            summary: portProbe.alive
                ? "\(preset.socks5Endpoint) 监听正常"
                : "\(preset.socks5Endpoint) 未连通",
            detail: portProbe.alive
                ? "TCP 握手 \(portProbe.latencyMs ?? 1) ms"
                : (portProbe.error ?? "本地代理端口未响应，请检查 Clash Verge"),
            latencyMs: portProbe.latencyMs,
            hasResidualClaudeProcess: false,
            checkedAt: Date()
        )

        // 第 5 项：进程干净度与时区核对不依赖网络，始终执行
        let item5 = checkProcessAndTimezone(preset: preset, config: config)

        guard portProbe.alive else {
            let reason = "本地代理端口 \(preset.socks5Endpoint) 未连通，跳过上游网络检测"
            let failItem: (PreFlightCheckKind) -> PreFlightItemResult = { kind in
                PreFlightItemResult(
                    kind: kind,
                    status: .failed,
                    summary: "前置代理未就绪",
                    detail: reason,
                    latencyMs: nil,
                    hasResidualClaudeProcess: false,
                    checkedAt: Date()
                )
            }
            return PreFlightReport(
                presetId: preset.id,
                items: [
                    localPortItem,
                    failItem(.exitIp),
                    failItem(.regionPolicy),
                    failItem(.dnsAndIpv6),
                    item5,
                    failItem(.anthropicTls)
                ],
                completedAt: Date()
            )
        }

        // 第 1 项通过后并发执行上游 trace、TLS 连通性、IPv6 泄露检查
        async let traceTask = fetchTraceAndBackupIp(preset: preset)
        async let claudeTlsTask = probeTlsEndpoint(url: "https://claude.ai", preset: preset)
        async let apiTlsTask = probeTlsEndpoint(url: "https://api.anthropic.com", preset: preset)
        async let ipv6Task = probeIpv6Leak(preset: preset)

        let (traceInfo, backupIp, traceLatencyMs, traceError) = await traceTask
        let claudeTls = await claudeTlsTask
        let apiTls = await apiTlsTask
        let ipv6Result = await ipv6Task

        // 第 2 项：出口 IP 精确锁死
        let effectiveIp = traceInfo?.ip ?? backupIp
        let ipEval = evaluateExitIp(actualIp: effectiveIp, expectedIp: preset.expectedExitIp)
        let item2 = PreFlightItemResult(
            kind: .exitIp,
            status: ipEval.passed ? .passed : .failed,
            summary: ipEval.summary,
            detail: ipEval.passed ? ipEval.detail : (traceError ?? ipEval.detail),
            latencyMs: traceLatencyMs,
            hasResidualClaudeProcess: false,
            checkedAt: Date()
        )

        // 第 3 项：地区与受限区核验
        let regionEval = evaluateRegion(
            actualLoc: traceInfo?.loc,
            expectedCountry: preset.expectedCountry,
            blockedCountries: config.blockedCountries
        )
        let item3 = PreFlightItemResult(
            kind: .regionPolicy,
            status: regionEval.passed ? .passed : .failed,
            summary: regionEval.summary,
            detail: regionEval.detail,
            latencyMs: nil,
            hasResidualClaudeProcess: false,
            checkedAt: Date()
        )

        // 第 4 项：远程 DNS 与 IPv6 穿透检查
        let dnsPassed = claudeTls.ok && apiTls.ok
        let item4: PreFlightItemResult
        if !dnsPassed {
            item4 = PreFlightItemResult(
                kind: .dnsAndIpv6,
                status: .failed,
                summary: "远程 DNS/域名解析失败",
                detail: "claude.ai 或 api.anthropic.com 无法经 socks5h 解析连通",
                latencyMs: nil,
                hasResidualClaudeProcess: false,
                checkedAt: Date()
            )
        } else if let leakedIpv6 = ipv6Result.leakedIpv6 {
            item4 = PreFlightItemResult(
                kind: .dnsAndIpv6,
                status: .warning,
                summary: "存在非预期 IPv6 出口",
                detail: "远程 DNS 正常，但检测到 IPv6 出口: \(leakedIpv6)",
                latencyMs: ipv6Result.latencyMs,
                hasResidualClaudeProcess: false,
                checkedAt: Date()
            )
        } else {
            item4 = PreFlightItemResult(
                kind: .dnsAndIpv6,
                status: .passed,
                summary: "远程 DNS 正常 · 无 IPv6 泄露",
                detail: "socks5h 解析 claude.ai / api.anthropic.com 正常，IPv6 探测已阻断",
                latencyMs: ipv6Result.latencyMs,
                hasResidualClaudeProcess: false,
                checkedAt: Date()
            )
        }

        // 第 6 项：Anthropic 端点 TLS 握手连通性
        let item6: PreFlightItemResult
        if claudeTls.ok && apiTls.ok {
            let maxMs = max(claudeTls.tlsMs, apiTls.tlsMs)
            item6 = PreFlightItemResult(
                kind: .anthropicTls,
                status: .passed,
                summary: "TLS 握手正常 (\(maxMs) ms)",
                detail: "claude.ai HTTP \(claudeTls.httpCode) (\(claudeTls.tlsMs) ms) · api.anthropic.com HTTP \(apiTls.httpCode) (\(apiTls.tlsMs) ms)",
                latencyMs: maxMs,
                hasResidualClaudeProcess: false,
                checkedAt: Date()
            )
        } else {
            let errSummary = !claudeTls.ok ? "claude.ai 握手失败" : "api.anthropic.com 握手失败"
            let errDetail = "claude.ai: \(claudeTls.detail) | api.anthropic.com: \(apiTls.detail)"
            item6 = PreFlightItemResult(
                kind: .anthropicTls,
                status: .failed,
                summary: errSummary,
                detail: errDetail,
                latencyMs: nil,
                hasResidualClaudeProcess: false,
                checkedAt: Date()
            )
        }

        _ = now
        return PreFlightReport(
            presetId: preset.id,
            items: [localPortItem, item2, item3, item4, item5, item6],
            completedAt: Date()
        )
    }

    // MARK: - 各项内部探测实现

    private static func fetchTraceAndBackupIp(preset: ProxyPreset) async -> (trace: CdnTraceInfo?, backupIp: String?, latencyMs: Int?, error: String?) {
        let primaryArgs = baseSocksArgs(for: preset) + ["https://claude.ai/cdn-cgi/trace"]
        let primary = await runCurl(arguments: primaryArgs)
        if primary.exitCode == 0 {
            let parsed = CdnTraceInfo.parse(primary.stdout)
            if parsed.ip != nil && parsed.loc != nil {
                return (parsed, parsed.ip, primary.elapsedMs, nil)
            }
        }

        // 主 trace 失败或字段残缺时请求备用 ipify
        let ipifyArgs = baseSocksArgs(for: preset) + ["https://api.ipify.org"]
        let ipify = await runCurl(arguments: ipifyArgs)
        let backupIp = ipify.exitCode == 0
            ? ipify.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            : nil

        let parsedPrimary = primary.exitCode == 0 ? CdnTraceInfo.parse(primary.stdout) : nil
        let err = primary.exitCode != 0 ? "curl(\(primary.exitCode)): \(primary.stderr.trimmingCharacters(in: .whitespacesAndNewlines))" : nil
        return (parsedPrimary, backupIp?.isEmpty == false ? backupIp : nil, primary.elapsedMs, err)
    }

    private struct TlsProbeResult: Sendable {
        var ok: Bool
        var httpCode: Int
        var tlsMs: Int
        var detail: String
    }

    private static func probeTlsEndpoint(url: String, preset: ProxyPreset) async -> TlsProbeResult {
        let args = baseSocksArgs(for: preset) + [
            "-I",
            "-o", "/dev/null",
            "-w", "%{http_code}|%{time_appconnect}|%{ssl_verify_result}",
            url
        ]
        let resp = await runCurl(arguments: args)
        guard resp.exitCode == 0 else {
            return TlsProbeResult(
                ok: false,
                httpCode: 0,
                tlsMs: resp.elapsedMs,
                detail: "curl(\(resp.exitCode)) \(resp.stderr.trimmingCharacters(in: .whitespacesAndNewlines))"
            )
        }
        let parts = resp.stdout.trimmingCharacters(in: .whitespacesAndNewlines).split(separator: "|")
        let code = parts.count > 0 ? (Int(parts[0]) ?? 0) : 0
        let appConnectSec = parts.count > 1 ? (Double(parts[1]) ?? 0.0) : 0.0
        let sslVerify = parts.count > 2 ? (Int(parts[2]) ?? -1) : -1
        let tlsMs = appConnectSec > 0 ? max(1, Int(appConnectSec * 1000.0)) : resp.elapsedMs

        let validHttp = (100..<500).contains(code)
        let sslOk = (sslVerify == 0)
        if validHttp && sslOk {
            return TlsProbeResult(ok: true, httpCode: code, tlsMs: tlsMs, detail: "HTTP \(code)")
        }
        return TlsProbeResult(
            ok: false,
            httpCode: code,
            tlsMs: tlsMs,
            detail: "HTTP \(code), ssl_verify=\(sslVerify)"
        )
    }

    private static func probeIpv6Leak(preset: ProxyPreset) async -> (leakedIpv6: String?, latencyMs: Int?) {
        let args = [
            "-6", "-sS",
            "--socks5-hostname", preset.socks5Endpoint,
            "--connect-timeout", "3",
            "--max-time", "4",
            "https://api6.ipify.org"
        ]
        let resp = await runCurl(arguments: args)
        guard resp.exitCode == 0 else {
            return (nil, resp.elapsedMs)
        }
        let body = resp.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
        if !body.isEmpty && body.contains(":") && body != preset.expectedExitIp {
            return (body, resp.elapsedMs)
        }
        return (nil, resp.elapsedMs)
    }

    static func checkProcessAndTimezone(preset: ProxyPreset, config: AppConfig) -> PreFlightItemResult {
        let processes = ProcessManager.findClaudeProcesses(claudeAppPath: config.claudeAppPath)
        let unproxiedMain = processes.filter { proc in
            proc.isMainProcess && !ProcessManager.hasExpectedProxyArgument(
                commandLine: proc.commandLine,
                arguments: proc.arguments,
                proxyHost: preset.proxyHost,
                proxyPort: preset.proxyPort
            )
        }
        let hasMain = processes.contains(where: { $0.isMainProcess })
        let hasResidual: Bool
        let processMsg: String
        if !unproxiedMain.isEmpty {
            hasResidual = true
            processMsg = "发现 \(unproxiedMain.count) 个未携带代理参数的 Claude 进程"
        } else if !hasMain && !processes.isEmpty {
            hasResidual = true
            processMsg = "发现 \(processes.count) 个残留 Claude Helper 进程"
        } else {
            hasResidual = false
            processMsg = processes.isEmpty ? "无残留进程" : "已有受控进程(\(processes.count))"
        }

        NSTimeZone.resetSystemTimeZone()
        let currentTz = TimeZone.autoupdatingCurrent.identifier
        let expectedTz = preset.expectedTimezone.trimmingCharacters(in: .whitespacesAndNewlines)
        let tzMatches = expectedTz.isEmpty || currentTz == expectedTz

        if hasResidual {
            return PreFlightItemResult(
                kind: .processAndTimezone,
                status: .failed,
                summary: processMsg,
                detail: "存在未受代理托管的进程，请点击右侧「一键清理」后再启动 | 当前时区 \(currentTz)",
                latencyMs: nil,
                hasResidualClaudeProcess: true,
                checkedAt: Date()
            )
        }

        if !tzMatches {
            let status: CheckStatus = preset.strictTimezoneCheck ? .failed : .warning
            return PreFlightItemResult(
                kind: .processAndTimezone,
                status: status,
                summary: "时区不同: \(currentTz)（期望 \(expectedTz)）",
                detail: preset.strictTimezoneCheck
                    ? "已开启严格时区校验，请将系统时区调整为 \(expectedTz)"
                    : "进程干净；系统时区与目标 \(expectedTz) 不一致（非阻断提醒）",
                latencyMs: nil,
                hasResidualClaudeProcess: false,
                checkedAt: Date()
            )
        }

        return PreFlightItemResult(
            kind: .processAndTimezone,
            status: .passed,
            summary: "\(processMsg) · 时区 \(currentTz)",
            detail: "无未代理残留进程，时区一致",
            latencyMs: nil,
            hasResidualClaudeProcess: false,
            checkedAt: Date()
        )
    }

    // MARK: - 运行期上游出口 IP 复验（区分漂移零容忍与单次网络抖动）

    static func verifyUpstreamExit(preset: ProxyPreset, blockedCountries: [String]) async -> ExitVerifyOutcome {
        let traceArgs = baseSocksArgs(for: preset, maxTime: 8, connectTimeout: 5) + ["https://claude.ai/cdn-cgi/trace"]
        let resp = await runCurl(arguments: traceArgs)

        if resp.exitCode == 0 {
            let trace = CdnTraceInfo.parse(resp.stdout)
            if let ip = trace.ip {
                let ipCheck = evaluateExitIp(actualIp: ip, expectedIp: preset.expectedExitIp)
                if !ipCheck.passed {
                    return .drifted(reason: "检测到出口 IP 漂移", detail: ipCheck.detail)
                }
                if let loc = trace.loc {
                    let regionCheck = evaluateRegion(
                        actualLoc: loc,
                        expectedCountry: preset.expectedCountry,
                        blockedCountries: blockedCountries
                    )
                    if !regionCheck.passed {
                        return .drifted(reason: "检测到出口地区异常", detail: regionCheck.detail)
                    }
                }
                return .matched(ip: ip)
            }
        }

        // 主 trace 网络异常或无 ip= 时尝试一次备用 ipify
        let ipifyArgs = baseSocksArgs(for: preset, maxTime: 6, connectTimeout: 4) + ["https://api.ipify.org"]
        let ipifyResp = await runCurl(arguments: ipifyArgs)
        if ipifyResp.exitCode == 0 {
            let ip = ipifyResp.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            if !ip.isEmpty {
                let ipCheck = evaluateExitIp(actualIp: ip, expectedIp: preset.expectedExitIp)
                if !ipCheck.passed {
                    return .drifted(reason: "检测到出口 IP 漂移", detail: ipCheck.detail)
                }
                return .matched(ip: ip)
            }
        }

        let errMsg = resp.stderr.trimmingCharacters(in: .whitespacesAndNewlines)
        return .transientError(errMsg.isEmpty ? "出口 IP 探测超时或无响应" : errMsg)
    }
}
