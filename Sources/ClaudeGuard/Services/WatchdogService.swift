import Foundation
import AppKit
import Network

@MainActor
final class WatchdogService {
    private var pathMonitor: NWPathMonitor?
    private let pathQueue = DispatchQueue(label: "com.claudeguard.nwpath", qos: .utility)
    private var lastPathStatus: NWPath.Status?
    private var lastInterfaceSignature: String = ""

    private var workspaceObservers: [NSObjectProtocol] = []
    private var probeTask: Task<Void, Never>?
    private var auditTask: Task<Void, Never>?
    private var exitIpTask: Task<Void, Never>?

    private var activeConfig: AppConfig?
    private var activePreset: ProxyPreset?
    private var isGuardingActive = false
    var isControlledLaunchInProgress = false
    var isKillSwitchLocked = false

    var onTriggerKillSwitch: ((_ reason: String, _ detail: String) -> Void)?
    var onProcessExitedNormally: (() -> Void)?
    var onProcessCountUpdated: ((_ count: Int) -> Void)?
    var onIpVerifiedUpdated: ((_ date: Date) -> Void)?
    var onWillSleepAction: (() -> Void)?
    var onDidWakeAction: (() -> Void)?

    func installSystemListeners(initialConfig: AppConfig) {
        self.activeConfig = initialConfig
        installWorkspaceObservers()
        installPathMonitor()
    }

    func updateConfigSnapshot(_ config: AppConfig) {
        self.activeConfig = config
        if isGuardingActive {
            self.activePreset = config.activePreset
        }
    }

    func startGuarding(preset: ProxyPreset, config: AppConfig) {
        stopGuarding()
        self.activePreset = preset
        self.activeConfig = config
        self.isGuardingActive = true

        let fastInterval = UInt64(max(1, config.fastProbeIntervalSec)) * 1_000_000_000
        let auditInterval = UInt64(max(1, config.socketAuditIntervalSec)) * 1_000_000_000
        let exitInterval = UInt64(max(5, config.exitIpVerifyIntervalSec)) * 1_000_000_000

        // Loop A：每 2 秒轻量本地代理端口心跳
        probeTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: fastInterval)
                guard !Task.isCancelled, let self, self.isGuardingActive else { break }

                let probe = await PreFlightChecker.probeLocalPort(
                    host: preset.proxyHost,
                    port: preset.proxyPort,
                    timeoutSec: 1.2
                )
                guard !Task.isCancelled, self.isGuardingActive else { break }
                if !probe.alive {
                    self.onTriggerKillSwitch?(
                        "本地代理端口 \(preset.proxyPort) 断连",
                        probe.error ?? "Clash Verge 代理监听已停止"
                    )
                    break
                }
            }
        }

        // Loop B：每 3 秒直连 Socket 泄露与越权启动审计
        auditTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: auditInterval)
                guard !Task.isCancelled, let self, self.isGuardingActive else { break }
                let snapshotConfig = self.activeConfig ?? config

                let auditResult = await Task.detached(priority: .utility) { () -> (
                    processes: [ClaudeProcessInfo],
                    rogueFound: ClaudeProcessInfo?,
                    leaks: [SocketConnectionRecord]
                ) in
                    let procs = ProcessManager.findClaudeProcesses(claudeAppPath: snapshotConfig.claudeAppPath)
                    guard !procs.isEmpty else {
                        return ([], nil, [])
                    }
                    let rogue: ClaudeProcessInfo?
                    if snapshotConfig.guardRogueLaunch {
                        rogue = procs.first { proc in
                            proc.isMainProcess && !ProcessManager.hasExpectedProxyArgument(
                                commandLine: proc.commandLine,
                                arguments: proc.arguments,
                                proxyHost: preset.proxyHost,
                                proxyPort: preset.proxyPort
                            )
                        }
                    } else {
                        rogue = nil
                    }
                    let leaks = SocketAuditor.auditProcesses(pids: procs.map(\.pid))
                    return (procs, rogue, leaks)
                }.value

                guard !Task.isCancelled, self.isGuardingActive else { break }

                if auditResult.processes.isEmpty {
                    self.stopGuarding()
                    self.onProcessExitedNormally?()
                    break
                }

                self.onProcessCountUpdated?(auditResult.processes.count)

                if let firstLeak = auditResult.leaks.first {
                    self.onTriggerKillSwitch?(
                        "检测到直连外网 Socket",
                        "PID \(firstLeak.pid) \(firstLeak.proto) -> \(firstLeak.remoteDisplay)"
                    )
                    break
                }

                if let rogue = auditResult.rogueFound {
                    self.onTriggerKillSwitch?(
                        "检测到未走代理的 Claude 进程",
                        "PID \(rogue.pid) 未携带 \(preset.expectedProxyFlag)，请通过 ClaudeGuard 启动"
                    )
                    break
                }
            }
        }

        // Loop C：每 25 秒上游链式出口定期复验（IP 漂移零容忍，单次超时 1.5s 后重试一次）
        exitIpTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: exitInterval)
                guard !Task.isCancelled, let self, self.isGuardingActive else { break }
                let snapshotConfig = self.activeConfig ?? config

                let firstAttempt = await PreFlightChecker.verifyUpstreamExit(
                    preset: preset,
                    blockedCountries: snapshotConfig.blockedCountries
                )
                guard !Task.isCancelled, self.isGuardingActive else { break }

                switch firstAttempt {
                case .matched:
                    self.onIpVerifiedUpdated?(Date())
                case .drifted(let reason, let detail):
                    self.onTriggerKillSwitch?(reason, detail)
                    return
                case .transientError(let firstErr):
                    // 单次网络超时 1.5 秒后立刻重试一次，连续 2 次失败才熔断
                    try? await Task.sleep(nanoseconds: 1_500_000_000)
                    guard !Task.isCancelled, self.isGuardingActive else { break }

                    let secondAttempt = await PreFlightChecker.verifyUpstreamExit(
                        preset: preset,
                        blockedCountries: snapshotConfig.blockedCountries
                    )
                    guard !Task.isCancelled, self.isGuardingActive else { break }

                    switch secondAttempt {
                    case .matched:
                        self.onIpVerifiedUpdated?(Date())
                    case .drifted(let reason, let detail):
                        self.onTriggerKillSwitch?(reason, detail)
                        return
                    case .transientError(let secondErr):
                        self.onTriggerKillSwitch?(
                            "上游出口连续 2 次复验失败",
                            "\(firstErr) -> 重试失败: \(secondErr)"
                        )
                        return
                    }
                }
            }
        }
    }

    func stopGuarding() {
        isGuardingActive = false
        probeTask?.cancel()
        probeTask = nil
        auditTask?.cancel()
        auditTask = nil
        exitIpTask?.cancel()
        exitIpTask = nil
    }

    // MARK: - 系统事件监听器

    private func installWorkspaceObservers() {
        let nc = NSWorkspace.shared.notificationCenter

        let sleepObserver = nc.addObserver(
            forName: NSWorkspace.willSleepNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated {
                self?.onWillSleepAction?()
            }
        }

        let wakeObserver = nc.addObserver(
            forName: NSWorkspace.didWakeNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor [weak self] in
                self?.onDidWakeAction?()
            }
        }

        let launchObserver = nc.addObserver(
            forName: NSWorkspace.didLaunchApplicationNotification,
            object: nil,
            queue: .main
        ) { [weak self] notification in
            guard let app = notification.userInfo?[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication,
                  app.bundleIdentifier == ProcessManager.claudeBundleId else {
                return
            }
            let pid = app.processIdentifier
            Task { @MainActor [weak self] in
                self?.handleClaudeAppLaunchedEvent(pid: pid)
            }
        }

        let terminateObserver = nc.addObserver(
            forName: NSWorkspace.didTerminateApplicationNotification,
            object: nil,
            queue: .main
        ) { [weak self] notification in
            guard let app = notification.userInfo?[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication,
                  app.bundleIdentifier == ProcessManager.claudeBundleId else {
                return
            }
            Task { @MainActor [weak self] in
                guard let self, self.isGuardingActive else { return }
                let remaining = ProcessManager.findClaudeProcesses(
                    claudeAppPath: self.activeConfig?.claudeAppPath ?? "/Applications/Claude.app"
                )
                if remaining.isEmpty {
                    self.stopGuarding()
                    self.onProcessExitedNormally?()
                }
            }
        }

        workspaceObservers = [sleepObserver, wakeObserver, launchObserver, terminateObserver]
    }

    private func handleClaudeAppLaunchedEvent(pid: pid_t) {
        guard let config = activeConfig, config.guardRogueLaunch else { return }
        if isControlledLaunchInProgress { return }

        if isKillSwitchLocked {
            onTriggerKillSwitch?(
                "熔断锁定期间拦截到启动 Claude",
                "PID \(pid) 尝试绕过锁定启动，请先在 ClaudeGuard 中点击「重新体检」"
            )
            return
        }

        let preset = activePreset ?? config.activePreset
        let args = ProcessManager.arguments(for: pid)
        let cmd = args.joined(separator: " ")
        let hasProxy = ProcessManager.hasExpectedProxyArgument(
            commandLine: cmd,
            arguments: args,
            proxyHost: preset.proxyHost,
            proxyPort: preset.proxyPort
        )

        if !hasProxy {
            onTriggerKillSwitch?(
                "拦截到未通过 ClaudeGuard 的手动启动",
                "PID \(pid) 缺少参数 \(preset.expectedProxyFlag)，请通过 ClaudeGuard 启动"
            )
        }
    }

    private func installPathMonitor() {
        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { [weak self] path in
            let ifaceSig = path.availableInterfaces.map { "\($0.name):\($0.type)" }.sorted().joined(separator: ",")
            let status = path.status
            Task { @MainActor [weak self] in
                self?.handleNetworkPathChange(status: status, interfaceSignature: ifaceSig)
            }
        }
        monitor.start(queue: pathQueue)
        self.pathMonitor = monitor
    }

    private func handleNetworkPathChange(status: NWPath.Status, interfaceSignature: String) {
        defer {
            lastPathStatus = status
            lastInterfaceSignature = interfaceSignature
        }

        guard isGuardingActive else { return }

        if status != .satisfied {
            onTriggerKillSwitch?(
                "系统网络连接断开",
                "NWPathMonitor 检测到网络变为不可用状态，已立即熔断"
            )
            return
        }

        if let prevStatus = lastPathStatus, prevStatus == .satisfied,
           !lastInterfaceSignature.isEmpty, lastInterfaceSignature != interfaceSignature,
           let preset = activePreset, let config = activeConfig {
            Task { [weak self] in
                guard let self, self.isGuardingActive else { return }
                let probe = await PreFlightChecker.probeLocalPort(host: preset.proxyHost, port: preset.proxyPort, timeoutSec: 1.5)
                if !probe.alive {
                    self.onTriggerKillSwitch?(
                        "网络切换后本地代理端口断连",
                        "接口变更为 \(interfaceSignature)，端口 \(preset.proxyPort) 不可达"
                    )
                    return
                }
                let exitOutcome = await PreFlightChecker.verifyUpstreamExit(
                    preset: preset,
                    blockedCountries: config.blockedCountries
                )
                if case .drifted(let reason, let detail) = exitOutcome {
                    self.onTriggerKillSwitch?(reason, "网络切换触发复验异常: \(detail)")
                }
            }
        }
    }

    deinit {
        pathMonitor?.cancel()
        for obs in workspaceObservers {
            NSWorkspace.shared.notificationCenter.removeObserver(obs)
        }
    }
}
