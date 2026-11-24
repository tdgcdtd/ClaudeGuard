import Foundation
import AppKit

@MainActor
final class GuardCoordinator: ObservableObject {
    @Published var config: AppConfig
    @Published var phase: GuardPhase = .checking
    @Published var report: PreFlightReport
    @Published var portHealthList: [PresetPortHealth] = []
    @Published var isBusyLaunching: Bool = false
    @Published var isCheckingPorts: Bool = false
    @Published var loginItemEnabled: Bool = false
    @Published var statusErrorBanner: String?
    @Published var recentLogsText: String = ""

    let configStore: ConfigStore
    let eventLogger: EventLogger
    let watchdog: WatchdogService

    private var preFlightTask: Task<Void, Never>?
    private var wakeRecoveryTask: Task<Void, Never>?

    init(
        configStore: ConfigStore = ConfigStore(),
        eventLogger: EventLogger = EventLogger(),
        watchdog: WatchdogService? = nil
    ) {
        self.configStore = configStore
        self.eventLogger = eventLogger
        let resolvedWatchdog = watchdog ?? WatchdogService()
        self.watchdog = resolvedWatchdog

        let loadedConfig = configStore.load()
        self.config = loadedConfig
        self.report = PreFlightReport.initial(presetId: loadedConfig.activePreset.id)
        self.loginItemEnabled = LoginItemService.isEnabled
        self.recentLogsText = eventLogger.readRecentLogs()

        bindWatchdogCallbacks()
        resolvedWatchdog.installSystemListeners(initialConfig: loadedConfig)
        eventLogger.requestNotificationPermissionIfPossible()
    }

    func bootstrap() {
        Task {
            await refreshAllPorts()
            await evaluateInitialState()
        }
    }

    private func evaluateInitialState() async {
        let currentConfig = config
        let activePreset = currentConfig.activePreset
        let running = await Task.detached(priority: .utility) {
            ProcessManager.findClaudeProcesses(claudeAppPath: currentConfig.claudeAppPath)
        }.value

        if let mainProc = running.first(where: { $0.isMainProcess }),
           ProcessManager.hasExpectedProxyArgument(
               commandLine: mainProc.commandLine,
               arguments: mainProc.arguments,
               proxyHost: activePreset.proxyHost,
               proxyPort: activePreset.proxyPort
           ) {
            // 已有受代理参数启动的 Claude Desktop：先执行一次全量体检，安全则无缝接管守护
            let checkReport = await PreFlightChecker.runFullCheck(preset: activePreset, config: currentConfig)
            self.report = checkReport
            if checkReport.canPassGate {
                let now = Date()
                self.phase = .guarding(
                    startedAt: now,
                    presetId: activePreset.id,
                    controlledPidCount: running.count,
                    lastIpVerifiedAt: now
                )
                self.watchdog.isKillSwitchLocked = false
                self.watchdog.startGuarding(preset: activePreset, config: currentConfig)
                self.eventLogger.log(
                    level: .info,
                    presetName: activePreset.name,
                    reason: "接管运行中的受控 Claude Desktop 进程",
                    detail: "PID \(mainProc.pid)，共 \(running.count) 个进程"
                )
            } else {
                triggerEmergencyKillSwitch(
                    reason: "启动接管时发现代理环境异常",
                    detail: checkReport.firstFailureSummary ?? "环境体检未通过"
                )
            }
            return
        }

        await runPreFlightCheck(manualUnlock: false)
    }

    private func bindWatchdogCallbacks() {
        watchdog.onTriggerKillSwitch = { [weak self] reason, detail in
            self?.triggerEmergencyKillSwitch(reason: reason, detail: detail)
        }

        watchdog.onProcessExitedNormally = { [weak self] in
            guard let self else { return }
            guard !self.phase.isLocked else { return }
            self.eventLogger.log(
                level: .info,
                presetName: self.config.activePreset.name,
                reason: "Claude Desktop 已正常退出，停止高频巡检"
            )
            Task {
                await self.runPreFlightCheck(manualUnlock: false)
            }
        }

        watchdog.onProcessCountUpdated = { [weak self] count in
            guard let self else { return }
            if case .guarding(let startedAt, let presetId, _, let lastVerified) = self.phase {
                self.phase = .guarding(
                    startedAt: startedAt,
                    presetId: presetId,
                    controlledPidCount: count,
                    lastIpVerifiedAt: lastVerified
                )
            }
        }

        watchdog.onIpVerifiedUpdated = { [weak self] verifiedDate in
            guard let self else { return }
            if case .guarding(let startedAt, let presetId, let pidCount, _) = self.phase {
                self.phase = .guarding(
                    startedAt: startedAt,
                    presetId: presetId,
                    controlledPidCount: pidCount,
                    lastIpVerifiedAt: verifiedDate
                )
            }
        }

        watchdog.onWillSleepAction = { [weak self] in
            self?.handleSystemWillSleep()
        }

        watchdog.onDidWakeAction = { [weak self] in
            self?.handleSystemDidWake()
        }
    }

    // MARK: - 用户操作

    func selectPreset(_ presetId: String) {
        guard !phase.isGuarding else {
            statusErrorBanner = "守护运行期间不可直接切换预设，请先停止 Claude Desktop"
            return
        }
        guard config.presets.contains(where: { $0.id == presetId }) else { return }
        config.activeDesktopPresetId = presetId
        saveConfigSilently()

        if !phase.isLocked {
            Task {
                await runPreFlightCheck(manualUnlock: false)
            }
        }
    }

    func runPreFlightCheck(manualUnlock: Bool, preserveErrorBanner: Bool = false) async {
        preFlightTask?.cancel()
        wakeRecoveryTask?.cancel()

        if phase.isLocked && !manualUnlock {
            return
        }

        let currentConfig = config
        let preset = currentConfig.activePreset
        if !preserveErrorBanner {
            statusErrorBanner = nil
        }
        if manualUnlock {
            watchdog.isKillSwitchLocked = false
        }
        phase = .checking
        report = PreFlightReport.checking(presetId: preset.id)

        let task = Task {
            async let fullReportTask = PreFlightChecker.runFullCheck(preset: preset, config: currentConfig)
            async let portsTask = PreFlightChecker.probeAllPresetPorts(presets: currentConfig.presets)

            let finalReport = await fullReportTask
            let ports = await portsTask

            guard !Task.isCancelled else { return }
            self.report = finalReport
            self.portHealthList = ports

            if self.phase.isGuarding || (self.phase.isLocked && !manualUnlock) {
                return
            }

            if finalReport.canPassGate {
                if let warn = finalReport.firstWarningSummary {
                    self.phase = .readyWithWarning(warn)
                } else {
                    self.phase = .readySafe
                }
            } else {
                self.phase = .blockedPreFlight(finalReport.firstFailureSummary ?? "存在未通过的体检项目")
            }
        }

        preFlightTask = task
        await task.value
    }

    func refreshAllPorts() async {
        guard !isCheckingPorts else { return }
        isCheckingPorts = true
        defer { isCheckingPorts = false }
        let health = await PreFlightChecker.probeAllPresetPorts(presets: config.presets)
        portHealthList = health
    }

    func cleanResidualProcesses() {
        Task {
            let appPath = config.claudeAppPath
            let killed = await Task.detached(priority: .userInitiated) {
                ProcessManager.terminateClaudeGracefullyThenKill(claudeAppPath: appPath, graceMs: 300)
            }.value
            if !killed.isEmpty {
                eventLogger.log(
                    level: .info,
                    presetName: config.activePreset.name,
                    reason: "用户手动清理残留 Claude Desktop 进程",
                    detail: "PID: \(killed.map(String.init).joined(separator: ", "))"
                )
            }
            await runPreFlightCheck(manualUnlock: false)
        }
    }

    func requestSafeLaunch() {
        guard phase.canLaunch, !isBusyLaunching else { return }
        let targetPreset = config.activePreset

        // 桌面端防串区锁 (Anti-Cross-Region Guard)
        if config.requiresCrossRegionConfirmation(for: targetPreset.id) {
            let lastName = config.preset(for: config.lastLaunchedDesktopPresetId)?.name
                ?? config.lastLaunchedDesktopPresetId
            let alert = NSAlert()
            alert.alertStyle = .critical
            alert.messageText = "跨区启动风险警告"
            alert.informativeText = "上次桌面端使用「\(lastName)」启动，当前目标为「\(targetPreset.name)」。跨区切换存在关联风控风险，是否确认切换？"
            alert.addButton(withTitle: "确认跨区启动")
            alert.addButton(withTitle: "取消")
            if #available(macOS 14.0, *) {
                NSApp.activate()
            } else {
                NSApp.activate(ignoringOtherApps: true)
            }
            let response = alert.runModal()
            guard response == .alertFirstButtonReturn else {
                return
            }
        }

        Task {
            await performSafeLaunchSequence()
        }
    }

    private func performSafeLaunchSequence() async {
        isBusyLaunching = true
        statusErrorBanner = nil
        defer { isBusyLaunching = false }

        // 启动前自动复检
        await runPreFlightCheck(manualUnlock: false)
        guard report.canPassGate else {
            statusErrorBanner = report.firstFailureSummary ?? "启动前复检未通过，已拦截启动"
            return
        }

        let currentConfig = config
        let preset = currentConfig.activePreset

        watchdog.isControlledLaunchInProgress = true
        defer { watchdog.isControlledLaunchInProgress = false }

        do {
            let launchedProcs = try await SafeLauncher.launch(preset: preset, config: currentConfig)
            config.lastLaunchedDesktopPresetId = preset.id
            saveConfigSilently()

            let now = Date()
            watchdog.isKillSwitchLocked = false
            phase = .guarding(
                startedAt: now,
                presetId: preset.id,
                controlledPidCount: launchedProcs.count,
                lastIpVerifiedAt: now
            )
            watchdog.startGuarding(preset: preset, config: currentConfig)

            eventLogger.log(
                level: .launch,
                presetName: preset.name,
                reason: "安全启动 Claude Desktop 成功",
                detail: "端口 \(preset.socks5Endpoint) | 出口 \(preset.expectedExitIp) | 进程数 \(launchedProcs.count)"
            )
        } catch {
            let msg = error.localizedDescription
            statusErrorBanner = msg
            eventLogger.log(
                level: .warning,
                presetName: preset.name,
                reason: "安全启动未通过",
                detail: msg
            )
            await runPreFlightCheck(manualUnlock: false, preserveErrorBanner: true)
        }
    }

    func triggerEmergencyKillSwitch(reason: String, detail: String) {
        preFlightTask?.cancel()
        wakeRecoveryTask?.cancel()
        watchdog.stopGuarding()
        watchdog.isKillSwitchLocked = true

        let appPath = config.claudeAppPath
        let presetName = config.activePreset.name

        // 同步执行毫秒级 SIGKILL，确保不等异步调度
        let killed = ProcessManager.killAllClaudeImmediately(claudeAppPath: appPath)
        let pidSummary = killed.isEmpty ? "无存活进程" : "已强杀 PID: \(killed.map(String.init).joined(separator: ", "))"
        let fullDetail = detail.isEmpty ? pidSummary : "\(detail) | \(pidSummary)"

        phase = .killSwitchLocked(reason: reason, detail: fullDetail, triggeredAt: Date())
        statusErrorBanner = "\(reason)：\(fullDetail)"

        eventLogger.log(
            level: .killSwitch,
            presetName: presetName,
            reason: reason,
            detail: fullDetail
        )
        eventLogger.triggerKillSwitchAlert(reason: reason, detail: detail)
        refreshRecentLogs()
    }

    // MARK: - 休眠与唤醒保护

    private func handleSystemWillSleep() {
        let currentConfig = config
        let wasGuarding = phase.isGuarding

        if currentConfig.killDesktopOnSleep {
            let killed = ProcessManager.terminateClaudeGracefullyThenKill(
                claudeAppPath: currentConfig.claudeAppPath,
                graceMs: 300
            )
            if !killed.isEmpty || wasGuarding {
                watchdog.stopGuarding()
                eventLogger.log(
                    level: .sleepGuard,
                    presetName: currentConfig.activePreset.name,
                    reason: "系统即将休眠，已自动切断 Claude Desktop",
                    detail: killed.isEmpty ? "无残留进程" : "终止 PID: \(killed.map(String.init).joined(separator: ", "))"
                )
                refreshRecentLogs()
            }
        }

        if currentConfig.killDonutOnSleep {
            let donutKilled = ProcessManager.terminateDonutOnSleep(graceMs: 300)
            if !donutKilled.isEmpty {
                eventLogger.log(
                    level: .sleepGuard,
                    presetName: nil,
                    reason: "系统即将休眠，已关闭 Donut Browser",
                    detail: "PID: \(donutKilled.map(String.init).joined(separator: ", "))"
                )
                refreshRecentLogs()
            }
        }
    }

    private func handleSystemDidWake() {
        guard !phase.isLocked else { return }
        watchdog.stopGuarding()
        preFlightTask?.cancel()
        wakeRecoveryTask?.cancel()

        phase = .wakingUp
        report = PreFlightReport.checking(presetId: config.activePreset.id)

        wakeRecoveryTask = Task { [weak self] in
            // 唤醒后等待 3 秒让 Wi-Fi 与 Clash Verge 恢复
            try? await Task.sleep(nanoseconds: 3_000_000_000)
            guard !Task.isCancelled, let self else { return }
            guard !self.phase.isLocked else { return }

            await self.runPreFlightCheck(manualUnlock: false)
            if self.report.canPassGate {
                self.eventLogger.sendNotification(
                    title: "✅ ClaudeGuard 唤醒复检通过",
                    body: "代理通道 \(self.config.activePreset.name) 已恢复安全绿灯"
                )
            }
        }
    }

    // MARK: - 配置与开关

    func updateToggle(
        killDesktopOnSleep: Bool? = nil,
        killDonutOnSleep: Bool? = nil,
        guardRogueLaunch: Bool? = nil
    ) {
        if let v = killDesktopOnSleep { config.killDesktopOnSleep = v }
        if let v = killDonutOnSleep { config.killDonutOnSleep = v }
        if let v = guardRogueLaunch { config.guardRogueLaunch = v }
        saveConfigSilently()
    }

    func setLoginItem(_ enabled: Bool) {
        do {
            try LoginItemService.setEnabled(enabled)
            loginItemEnabled = LoginItemService.isEnabled
        } catch {
            loginItemEnabled = LoginItemService.isEnabled
            statusErrorBanner = "设置开机自启失败（建议将 ClaudeGuard.app 放入 /Applications）：\(error.localizedDescription)"
        }
    }

    func applyUpdatedConfig(_ newConfig: AppConfig) {
        let sanitized = newConfig.sanitized()
        config = sanitized
        saveConfigSilently()
        if !phase.isGuarding && !phase.isLocked {
            Task {
                await runPreFlightCheck(manualUnlock: false)
            }
        } else {
            Task {
                await refreshAllPorts()
            }
        }
    }

    func reloadConfigFromDisk() {
        let reloaded = configStore.load()
        config = reloaded
        watchdog.updateConfigSnapshot(reloaded)
        Task {
            await refreshAllPorts()
            if !phase.isGuarding && !phase.isLocked {
                await runPreFlightCheck(manualUnlock: false)
            }
        }
    }

    func refreshRecentLogs() {
        recentLogsText = eventLogger.readRecentLogs()
    }

    func clearLogs() {
        eventLogger.clearLogs()
        refreshRecentLogs()
    }

    private func saveConfigSilently() {
        do {
            try configStore.save(config)
            watchdog.updateConfigSnapshot(config)
        } catch {
            statusErrorBanner = "保存配置文件失败：\(error.localizedDescription)"
        }
    }
}
