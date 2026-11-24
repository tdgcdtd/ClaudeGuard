import SwiftUI

struct StatusPopoverView: View {
    @ObservedObject var coordinator: GuardCoordinator
    var onOpenSettings: () -> Void
    var onOpenLogs: () -> Void
    var onQuitRequested: () -> Void

    private static let timeFormatter: DateFormatter = {
        let df = DateFormatter()
        df.locale = Locale(identifier: "en_US_POSIX")
        df.dateFormat = "HH:mm:ss"
        return df
    }()

    var body: some View {
        VStack(spacing: 10) {
            statusBanner
            presetAndPortsSection
            checkItemsSection
            if let err = coordinator.statusErrorBanner, !coordinator.phase.isLocked {
                errorNoteBanner(err)
            }
            actionSection
            Divider()
            quickTogglesAndFooter
        }
        .padding(14)
        .frame(width: 420)
        .background(Color(nsColor: .windowBackgroundColor))
    }

    // MARK: - 1. 顶部状态横幅

    private var statusBanner: some View {
        let info = bannerPresentation(for: coordinator.phase)
        return HStack(alignment: .center, spacing: 10) {
            Image(systemName: info.icon)
                .font(.system(size: 20, weight: .semibold))
                .foregroundColor(info.tint)

            VStack(alignment: .leading, spacing: 2) {
                Text(info.title)
                    .font(.system(size: 13.5, weight: .semibold))
                    .foregroundColor(.primary)
                Text(info.subtitle)
                    .font(.system(size: 11.5))
                    .foregroundColor(.secondary)
                    .lineLimit(2)
            }
            Spacer(minLength: 4)
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .fill(info.tint.opacity(0.12))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .stroke(info.tint.opacity(0.35), lineWidth: 1)
        )
    }

    private func bannerPresentation(for phase: GuardPhase) -> (icon: String, title: String, subtitle: String, tint: Color) {
        switch phase {
        case .checking:
            return ("hourglass.circle.fill", "正在执行 6 项全量环境体检...", "校验本地端口、出口 IP、地区策略、IPv6 与 TLS 握手", .orange)
        case .wakingUp:
            return ("moon.zzz.fill", "唤醒恢复中（待复检）", "等待 Wi-Fi 与 Clash Verge 稳定后将自动复检", .orange)
        case .readySafe:
            return ("checkmark.shield.fill", "环境安全，可启动 Claude Desktop", "6 项体检全绿 · 目标 \(coordinator.config.activePreset.expectedExitIp)", .green)
        case .readyWithWarning(let warn):
            return ("exclamationmark.shield.fill", "核心安全已通过（含非阻断提醒）", warn, .orange)
        case .blockedPreFlight(let reason):
            return ("xmark.shield.fill", "环境异常，已禁止启动", reason, .red)
        case .guarding(_, let presetId, let pidCount, _):
            let presetName = coordinator.config.preset(for: presetId)?.name ?? presetId
            return ("lock.shield.fill", "安全 · 守护中（\(presetName)）", "三层实时监控运行中 · 已托管 \(pidCount) 个进程", .green)
        case .killSwitchLocked(let reason, let detail, _):
            return ("bolt.shield.fill", "已触发熔断：\(reason)", "\(detail) — 请排查后点击「重新体检」解锁", .red)
        }
    }

    // MARK: - 2. 多预设切换与 Donut 全预设端口状态条

    private var presetAndPortsSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                Text("桌面预设")
                    .font(.system(size: 12, weight: .medium))
                    .foregroundColor(.secondary)

                Picker("", selection: Binding(
                    get: { coordinator.config.activeDesktopPresetId },
                    set: { coordinator.selectPreset($0) }
                )) {
                    ForEach(coordinator.config.presets) { preset in
                        Text("\(preset.name) (:\(preset.proxyPort))")
                            .tag(preset.id)
                    }
                }
                .labelsHidden()
                .disabled(coordinator.phase.isGuarding || coordinator.isBusyLaunching)
            }

            HStack(spacing: 6) {
                Text("全端口:")
                    .font(.system(size: 11, weight: .medium))
                    .foregroundColor(.secondary)

                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 6) {
                        ForEach(coordinator.config.presets) { preset in
                            let health = coordinator.portHealthList.first(where: { $0.presetId == preset.id })
                            portPill(preset: preset, health: health)
                        }
                    }
                }

                Spacer(minLength: 2)

                Button {
                    Task { await coordinator.refreshAllPorts() }
                } label: {
                    Image(systemName: "arrow.clockwise")
                        .font(.system(size: 11, weight: .semibold))
                }
                .buttonStyle(.borderless)
                .help("刷新所有预设代理端口状态（含 Donut Browser 所用端口）")
                .disabled(coordinator.isCheckingPorts)
            }
        }
        .padding(9)
        .background(
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .fill(Color(nsColor: .controlBackgroundColor))
        )
    }

    private func portPill(preset: ProxyPreset, health: PresetPortHealth?) -> some View {
        let isAlive = health?.isAlive
        let dotColor: Color = isAlive == true ? .green : (isAlive == false ? .red : .gray)
        let latencyText = health?.latencyMs.map { " \($0)ms" } ?? ""
        return HStack(spacing: 4) {
            Circle()
                .fill(dotColor)
                .frame(width: 7, height: 7)
            Text("\(preset.shortLabel) :\(preset.proxyPort)\(latencyText)")
                .font(.system(size: 11, weight: .medium, design: .monospaced))
        }
        .padding(.horizontal, 7)
        .padding(.vertical, 3)
        .background(
            Capsule()
                .fill(dotColor.opacity(0.10))
        )
        .overlay(
            Capsule()
                .stroke(dotColor.opacity(0.28), lineWidth: 0.8)
        )
    }

    // MARK: - 3. 6 项体检明细列表

    private var checkItemsSection: some View {
        VStack(spacing: 5) {
            ForEach(coordinator.report.items) { item in
                HStack(alignment: .top, spacing: 8) {
                    statusIcon(for: item.status)
                        .frame(width: 16, height: 16)
                        .padding(.top, 1)

                    VStack(alignment: .leading, spacing: 1.5) {
                        HStack {
                            Text("\(item.kind.rawValue). \(item.kind.title)")
                                .font(.system(size: 12, weight: .medium))
                            Spacer()
                            if let checkedAt = item.checkedAt {
                                Text(Self.timeFormatter.string(from: checkedAt))
                                    .font(.system(size: 10, design: .monospaced))
                                    .foregroundColor(.secondary)
                            }
                        }

                        HStack(spacing: 6) {
                            Text(item.summary)
                                .font(.system(size: 11))
                                .foregroundColor(item.status == .failed ? .red : (item.status == .warning ? .orange : .secondary))
                                .lineLimit(1)
                                .truncationMode(.middle)

                            Spacer(minLength: 4)

                            if item.hasResidualClaudeProcess && !coordinator.phase.isGuarding {
                                Button("一键清理") {
                                    coordinator.cleanResidualProcesses()
                                }
                                .controlSize(.mini)
                                .buttonStyle(.borderedProminent)
                                .tint(.red)
                            }
                        }
                    }
                }
                .padding(.horizontal, 8)
                .padding(.vertical, 5)
                .background(
                    RoundedRectangle(cornerRadius: 6, style: .continuous)
                        .fill(Color(nsColor: .controlBackgroundColor).opacity(0.75))
                )
            }
        }
    }

    @ViewBuilder
    private func statusIcon(for status: CheckStatus) -> some View {
        switch status {
        case .pending:
            Image(systemName: "circle.dotted")
                .foregroundColor(.secondary)
        case .checking:
            ProgressView()
                .scaleEffect(0.55)
        case .passed:
            Image(systemName: "checkmark.circle.fill")
                .foregroundColor(.green)
        case .warning:
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundColor(.orange)
        case .failed:
            Image(systemName: "xmark.octagon.fill")
                .foregroundColor(.red)
        }
    }

    private func errorNoteBanner(_ text: String) -> some View {
        Text(text)
            .font(.system(size: 11))
            .foregroundColor(.red)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(7)
            .background(
                RoundedRectangle(cornerRadius: 6)
                    .fill(Color.red.opacity(0.08))
            )
    }

    // MARK: - 4. 核心操作区

    @ViewBuilder
    private var actionSection: some View {
        if case .guarding(let startedAt, _, let pidCount, let lastIpVerifiedAt) = coordinator.phase {
            VStack(spacing: 8) {
                Button {
                    coordinator.triggerEmergencyKillSwitch(
                        reason: "用户手动触发一键紧急熔断",
                        detail: "主动强杀所有受控 Claude Desktop 进程"
                    )
                } label: {
                    HStack {
                        Image(systemName: "bolt.slash.fill")
                        Text("一键紧急熔断（立即切断）")
                            .fontWeight(.semibold)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 4)
                }
                .buttonStyle(.borderedProminent)
                .tint(.red)
                .controlSize(.large)

                TimelineView(.periodic(from: .now, by: 1.0)) { context in
                    let elapsed = max(0, Int(context.date.timeIntervalSince(startedAt)))
                    let durationText = formatDuration(elapsed)
                    let ipTimeText = lastIpVerifiedAt.map { Self.timeFormatter.string(from: $0) } ?? "等待复验"
                    HStack {
                        Text("已守护 \(durationText)")
                        Text("·")
                        Text("进程 \(pidCount)")
                        Spacer()
                        Text("上次出口复验: \(ipTimeText)")
                    }
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(.secondary)
                }
            }
        } else {
            HStack(spacing: 8) {
                Button {
                    coordinator.requestSafeLaunch()
                } label: {
                    HStack {
                        if coordinator.isBusyLaunching {
                            ProgressView().scaleEffect(0.65)
                        } else {
                            Image(systemName: "play.shield.fill")
                        }
                        Text(coordinator.isBusyLaunching ? "安全启动复核中..." : "安全启动 Claude Desktop")
                            .fontWeight(.semibold)
                    }
                    .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .tint(.green)
                .controlSize(.large)
                .disabled(!coordinator.phase.canLaunch || coordinator.isBusyLaunching)

                Button {
                    Task {
                        await coordinator.runPreFlightCheck(manualUnlock: true)
                    }
                } label: {
                    HStack(spacing: 4) {
                        Image(systemName: "arrow.triangle.2.circlepath")
                        Text("重新体检")
                    }
                }
                .controlSize(.large)
                .disabled(coordinator.phase == .checking || coordinator.isBusyLaunching)
            }
        }
    }

    private func formatDuration(_ totalSeconds: Int) -> String {
        let h = totalSeconds / 3600
        let m = (totalSeconds % 3600) / 60
        let s = totalSeconds % 60
        if h > 0 {
            return String(format: "%02d:%02d:%02d", h, m, s)
        }
        return String(format: "%02d:%02d", m, s)
    }

    // MARK: - 5. 底部快捷开关与工具栏

    private var quickTogglesAndFooter: some View {
        VStack(alignment: .leading, spacing: 6) {
            Toggle("合盖休眠前自动关闭 Claude Desktop", isOn: Binding(
                get: { coordinator.config.killDesktopOnSleep },
                set: { coordinator.updateToggle(killDesktopOnSleep: $0) }
            ))
            .font(.system(size: 11.5))

            Toggle("合盖休眠前同时关闭 Donut Browser", isOn: Binding(
                get: { coordinator.config.killDonutOnSleep },
                set: { coordinator.updateToggle(killDonutOnSleep: $0) }
            ))
            .font(.system(size: 11.5))

            Toggle("拦截未走代理的手动启动", isOn: Binding(
                get: { coordinator.config.guardRogueLaunch },
                set: { coordinator.updateToggle(guardRogueLaunch: $0) }
            ))
            .font(.system(size: 11.5))

            Toggle("开机自动启动 ClaudeGuard", isOn: Binding(
                get: { coordinator.loginItemEnabled },
                set: { coordinator.setLoginItem($0) }
            ))
            .font(.system(size: 11.5))

            HStack(spacing: 8) {
                Button("编辑预设配置") {
                    onOpenSettings()
                }
                .controlSize(.small)

                Button("查看熔断日志") {
                    onOpenLogs()
                }
                .controlSize(.small)

                Spacer()

                Button("退出") {
                    onQuitRequested()
                }
                .controlSize(.small)
            }
            .padding(.top, 4)
        }
        .toggleStyle(.checkbox)
    }
}
