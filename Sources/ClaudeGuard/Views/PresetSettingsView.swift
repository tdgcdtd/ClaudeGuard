import SwiftUI
import AppKit

@MainActor
final class PresetSettingsDraft: ObservableObject {
    @Published var draftConfig: AppConfig
    @Published var selectedPresetId: String
    @Published var blockedCountriesText: String
    @Published var feedbackMessage: String?

    init(coordinator: GuardCoordinator) {
        let cfg = coordinator.config
        self.draftConfig = cfg
        self.selectedPresetId = cfg.activeDesktopPresetId
        self.blockedCountriesText = cfg.blockedCountries.joined(separator: ", ")
        self.feedbackMessage = nil
    }

    func syncFromCoordinator(_ coordinator: GuardCoordinator) {
        let cfg = coordinator.config
        self.draftConfig = cfg
        self.selectedPresetId = cfg.activeDesktopPresetId
        self.blockedCountriesText = cfg.blockedCountries.joined(separator: ", ")
        self.feedbackMessage = nil
    }
}

struct PresetSettingsView: View {
    @ObservedObject var coordinator: GuardCoordinator
    @ObservedObject var draft: PresetSettingsDraft

    var body: some View {
        VStack(spacing: 12) {
            HStack(spacing: 12) {
                presetSidebar
                Divider()
                presetDetailEditor
            }
            Divider()
            globalSettingsSection
            Divider()
            footerToolbar
        }
        .padding(14)
        .frame(minWidth: 660, minHeight: 460)
    }

    private var presetSidebar: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("代理预设列表")
                .font(.headline)

            List(selection: $draft.selectedPresetId) {
                ForEach(draft.draftConfig.presets) { preset in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(preset.name)
                            .font(.system(size: 12.5, weight: .medium))
                        Text("\(preset.socks5Endpoint) → \(preset.expectedCountry)")
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundColor(.secondary)
                    }
                    .tag(preset.id)
                }
            }
            .frame(width: 210)
            .listStyle(.bordered)

            HStack {
                Button("+ 新增") {
                    addNewPreset()
                }
                Button("删除") {
                    deleteSelectedPreset()
                }
                .disabled(draft.draftConfig.presets.count <= 1)
            }
        }
    }

    @ViewBuilder
    private var presetDetailEditor: some View {
        if let index = draft.draftConfig.presets.firstIndex(where: { $0.id == draft.selectedPresetId }) {
            Form {
                TextField("预设 ID (唯一标识):", text: $draft.draftConfig.presets[index].id)
                TextField("显示名称:", text: $draft.draftConfig.presets[index].name)
                TextField("代理 Host:", text: $draft.draftConfig.presets[index].proxyHost)
                TextField("代理端口 (Port):", value: $draft.draftConfig.presets[index].proxyPort, format: .number)
                TextField("期望出口 IP:", text: $draft.draftConfig.presets[index].expectedExitIp)
                TextField("期望国家码 (如 JP/US):", text: $draft.draftConfig.presets[index].expectedCountry)
                TextField("期望时区 (如 Asia/Tokyo):", text: $draft.draftConfig.presets[index].expectedTimezone)
                Toggle("时区不一致时阻断启动 (strictTimezoneCheck)", isOn: $draft.draftConfig.presets[index].strictTimezoneCheck)
            }
            .formStyle(.grouped)
        } else {
            Text("请选择左侧一个预设进行编辑")
                .foregroundColor(.secondary)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    private var globalSettingsSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 12) {
                Text("受限国家码:")
                    .frame(width: 90, alignment: .trailing)
                TextField("CN, HK, MO, RU, KP, IR, SY", text: $draft.blockedCountriesText)
            }
            HStack(spacing: 12) {
                Text("Claude 路径:")
                    .frame(width: 90, alignment: .trailing)
                TextField("/Applications/Claude.app", text: $draft.draftConfig.claudeAppPath)
            }
            HStack(spacing: 16) {
                HStack {
                    Text("端口心跳(秒):")
                    TextField("", value: $draft.draftConfig.fastProbeIntervalSec, format: .number)
                        .frame(width: 48)
                }
                HStack {
                    Text("Socket审计(秒):")
                    TextField("", value: $draft.draftConfig.socketAuditIntervalSec, format: .number)
                        .frame(width: 48)
                }
                HStack {
                    Text("出口复验(秒):")
                    TextField("", value: $draft.draftConfig.exitIpVerifyIntervalSec, format: .number)
                        .frame(width: 48)
                }
                Spacer()
            }
        }
        .font(.system(size: 12))
    }

    private var footerToolbar: some View {
        HStack {
            Button("在 Finder 显示 config.json") {
                NSWorkspace.shared.activateFileViewerSelecting([coordinator.configStore.configFileURL])
            }
            Button("从磁盘重新加载") {
                coordinator.reloadConfigFromDisk()
                draft.syncFromCoordinator(coordinator)
                draft.feedbackMessage = "已重新加载磁盘配置"
            }

            if let feedbackMessage = draft.feedbackMessage {
                Text(feedbackMessage)
                    .font(.system(size: 11.5))
                    .foregroundColor(.green)
            }

            Spacer()

            Button("保存并应用") {
                saveChanges()
            }
            .buttonStyle(.borderedProminent)
        }
    }

    private func addNewPreset() {
        let suffix = Int.random(in: 100...999)
        let newPreset = ProxyPreset(
            id: "custom-\(suffix)",
            name: "自定义预设 \(suffix)",
            proxyHost: "127.0.0.1",
            proxyPort: 17893,
            expectedExitIp: "",
            expectedCountry: "JP",
            expectedTimezone: "Asia/Tokyo",
            strictTimezoneCheck: false
        )
        draft.draftConfig.presets.append(newPreset)
        draft.selectedPresetId = newPreset.id
    }

    private func deleteSelectedPreset() {
        guard draft.draftConfig.presets.count > 1 else { return }
        draft.draftConfig.presets.removeAll { $0.id == draft.selectedPresetId }
        if let first = draft.draftConfig.presets.first {
            draft.selectedPresetId = first.id
        }
    }

    private func saveChanges() {
        var updated = draft.draftConfig
        updated.blockedCountries = draft.blockedCountriesText
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines).uppercased() }
            .filter { !$0.isEmpty }

        if let currentSelected = updated.presets.first(where: { $0.id == draft.selectedPresetId }) {
            draft.selectedPresetId = currentSelected.sanitized().id
        }
        coordinator.applyUpdatedConfig(updated)
        draft.draftConfig = coordinator.config
        draft.feedbackMessage = "配置已保存"
    }
}
