import AppKit
import SwiftUI
import Combine

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate, NSPopoverDelegate, NSWindowDelegate {
    let coordinator = GuardCoordinator()

    private var statusItem: NSStatusItem?
    private var popover: NSPopover?
    private var settingsWindow: NSWindow?
    private var settingsDraft: PresetSettingsDraft?
    private var logWindow: NSWindow?
    private var phaseCancellable: AnyCancellable?

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)
        setupStatusItem()
        observePhaseChanges()
        coordinator.bootstrap()
    }

    func applicationWillTerminate(_ notification: Notification) {
        coordinator.watchdog.stopGuarding()
    }

    private func setupStatusItem() {
        let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        if let button = item.button {
            button.action = #selector(togglePopover(_:))
            button.target = self
            button.imagePosition = .imageLeading
            button.toolTip = "ClaudeGuard · Claude Desktop 代理防泄露守护"
        }
        statusItem = item
        updateStatusIcon(for: coordinator.phase)
    }

    private func makePopover() -> NSPopover {
        let pop = NSPopover()
        pop.behavior = .transient
        pop.animates = true
        pop.delegate = self
        pop.contentSize = NSSize(width: 420, height: 610)

        let rootView = StatusPopoverView(
            coordinator: coordinator,
            onOpenSettings: { [weak self] in self?.openSettingsWindow() },
            onOpenLogs: { [weak self] in self?.openLogWindow() },
            onQuitRequested: { [weak self] in self?.confirmAndQuit() }
        )
        pop.contentViewController = NSHostingController(rootView: rootView)
        return pop
    }

    private func observePhaseChanges() {
        phaseCancellable = coordinator.$phase
            .receive(on: RunLoop.main)
            .sink { [weak self] newPhase in
                self?.updateStatusIcon(for: newPhase)
            }
    }

    private func updateStatusIcon(for phase: GuardPhase) {
        guard let button = statusItem?.button else { return }

        let dotColor: NSColor
        let symbolName: String
        let titleText: String

        switch phase {
        case .readySafe:
            dotColor = NSColor.systemGreen
            symbolName = "checkmark.shield"
            titleText = ""
        case .guarding:
            dotColor = NSColor.systemGreen
            symbolName = "checkmark.shield.fill"
            titleText = " 安全 · 守护中"
        case .checking, .wakingUp, .readyWithWarning:
            dotColor = NSColor.systemYellow
            symbolName = "shield.lefthalf.filled"
            titleText = ""
        case .blockedPreFlight:
            dotColor = NSColor.systemRed
            symbolName = "exclamationmark.shield"
            titleText = ""
        case .killSwitchLocked:
            dotColor = NSColor.systemRed
            symbolName = "exclamationmark.shield.fill"
            titleText = " 熔断"
        }

        button.image = renderStatusBadgeImage(symbolName: symbolName, dotColor: dotColor)
        button.title = titleText
        button.font = NSFont.systemFont(ofSize: 12, weight: .medium)
    }

    private func renderStatusBadgeImage(symbolName: String, dotColor: NSColor) -> NSImage {
        let size = NSSize(width: 22, height: 18)
        let image = NSImage(size: size, flipped: false) { rect in
            let symbolConfig = NSImage.SymbolConfiguration(pointSize: 14, weight: .medium)
                .applying(NSImage.SymbolConfiguration(paletteColors: [NSColor.labelColor]))
            if let shield = NSImage(systemSymbolName: symbolName, accessibilityDescription: "ClaudeGuard")?
                .withSymbolConfiguration(symbolConfig) {
                shield.draw(in: NSRect(x: 1, y: 1, width: 15, height: 16))
            }

            let dotRect = NSRect(x: rect.width - 7, y: 1.5, width: 6, height: 6)
            dotColor.setFill()
            NSBezierPath(ovalIn: dotRect).fill()

            NSColor.windowBackgroundColor.withAlphaComponent(0.7).setStroke()
            let ring = NSBezierPath(ovalIn: dotRect)
            ring.lineWidth = 0.8
            ring.stroke()
            return true
        }
        image.isTemplate = false
        return image
    }

    @objc private func togglePopover(_ sender: AnyObject?) {
        guard let button = statusItem?.button else { return }
        if let existing = popover, existing.isShown {
            existing.performClose(sender)
            return
        }

        let pop = popover ?? makePopover()
        popover = pop
        pop.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
        pop.contentViewController?.view.window?.makeKey()
        Task {
            await coordinator.refreshAllPorts()
        }
    }

    func popoverDidClose(_ notification: Notification) {
        popover?.contentViewController = nil
        popover = nil
    }

    func openSettingsWindow() {
        popover?.performClose(nil)
        if let settingsDraft {
            settingsDraft.syncFromCoordinator(coordinator)
        }
        if settingsWindow == nil {
            let draft = PresetSettingsDraft(coordinator: coordinator)
            self.settingsDraft = draft
            let hosting = NSHostingController(rootView: PresetSettingsView(coordinator: coordinator, draft: draft))
            let win = NSWindow(contentViewController: hosting)
            win.title = "ClaudeGuard · 预设与安全配置"
            win.setContentSize(NSSize(width: 680, height: 480))
            win.styleMask = [.titled, .closable, .miniaturizable, .resizable]
            win.delegate = self
            win.isReleasedWhenClosed = false
            win.center()
            settingsWindow = win
        }
        activateAndShow(settingsWindow)
    }

    func openLogWindow() {
        popover?.performClose(nil)
        coordinator.refreshRecentLogs()
        if logWindow == nil {
            let hosting = NSHostingController(rootView: EventLogView(coordinator: coordinator))
            let win = NSWindow(contentViewController: hosting)
            win.title = "ClaudeGuard · 安全与熔断日志"
            win.setContentSize(NSSize(width: 680, height: 440))
            win.styleMask = [.titled, .closable, .miniaturizable, .resizable]
            win.delegate = self
            win.isReleasedWhenClosed = false
            win.center()
            logWindow = win
        }
        activateAndShow(logWindow)
    }

    func windowWillClose(_ notification: Notification) {
        guard let closing = notification.object as? NSWindow else { return }
        if closing === settingsWindow {
            settingsWindow?.contentViewController = nil
            settingsWindow = nil
            settingsDraft = nil
        } else if closing === logWindow {
            logWindow?.contentViewController = nil
            logWindow = nil
        }
    }

    private func activateAndShow(_ window: NSWindow?) {
        guard let window else { return }
        if #available(macOS 14.0, *) {
            NSApp.activate()
        } else {
            NSApp.activate(ignoringOtherApps: true)
        }
        window.makeKeyAndOrderFront(nil)
    }

    private func confirmAndQuit() {
        if coordinator.phase.isGuarding {
            let alert = NSAlert()
            alert.alertStyle = .warning
            alert.messageText = "当前正在守护 Claude Desktop"
            alert.informativeText = "退出 ClaudeGuard 后，将无法继续监控 Claude Desktop 的代理与直连泄露。建议先熔断或关闭 Claude Desktop 再退出。"
            alert.addButton(withTitle: "立即熔断并退出")
            alert.addButton(withTitle: "仅退出 ClaudeGuard")
            alert.addButton(withTitle: "取消")
            if #available(macOS 14.0, *) {
                NSApp.activate()
            } else {
                NSApp.activate(ignoringOtherApps: true)
            }
            let result = alert.runModal()
            if result == .alertFirstButtonReturn {
                ProcessManager.killAllClaudeImmediately(claudeAppPath: coordinator.config.claudeAppPath)
                NSApp.terminate(nil)
            } else if result == .alertSecondButtonReturn {
                NSApp.terminate(nil)
            }
        } else {
            NSApp.terminate(nil)
        }
    }
}
