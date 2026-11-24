import SwiftUI
import AppKit

struct EventLogView: View {
    @ObservedObject var coordinator: GuardCoordinator

    var body: some View {
        VStack(spacing: 10) {
            HStack {
                Text("安全事件与熔断审计日志")
                    .font(.headline)
                Spacer()
                Button("在 Finder 定位") {
                    NSWorkspace.shared.activateFileViewerSelecting([coordinator.eventLogger.logFileURL])
                }
                Button("刷新") {
                    coordinator.refreshRecentLogs()
                }
                Button("清空日志") {
                    coordinator.clearLogs()
                }
            }

            ScrollView {
                Text(coordinator.recentLogsText)
                    .font(.system(size: 11.5, design: .monospaced))
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .textSelection(.enabled)
                    .padding(10)
            }
            .background(
                RoundedRectangle(cornerRadius: 8)
                    .fill(Color(nsColor: .textBackgroundColor))
            )
            .overlay(
                RoundedRectangle(cornerRadius: 8)
                    .stroke(Color.secondary.opacity(0.25), lineWidth: 1)
            )
        }
        .padding(14)
        .frame(minWidth: 640, minHeight: 420)
        .onAppear {
            coordinator.refreshRecentLogs()
        }
    }
}
