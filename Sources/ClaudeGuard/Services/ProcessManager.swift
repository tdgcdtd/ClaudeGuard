import Foundation
import AppKit
import Darwin

struct ClaudeProcessInfo: Equatable, Sendable {
    var pid: pid_t
    var ppid: pid_t
    var executablePath: String
    var arguments: [String]
    var commandLine: String
    var bundleIdentifier: String?
    var isMainProcess: Bool
}

enum ProcessManager {
    static let claudeBundleId = "com.anthropic.claudefordesktop"
    static let claudeGuardBundleId = "com.claudeguard.app"
    static let donutBundleId = "com.donutbrowser"

    // MARK: - 纯逻辑（供单元测试直接验证防误杀边界）

    static func normalizedAppPrefix(_ appPath: String) -> String? {
        var trimmed = appPath.trimmingCharacters(in: .whitespacesAndNewlines)
        while trimmed.count > 1 && trimmed.hasSuffix("/") {
            trimmed.removeLast()
        }
        guard !trimmed.isEmpty,
              trimmed != "/",
              trimmed.hasPrefix("/"),
              trimmed.hasSuffix(".app") else {
            return nil
        }
        return trimmed + "/"
    }

    static func isTargetClaudeProcess(
        pid: pid_t,
        executablePath: String,
        bundleIdentifier: String?,
        claudeAppPath: String = "/Applications/Claude.app",
        selfPid: pid_t = ProcessInfo.processInfo.processIdentifier
    ) -> Bool {
        guard pid > 1, pid != selfPid else { return false }

        if bundleIdentifier == claudeGuardBundleId {
            return false
        }
        if executablePath.hasSuffix("/ClaudeGuard") || executablePath.contains("/ClaudeGuard.app/") {
            return false
        }

        if bundleIdentifier == claudeBundleId {
            return true
        }
        if let prefix = normalizedAppPrefix(claudeAppPath), executablePath.hasPrefix(prefix) {
            return true
        }
        return false
    }

    static func isMainClaudeExecutable(
        executablePath: String,
        bundleIdentifier: String?,
        claudeAppPath: String = "/Applications/Claude.app"
    ) -> Bool {
        if let prefix = normalizedAppPrefix(claudeAppPath) {
            if executablePath == "\(prefix)Contents/MacOS/Claude" {
                return true
            }
        }
        if bundleIdentifier == claudeBundleId && !executablePath.contains("/Frameworks/") {
            return true
        }
        return false
    }

    static func hasExpectedProxyArgument(
        commandLine: String,
        arguments: [String],
        proxyHost: String,
        proxyPort: Int
    ) -> Bool {
        let expectedFlag = "--proxy-server=socks5://\(proxyHost):\(proxyPort)"
        if !arguments.isEmpty {
            return arguments.contains(expectedFlag)
        }
        let tokens = commandLine.split(whereSeparator: { $0.isWhitespace }).map(String.init)
        return tokens.contains(expectedFlag)
    }

    static func parseKernProcArgs2(_ data: Data) -> [String] {
        guard data.count >= MemoryLayout<Int32>.size else { return [] }
        let argc: Int32 = data.withUnsafeBytes { raw in
            raw.loadUnaligned(as: Int32.self)
        }
        guard argc > 0 && argc < 4096 else { return [] }

        var index = MemoryLayout<Int32>.size
        let bytes = [UInt8](data)

        // 跳过可执行文件路径（到第一个 \0）
        while index < bytes.count && bytes[index] != 0 {
            index += 1
        }
        // 跳过路径后的所有填充 \0
        while index < bytes.count && bytes[index] == 0 {
            index += 1
        }

        var args: [String] = []
        args.reserveCapacity(Int(argc))
        while index < bytes.count && args.count < Int(argc) {
            let start = index
            while index < bytes.count && bytes[index] != 0 {
                index += 1
            }
            if index > start {
                let slice = bytes[start..<index]
                if let str = String(bytes: slice, encoding: .utf8) {
                    args.append(str)
                }
            } else {
                args.append("")
            }
            index += 1
        }
        return args
    }

    // MARK: - 系统进程枚举与强杀操作

    static func allProcessIds() -> [pid_t] {
        let estimated = proc_listallpids(nil, 0)
        guard estimated > 0 else { return [] }
        let capacity = Int(estimated) * 2 + 64
        var pids = [pid_t](repeating: 0, count: capacity)
        let bufferSize = Int32(capacity * MemoryLayout<pid_t>.stride)
        let actualCount = pids.withUnsafeMutableBufferPointer { buf in
            proc_listallpids(buf.baseAddress, bufferSize)
        }
        guard actualCount > 0 else { return [] }
        return Array(pids.prefix(Int(actualCount))).filter { $0 > 0 }
    }

    static func executablePath(for pid: pid_t) -> String? {
        var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN) * 4)
        let length = proc_pidpath(pid, &buffer, UInt32(buffer.count))
        guard length > 0 else { return nil }
        return String(cString: buffer)
    }

    static func parentPid(for pid: pid_t) -> pid_t {
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.stride)
        let result = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size)
        if result == size {
            return pid_t(info.pbi_ppid)
        }
        return 0
    }

    static func arguments(for pid: pid_t) -> [String] {
        var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
        var size: size_t = 0
        var kernelArgs: [String] = []
        if sysctl(&mib, UInt32(mib.count), nil, &size, nil, 0) == 0, size > 0 {
            var data = Data(count: size)
            let status = data.withUnsafeMutableBytes { ptr -> Int32 in
                sysctl(&mib, UInt32(mib.count), ptr.baseAddress, &size, nil, 0)
            }
            if status == 0 {
                kernelArgs = parseKernProcArgs2(data.prefix(size))
                if kernelArgs.contains(where: { $0.hasPrefix("--") }) {
                    return kernelArgs
                }
            }
        }
        let psArgs = fallbackPsCommandLine(for: pid)
        return psArgs.isEmpty ? kernelArgs : psArgs
    }

    private static func fallbackPsCommandLine(for pid: pid_t) -> [String] {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/ps")
        process.arguments = ["-ww", "-p", "\(pid)", "-o", "command="]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            guard process.terminationStatus == 0,
                  let text = String(data: data, encoding: .utf8)?
                    .trimmingCharacters(in: .whitespacesAndNewlines),
                  !text.isEmpty else {
                return []
            }
            return text.split(whereSeparator: { $0.isWhitespace }).map(String.init)
        } catch {
            return []
        }
    }

    private static func runningBundleIdsByPid() -> [pid_t: String] {
        var map: [pid_t: String] = [:]
        for app in NSWorkspace.shared.runningApplications {
            if let bid = app.bundleIdentifier {
                map[app.processIdentifier] = bid
            }
        }
        return map
    }

    static func findClaudeProcesses(claudeAppPath: String = "/Applications/Claude.app") -> [ClaudeProcessInfo] {
        let pids = allProcessIds()
        let bundleMap = runningBundleIdsByPid()
        let selfPid = ProcessInfo.processInfo.processIdentifier

        var results: [ClaudeProcessInfo] = []
        for pid in pids {
            let path = executablePath(for: pid) ?? ""
            let bundleId = bundleMap[pid]
            guard isTargetClaudeProcess(
                pid: pid,
                executablePath: path,
                bundleIdentifier: bundleId,
                claudeAppPath: claudeAppPath,
                selfPid: selfPid
            ) else {
                continue
            }

            let args = arguments(for: pid)
            let cmd = args.joined(separator: " ")
            let ppid = parentPid(for: pid)
            let isMain = isMainClaudeExecutable(
                executablePath: path,
                bundleIdentifier: bundleId,
                claudeAppPath: claudeAppPath
            )
            results.append(
                ClaudeProcessInfo(
                    pid: pid,
                    ppid: ppid,
                    executablePath: path,
                    arguments: args,
                    commandLine: cmd,
                    bundleIdentifier: bundleId,
                    isMainProcess: isMain
                )
            )
        }
        return results
    }

    static func isPidAlive(_ pid: pid_t) -> Bool {
        guard pid > 1 else { return false }
        if Darwin.kill(pid, 0) == 0 {
            return true
        }
        return errno == EPERM
    }

    /// 熔断秒杀：立即对所有受控 Claude 进程（含 Helper 子进程）发送 SIGKILL，确保毫秒级断网
    @discardableResult
    static func killAllClaudeImmediately(claudeAppPath: String = "/Applications/Claude.app") -> [pid_t] {
        var killed: Set<pid_t> = []
        let firstPass = findClaudeProcesses(claudeAppPath: claudeAppPath)
        for proc in firstPass {
            _ = Darwin.kill(proc.pid, SIGKILL)
            killed.insert(proc.pid)
        }
        if !firstPass.isEmpty {
            usleep(40_000)
            let secondPass = findClaudeProcesses(claudeAppPath: claudeAppPath)
            for proc in secondPass {
                _ = Darwin.kill(proc.pid, SIGKILL)
                killed.insert(proc.pid)
            }
        }
        return Array(killed).sorted()
    }

    /// 合盖休眠 / 清理残留：先发 SIGTERM，最多等待 300ms，未退出则 SIGKILL
    @discardableResult
    static func terminateClaudeGracefullyThenKill(
        claudeAppPath: String = "/Applications/Claude.app",
        graceMs: Int = 300
    ) -> [pid_t] {
        let initial = findClaudeProcesses(claudeAppPath: claudeAppPath)
        guard !initial.isEmpty else { return [] }

        var affected: Set<pid_t> = []
        for proc in initial {
            _ = Darwin.kill(proc.pid, SIGTERM)
            affected.insert(proc.pid)
        }

        let deadline = Date().addingTimeInterval(Double(max(0, graceMs)) / 1000.0)
        while Date() < deadline {
            let remaining = findClaudeProcesses(claudeAppPath: claudeAppPath)
            if remaining.isEmpty {
                return Array(affected).sorted()
            }
            usleep(30_000)
        }

        let stubborn = findClaudeProcesses(claudeAppPath: claudeAppPath)
        for proc in stubborn {
            _ = Darwin.kill(proc.pid, SIGKILL)
            affected.insert(proc.pid)
        }
        return Array(affected).sorted()
    }

    /// 合盖休眠时可选优雅关闭 Donut Browser
    @discardableResult
    static func terminateDonutOnSleep(graceMs: Int = 300) -> [pid_t] {
        let selfPid = ProcessInfo.processInfo.processIdentifier
        let bundleMap = runningBundleIdsByPid()
        var targetPids: [pid_t] = []

        for app in NSWorkspace.shared.runningApplications where app.bundleIdentifier == donutBundleId {
            if app.processIdentifier != selfPid {
                _ = app.terminate()
                targetPids.append(app.processIdentifier)
            }
        }

        for pid in allProcessIds() where pid != selfPid {
            let path = executablePath(for: pid) ?? ""
            let bid = bundleMap[pid]
            if bid == donutBundleId || path.hasPrefix("/Applications/Donut.app/") {
                if !targetPids.contains(pid) {
                    targetPids.append(pid)
                }
                _ = Darwin.kill(pid, SIGTERM)
            }
        }

        guard !targetPids.isEmpty else { return [] }

        let deadline = Date().addingTimeInterval(Double(max(0, graceMs)) / 1000.0)
        while Date() < deadline {
            if targetPids.allSatisfy({ !isPidAlive($0) }) {
                return targetPids
            }
            usleep(30_000)
        }

        for pid in targetPids where isPidAlive(pid) {
            _ = Darwin.kill(pid, SIGKILL)
        }
        return targetPids
    }
}
