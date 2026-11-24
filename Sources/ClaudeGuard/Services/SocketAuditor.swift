import Foundation
import Darwin

struct SocketEndpoint: Equatable, Sendable {
    var host: String
    var port: Int
}

struct SocketConnectionRecord: Equatable, Sendable {
    var pid: pid_t
    var proto: String
    var localHost: String
    var localPort: Int
    var remoteHost: String?
    var remotePort: Int?
    var state: String
    var rawName: String

    var remoteDisplay: String {
        guard let remoteHost else { return rawName }
        if let remotePort {
            return "\(remoteHost):\(remotePort)"
        }
        return remoteHost
    }
}

enum SocketAuditor {
    // MARK: - 纯解析与泄露判定（供单元测试直接验证）

    static func stripBrackets(_ host: String) -> String {
        var cleaned = host.trimmingCharacters(in: .whitespacesAndNewlines)
        if cleaned.hasPrefix("[") && cleaned.hasSuffix("]") && cleaned.count >= 2 {
            cleaned.removeFirst()
            cleaned.removeLast()
        }
        return cleaned
    }

    static func isLoopbackHost(_ rawHost: String) -> Bool {
        let host = stripBrackets(rawHost).lowercased()
        guard !host.isEmpty else { return false }

        if host == "localhost" || host == "::1" || host == "0:0:0:0:0:0:0:1"
            || host == "::7f00:1" || host == "::ffff:7f00:1" {
            return true
        }
        if host == "127.0.0.1" {
            return true
        }
        // 支持 127.0.0.0/8 回环段
        let ipv4Candidate = host.hasPrefix("::ffff:") ? String(host.dropFirst("::ffff:".count)) : host
        let octets = ipv4Candidate.split(separator: ".")
        if octets.count == 4,
           let first = Int(octets[0]), first == 127,
           octets.allSatisfy({ Int($0).map { (0...255).contains($0) } ?? false }) {
            return true
        }
        return false
    }

    static func isWildcardOrUnspecifiedHost(_ rawHost: String) -> Bool {
        let host = stripBrackets(rawHost).lowercased()
        return host.isEmpty || host == "*" || host == "0.0.0.0" || host == "::" || host == "0:0:0:0:0:0:0:0"
    }

    static func isExternalLeak(_ record: SocketConnectionRecord) -> Bool {
        let upperState = record.state.uppercased()
        if upperState == "LISTEN" && record.remoteHost == nil {
            return false
        }
        guard let remote = record.remoteHost, !isWildcardOrUnspecifiedHost(remote) else {
            return false
        }
        if upperState == "LISTEN" {
            return false
        }
        return !isLoopbackHost(remote)
    }

    static func parseEndpoint(_ token: String) -> SocketEndpoint? {
        let trimmed = token.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }

        // 带方括号 IPv6: [::1]:17892 或 [2606:4700::1]:443
        if trimmed.hasPrefix("["), let closeBracket = trimmed.firstIndex(of: "]") {
            let host = String(trimmed[trimmed.index(after: trimmed.startIndex)..<closeBracket])
            let afterBracket = trimmed[trimmed.index(after: closeBracket)...]
            if afterBracket.hasPrefix(":") {
                let portStr = String(afterBracket.dropFirst())
                let port = portStr == "*" ? 0 : (Int(portStr) ?? -1)
                guard port >= 0 else { return nil }
                return SocketEndpoint(host: host, port: port)
            }
            return SocketEndpoint(host: host, port: 0)
        }

        // 普通 IPv4 / 通配 / 主机名: 127.0.0.1:17892 或 *:*
        if let lastColon = trimmed.lastIndex(of: ":") {
            let host = String(trimmed[..<lastColon])
            let portStr = String(trimmed[trimmed.index(after: lastColon)...])
            let port = portStr == "*" ? 0 : (Int(portStr) ?? -1)
            guard !host.isEmpty, port >= 0 else { return nil }
            return SocketEndpoint(host: host, port: port)
        }

        return nil
    }

    static func parseSocketNameField(
        _ nameField: String,
        pid: pid_t = 0,
        proto: String = "TCP"
    ) -> SocketConnectionRecord? {
        var working = nameField.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !working.isEmpty else { return nil }

        var state = ""
        if working.hasSuffix(")"), let openParen = working.lastIndex(of: "(") {
            state = String(working[working.index(after: openParen)..<working.index(before: working.endIndex)])
                .trimmingCharacters(in: .whitespaces)
            working = String(working[..<openParen]).trimmingCharacters(in: .whitespaces)
        }

        if let arrowRange = working.range(of: "->") {
            let localStr = String(working[..<arrowRange.lowerBound])
            let remoteStr = String(working[arrowRange.upperBound...])
            guard let localEp = parseEndpoint(localStr),
                  let remoteEp = parseEndpoint(remoteStr) else {
                return nil
            }
            return SocketConnectionRecord(
                pid: pid,
                proto: proto.uppercased(),
                localHost: localEp.host,
                localPort: localEp.port,
                remoteHost: remoteEp.host,
                remotePort: remoteEp.port,
                state: state.isEmpty ? "CONNECTED" : state,
                rawName: nameField
            )
        }

        guard let localEp = parseEndpoint(working) else {
            return nil
        }
        return SocketConnectionRecord(
            pid: pid,
            proto: proto.uppercased(),
            localHost: localEp.host,
            localPort: localEp.port,
            remoteHost: nil,
            remotePort: nil,
            state: state.isEmpty ? "UNCONNECTED" : state,
            rawName: nameField
        )
    }

    static func parseLsofOutput(_ output: String) -> [SocketConnectionRecord] {
        var results: [SocketConnectionRecord] = []
        for rawLine in output.split(whereSeparator: \.isNewline) {
            let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !line.isEmpty, !line.hasPrefix("COMMAND") else { continue }

            // lsof -nP -iTCP -iUDP 典型列：COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME [(STATE)]
            let tokens = line.split(whereSeparator: { $0.isWhitespace }).map(String.init)
            guard tokens.count >= 9, let pid = pid_t(tokens[1]) else { continue }

            let nodeIndex = tokens.firstIndex(where: { $0 == "TCP" || $0 == "UDP" })
            guard let idx = nodeIndex, idx + 1 < tokens.count else { continue }

            let proto = tokens[idx]
            let nameField = tokens[(idx + 1)...].joined(separator: " ")
            if let record = parseSocketNameField(nameField, pid: pid, proto: proto) {
                results.append(record)
            }
        }
        return results
    }

    // MARK: - 实时进程 Socket 审计（libproc 原生为主，lsof 回退）

    static func auditProcesses(pids: [pid_t]) -> [SocketConnectionRecord] {
        let validPids = pids.filter { $0 > 1 }
        guard !validPids.isEmpty else { return [] }

        var allRecords: [SocketConnectionRecord] = []
        var fallbackPids: [pid_t] = []

        for pid in validPids {
            if let pidRecords = readSocketsViaLibproc(pid: pid) {
                allRecords.append(contentsOf: pidRecords)
            } else {
                fallbackPids.append(pid)
            }
        }

        if !fallbackPids.isEmpty {
            allRecords.append(contentsOf: readSocketsViaLsof(pids: fallbackPids))
        }

        return allRecords.filter(isExternalLeak)
    }

    private static func readSocketsViaLibproc(pid: pid_t) -> [SocketConnectionRecord]? {
        let initialBytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nil, 0)
        if initialBytes < 0 {
            return nil
        }
        if initialBytes == 0 {
            return []
        }

        let fdStride = MemoryLayout<proc_fdinfo>.stride
        let count = Int(initialBytes) / fdStride + 32
        var fdList = [proc_fdinfo](repeating: proc_fdinfo(), count: count)
        let actualBytes = fdList.withUnsafeMutableBufferPointer { buf in
            proc_pidinfo(pid, PROC_PIDLISTFDS, 0, buf.baseAddress, Int32(count * fdStride))
        }
        guard actualBytes >= 0 else { return nil }

        let actualCount = Int(actualBytes) / fdStride
        var records: [SocketConnectionRecord] = []

        for i in 0..<actualCount {
            let fd = fdList[i]
            guard fd.proc_fdtype == PROX_FDTYPE_SOCKET else { continue }

            var sockInfo = socket_fdinfo()
            let sockInfoSize = Int32(MemoryLayout<socket_fdinfo>.stride)
            let ret = proc_pidfdinfo(pid, fd.proc_fd, PROC_PIDFDSOCKETINFO, &sockInfo, sockInfoSize)
            guard ret == sockInfoSize else { continue }

            let kind = sockInfo.psi.soi_kind
            if kind == SOCKINFO_TCP {
                let tcp = sockInfo.psi.soi_proto.pri_tcp
                let stateName = tcpStateName(tcp.tcpsi_state)
                if let record = buildRecord(pid: pid, proto: "TCP", inSock: tcp.tcpsi_ini, state: stateName) {
                    records.append(record)
                }
            } else if kind == SOCKINFO_IN {
                let inSock = sockInfo.psi.soi_proto.pri_in
                if let record = buildRecord(pid: pid, proto: "UDP", inSock: inSock, state: "UDP") {
                    records.append(record)
                }
            }
        }

        return records
    }

    private static func buildRecord(
        pid: pid_t,
        proto: String,
        inSock: in_sockinfo,
        state: String
    ) -> SocketConnectionRecord? {
        let lport = Int(UInt16(bigEndian: UInt16(truncatingIfNeeded: inSock.insi_lport)))
        let fport = Int(UInt16(bigEndian: UInt16(truncatingIfNeeded: inSock.insi_fport)))

        let isIPv4 = (inSock.insi_vflag & UInt8(INI_IPV4)) != 0
        let isIPv6 = (inSock.insi_vflag & UInt8(INI_IPV6)) != 0
        let localHost: String
        let remoteHost: String?

        if isIPv4 {
            localHost = formatIPv4(inSock.insi_laddr.ina_46.i46a_addr4) ?? "0.0.0.0"
            let rawRemote = formatIPv4(inSock.insi_faddr.ina_46.i46a_addr4)
            if let rawRemote, (!isWildcardOrUnspecifiedHost(rawRemote) || fport > 0) {
                remoteHost = rawRemote
            } else {
                remoteHost = nil
            }
        } else if isIPv6 {
            localHost = formatIPv6(inSock.insi_laddr.ina_6) ?? "::"
            let rawRemote = formatIPv6(inSock.insi_faddr.ina_6)
            if let rawRemote, !isWildcardOrUnspecifiedHost(rawRemote) || fport > 0 {
                remoteHost = rawRemote
            } else {
                remoteHost = nil
            }
        } else {
            return nil
        }

        let remotePort: Int? = remoteHost != nil ? fport : nil
        let rawName: String
        if let remoteHost, let remotePort {
            rawName = "\(localHost):\(lport)->\(remoteHost):\(remotePort) (\(state))"
        } else {
            rawName = "\(localHost):\(lport) (\(state))"
        }

        return SocketConnectionRecord(
            pid: pid,
            proto: proto,
            localHost: localHost,
            localPort: lport,
            remoteHost: remoteHost,
            remotePort: remotePort,
            state: state,
            rawName: rawName
        )
    }

    private static func formatIPv4(_ addr: in_addr) -> String? {
        var copy = addr
        var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        guard inet_ntop(AF_INET, &copy, &buffer, socklen_t(INET_ADDRSTRLEN)) != nil else {
            return nil
        }
        return String(cString: buffer)
    }

    private static func formatIPv6(_ addr: in6_addr) -> String? {
        var copy = addr
        var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        guard inet_ntop(AF_INET6, &copy, &buffer, socklen_t(INET6_ADDRSTRLEN)) != nil else {
            return nil
        }
        return String(cString: buffer)
    }

    private static func tcpStateName(_ state: Int32) -> String {
        switch state {
        case TSI_S_CLOSED: return "CLOSED"
        case TSI_S_LISTEN: return "LISTEN"
        case TSI_S_SYN_SENT: return "SYN_SENT"
        case TSI_S_SYN_RECEIVED: return "SYN_RCVD"
        case TSI_S_ESTABLISHED: return "ESTABLISHED"
        case TSI_S__CLOSE_WAIT: return "CLOSE_WAIT"
        case TSI_S_FIN_WAIT_1: return "FIN_WAIT_1"
        case TSI_S_CLOSING: return "CLOSING"
        case TSI_S_LAST_ACK: return "LAST_ACK"
        case TSI_S_FIN_WAIT_2: return "FIN_WAIT_2"
        case TSI_S_TIME_WAIT: return "TIME_WAIT"
        default: return "STATE_\(state)"
        }
    }

    private static func readSocketsViaLsof(pids: [pid_t]) -> [SocketConnectionRecord] {
        guard !pids.isEmpty else { return [] }
        let pidArg = pids.map(String.init).joined(separator: ",")
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/lsof")
        process.arguments = ["-nP", "-a", "-p", pidArg, "-iTCP", "-iUDP"]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            guard let text = String(data: data, encoding: .utf8) else { return [] }
            return parseLsofOutput(text)
        } catch {
            return []
        }
    }
}
