# ClaudeGuard

macOS 原生超轻量级菜单栏安全守护工具（Apple Silicon / Intel 通用，macOS 13+），专为在 Clash Verge（TUN 模式 + 本地回环链式代理端口）环境下安全使用 **Claude Desktop**（并兼顾监控 **Donut Browser** 端口健康）而设计。

核心闭环：**启动前 6 项 `socks5h` 全量环境体检 → 官方本地策略锁定与防泄露参数启动 → 运行期多维度实时监控与休眠保护 → 异常毫秒级 `SIGKILL` 熔断告警**。

---

## 核心特性

- **纯原生零第三方依赖**：Swift 5.9+ / AppKit (`NSStatusItem` + `NSPopover`) + SwiftUI，无 Dock 图标（`LSUIElement = true`）；Popover 与辅助窗口懒加载且关闭即释放，后台空闲物理内存约 `13 MB`、CPU `0.0%`。
- **零系统侵入**：不申请 `sudo`/root、不写入 `pf` 防火墙规则、不修改 Clash Verge 配置或 macOS 系统代理设置。
- **防误杀安全红线**：进程枚举与熔断仅锁定 `com.anthropic.claudefordesktop` 或 `/Applications/Claude.app/` 下进程（基于 `libproc` + `KERN_PROCARGS2`），绝不误杀 `ClaudeGuard` 自身或终端 CLI。
- **启动前 6 项全量体检（全走 `--socks5-hostname`）**：
  1. `NWConnection` 本地监听端口存活与延迟探测（同时提供全预设端口胶囊条以便确认 Donut Browser 端口健康）
  2. `https://claude.ai/cdn-cgi/trace` 与备用 `https://api.ipify.org` 出口 IP 100% 精确锁死校验
  3. 地区码校验与高风险地区（`CN`/`HK`/`MO`/`RU`/`KP`/`IR`/`SY`）强制拦截
  4. 远程 DNS 解析可用性与 `curl -6` IPv6 穿透泄露检测
  5. 未带代理参数的残留 Claude 进程扫描（提供一键清理）与时区核对（可选非阻断提醒或严格阻断）
  6. `https://claude.ai` 与 `https://api.anthropic.com` TLS 握手验证与耗时统计
- **桌面端防串区锁 & 内置更新器直连封堵**：
  - 切换地区预设启动时强制弹出高危二次确认，防止手滑串号；
  - 启动前自动同步 Claude Desktop 官方本地策略库（`~/Library/Application Support/Claude-3p/configLibrary/`），写入 `disableAutoUpdates: true`（阻断内置 `Squirrel.framework` / `NSURLSession` 绕过代理走系统 TUN 直连）与 `egressProxyUrl`（锁定 `defaultSession` 出口），并注入 `--proxy-server=socks5://...`、`--proxy-bypass-list=127.0.0.1;[::1];localhost` 与 `--force-webrtc-ip-handling-policy=disable_non_proxied_udp`。
- **运行期三层实时守护与休眠保护**：
  - 常驻 `NWPathMonitor` 网络变更监听与 `NSWorkspace` 休眠/唤醒/应用启停事件（合盖前 `SIGTERM -> 300ms -> SIGKILL` 切断 Claude Desktop，可选同步关闭 Donut Browser；唤醒等待 3 秒自动复检）；
  - 仅在 Claude Desktop 运行期激活高频巡检：`2s` 端口心跳、`3s` Darwin `libproc` Socket 直连泄露与越权启动审计、`25s` 上游出口复验（IP 漂移零容忍，单次超时 1.5s 后重试一次）。
- **毫秒级熔断与留痕**：一旦检测到直连外网 Socket、出口 IP 漂移、本地代理断连或越权启动，立即 `SIGKILL` 强杀全部受控进程，菜单栏变红锁定、触发系统通知与 `Basso` 告警音，并记录至 `~/Library/Application Support/ClaudeGuard/events.log`。

---

## 安装方式

### 方式 1：直接下载预编译通用包（推荐）
前往 [GitHub Releases](https://github.com/tdgcdtd/ClaudeGuard/releases) 下载 `ClaudeGuard-v1.0.0-macOS-universal.zip`，解压后将 `ClaudeGuard.app` 拖入 `/Applications` 即可。
> 因使用本地 ad-hoc 签名，首次打开若提示无法验证开发者，可在系统「隐私与安全性」中点击「仍要打开」，或执行：
> `xattr -cr /Applications/ClaudeGuard.app`

### 方式 2：从源码编译打包
```bash
git clone https://github.com/tdgcdtd/ClaudeGuard.git
cd ClaudeGuard

# 编译 Universal Binary（arm64 + x86_64）并生成 ClaudeGuard.app
chmod +x build_app.sh
./build_app.sh

# 安装到 /Applications
rm -rf /Applications/ClaudeGuard.app && cp -R ./ClaudeGuard.app /Applications/
```

---

## 首次配置说明 (`config.json`)

首次启动会自动生成配置文件：`~/Library/Application Support/ClaudeGuard/config.json`。默认模板使用 RFC 5737 示例出口 IP（`203.0.113.10` 与 `198.51.100.20`），**请在首次运行后点击 Popover 底部「编辑预设配置」将 `expectedExitIp` 修改为你自己的静态住宅出口 IP**：

```json
{
  "activeDesktopPresetId": "jp-static",
  "lastLaunchedDesktopPresetId": "jp-static",
  "presets": [
    {
      "id": "jp-static",
      "name": "JP 静态代理 (主力)",
      "proxyHost": "127.0.0.1",
      "proxyPort": 17892,
      "expectedExitIp": "203.0.113.10",
      "expectedCountry": "JP",
      "expectedTimezone": "Asia/Tokyo",
      "strictTimezoneCheck": false
    },
    {
      "id": "us-static",
      "name": "US 静态代理 (备用)",
      "proxyHost": "127.0.0.1",
      "proxyPort": 17891,
      "expectedExitIp": "198.51.100.20",
      "expectedCountry": "US",
      "expectedTimezone": "America/Los_Angeles",
      "strictTimezoneCheck": false
    }
  ],
  "blockedCountries": ["CN", "HK", "MO", "RU", "KP", "IR", "SY"],
  "claudeAppPath": "/Applications/Claude.app",
  "killDesktopOnSleep": true,
  "killDonutOnSleep": false,
  "guardRogueLaunch": true,
  "fastProbeIntervalSec": 2,
  "socketAuditIntervalSec": 3,
  "exitIpVerifyIntervalSec": 25
}
```

---

## 测试与核查指南

### 1. 运行单元测试（Swift Testing）
```bash
# 若当前仅安装了 CommandLineTools（未安装完整 Xcode），需显式指定 TestingMacros 插件路径
swift test --disable-xctest --enable-swift-testing \
  -Xswiftc -load-plugin-library \
  -Xswiftc /Library/Developer/CommandLineTools/usr/lib/swift/host/plugins/testing/libTestingMacros.dylib
```

### 2. 验证 Claude Desktop 启动参数与本地策略
点击 **「安全启动 Claude Desktop」** 进入 **`安全 · 守护中`** 后，可在终端检查进程参数：
```bash
ps -ww -axo pid,command | grep "/Applications/Claude.app/Contents/MacOS/Claude" | grep -v grep
```
应能看到 `--proxy-server=socks5://127.0.0.1:<port>`、`--proxy-bypass-list=127.0.0.1;[::1];localhost` 与 `--force-webrtc-ip-handling-policy=disable_non_proxied_udp`。

### 3. 模拟断代理触发秒级熔断测试
1. 在 **`安全 · 守护中`** 状态下，停用 Clash Verge 中对应端口监听。
2. 2 秒内 ClaudeGuard 会触发紧急熔断：`SIGKILL` 强杀 `/Applications/Claude.app/` 全部进程，菜单栏变为红灯 **`熔断`**，弹出系统通知并写入 `~/Library/Application Support/ClaudeGuard/events.log`。
3. 恢复端口后，点击 Popover 中的 **「重新体检」** 解锁。

### 4. 核查后台常驻内存与空闲 CPU 占用
```bash
PGID=$(pgrep -x ClaudeGuard)
ps -o pid,rss,%cpu,comm -p "$PGID"
footprint "$PGID" | head -n 10
```
- `footprint` 显示进程真实独立物理内存（与「活动监视器 -> 内存」口径一致，后台空闲约 13 MB，远低于 35 MB 红线）；
- `ps -o rss`（单位 KB）会将系统共用的只读 `dyld shared cache` 计入其中；
- 未运行 Claude Desktop 时空闲 `%cpu` 接近 `0.0%`。

---

## License

[MIT License](LICENSE)
