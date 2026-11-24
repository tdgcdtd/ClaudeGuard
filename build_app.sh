#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
APP_NAME="ClaudeGuard"
APP_BUNDLE="${ROOT_DIR}/${APP_NAME}.app"
CONTENTS_DIR="${APP_BUNDLE}/Contents"
MACOS_DIR="${CONTENTS_DIR}/MacOS"
RESOURCES_DIR="${CONTENTS_DIR}/Resources"
INFO_PLIST="${CONTENTS_DIR}/Info.plist"

cd "${ROOT_DIR}"

echo "==> [1/4] 编译 Release 二进制..."
BIN_PATH=""
if swift build -c release --arch arm64 --arch x86_64; then
    if [[ -x "${ROOT_DIR}/.build/apple/Products/Release/${APP_NAME}" ]]; then
        BIN_PATH="${ROOT_DIR}/.build/apple/Products/Release/${APP_NAME}"
    fi
else
    echo "⚠️  当前 SDK/工具链不支持同时构建 arm64 + x86_64 通用二进制，回退为本机架构 Release 编译..."
    swift build -c release
fi

if [[ -z "${BIN_PATH}" ]]; then
    BIN_PATH="${ROOT_DIR}/.build/release/${APP_NAME}"
fi

if [[ ! -x "${BIN_PATH}" ]]; then
    echo "❌ 未找到编译产物: ${BIN_PATH}"
    exit 1
fi

echo "==> [2/4] 组装 ${APP_NAME}.app 目录结构..."
rm -rf "${APP_BUNDLE}"
mkdir -p "${MACOS_DIR}" "${RESOURCES_DIR}"

cp "${BIN_PATH}" "${MACOS_DIR}/${APP_NAME}"
chmod +x "${MACOS_DIR}/${APP_NAME}"
strip -x "${MACOS_DIR}/${APP_NAME}" || true

cat > "${INFO_PLIST}" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>zh_CN</string>
    <key>CFBundleExecutable</key>
    <string>ClaudeGuard</string>
    <key>CFBundleIdentifier</key>
    <string>com.claudeguard.app</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>ClaudeGuard</string>
    <key>CFBundleDisplayName</key>
    <string>ClaudeGuard</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0.0</string>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>LSMinimumSystemVersion</key>
    <string>13.0</string>
    <key>LSUIElement</key>
    <true/>
    <key>NSHighResolutionCapable</key>
    <true/>
    <key>NSUserNotificationAlertStyle</key>
    <string>alert</string>
</dict>
</plist>
PLIST

printf "APPL????" > "${CONTENTS_DIR}/PkgInfo"
plutil -lint "${INFO_PLIST}"

echo "==> [3/4] 执行本地 ad-hoc 签名并校验..."
codesign --force --deep --sign - "${APP_BUNDLE}"
codesign --verify --verbose=2 "${APP_BUNDLE}"

echo "==> [4/4] 打包完成！"
echo "📦 应用路径: ${APP_BUNDLE}"
echo "🧬 二进制架构: $(file "${MACOS_DIR}/${APP_NAME}")"
echo "📏 应用体积: $(du -sh "${APP_BUNDLE}" | awk '{print $1}')"
echo "💡 可直接执行以下命令安装到 /Applications："
echo "   rm -rf /Applications/${APP_NAME}.app && cp -R \"${APP_BUNDLE}\" /Applications/"
