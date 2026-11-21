# V5Vpn-Rust

V5Vpn-Rust 是一个独立的 V5VPN 兼容客户端，使用 Rust 实现账号登录、会话管理和授权资源访问，提供桌面界面与命令行工具。项目面向获授权使用企业 V5VPN 网关的场景。

## 已实现的功能

- **账号口令登录**。使用国际算法访问 HTTPS 网关，获取会话资源授权，并处理心跳和主动断开。桌面端可保存多个网关配置。
- **SSL VPN 网页访问**。桌面端为本次连接启用系统 PAC。本地代理转发授权范围内的 HTTP、HTTPS 和 WebSocket 请求。断开后恢复连接前的系统代理设置。
- **NC/IPsec 网络接入**。根据网关下发的 NC 授权建立 IKEv1/IPsec 隧道，并安装本次会话的 IPv4 授权路由。Windows 通过 WSL2 和 strongSwan 建立隧道，也能桥接按单一 IPv4 主机及 TCP 端口获授权的资源，供桌面程序使用。macOS 使用原生 strongSwan，桌面登录时通过系统管理员授权自动建立隧道，断开或退出时清理会话网络配置。
- **记住账号和密码**。勾选保存选项并完成登录后，可以从当前网关的已保存账号菜单直接选择，也可移除保存记录。

## 适用范围

| 平台 | 接入方式与验证状态 |
| --- | --- |
| Windows x64 | 桌面版以单个 EXE 分发，内置界面和图标，并按需准备运行环境。SSL VPN 网页访问、NC 授权内网访问和堡垒机远程桌面已在实际网关场景验证。 |
| Apple Silicon macOS | 已在 macOS 27.2 上验证桌面登录、系统管理员授权、自动建立 NC/IPsec 隧道、授权内网页面访问及断开清理。桌面端同时提供 SSL 网页转发，正常使用无需运行终端命令。 |

当前适用于使用国际算法、且仅要求账号口令的 V5VPN 网关。证书登录、匿名登录、国密和多因素认证尚未实现。可访问的资源和网段由网关当次授权决定。

## 构建与运行

### Windows

从 [GitHub Releases](https://github.com/zhujiuyi/V5Vpn-Rust/releases) 下载 `V5VPN-Rust.exe`，双击启动。客户端检测 Microsoft Edge WebView2 Evergreen Runtime，缺失时从微软下载并安装。安装需要网络连接。

从源码构建需要 Rust MSVC 工具链和 Windows SDK。从仓库根目录构建并启动桌面端。

```powershell
cargo build --locked --release --bin v5vpn-desktop
.\target\release\v5vpn-desktop.exe
```

在「系统设置」中填写网关名称、地址和端口，再用账号口令登录。SSL VPN 网页转发就绪后，可用常用浏览器访问授权网页。

网关授予 NC/IPsec 资源后，桌面端会检查 WSL 2 和专用的 `V5VPN-NC` 环境，并按需下载、安装 Ubuntu 和 strongSwan 依赖。若当前进程需要提权，Windows 会提示管理员授权。授权时使用同一个 Windows 账号，随后在新窗口重新登录。如果 WSL 安装要求重启，请重启 Windows 后再次启动客户端。

开发联调时也可以在管理员 PowerShell 中手动准备 WSL 组件。

```powershell
wsl.exe --install --no-distribution --web-download
wsl.exe --status
```

在同一个 Windows 账号下运行 [WSL 初始化脚本](support/setup-wsl.ps1)，准备专用的 `V5VPN-NC` WSL2 Ubuntu 环境及其 strongSwan 依赖。

```powershell
.\support\setup-wsl.ps1
```

如果 PowerShell 执行策略要求脚本签名，请按本机策略处理签名。

需要 NC/IPsec 时，以同一个 Windows 账号的管理员权限运行客户端，以便配置会话路由。

### Apple Silicon macOS

源码构建需要 Rust 工具链和 Xcode 命令行工具。NC/IPsec 使用 Apple Silicon Homebrew 的 strongSwan，首次使用前安装运行组件并构建完整应用包：

```sh
brew install strongswan
./support/package-macos.sh
open ./target/aarch64-apple-darwin/release/V5VPN.app
```

构建结果位于 `target/aarch64-apple-darwin/release/V5VPN.app`。可将完整应用包拖入「应用程序」目录，之后从访达或 Dock 打开。首次安装 strongSwan 后，日常登录和退出均在桌面端完成。

在「系统设置」中填写网关名称、IP 或域名和端口，再返回桌面登录页输入 VPN 账号口令。网关授予 NC 资源时，客户端通过系统管理员授权窗口启动本次会话的 NC 辅助程序；在该窗口输入 macOS 管理员密码，授权后自动建立隧道。VPN 口令在桌面登录页输入，已保存的口令从用户钥匙串读取。若取消管理员授权，NC 显示未连接，已有 SSL 授权仍可用于网页转发。

可使用 `Command+Q` 或应用菜单中的「退出 V5VPN」退出。客户端先断开网关会话，清理 NC 隧道、授权路由和系统 PAC，再结束进程；窗口关闭和 Dock 的退出请求也进入同一流程。应用包包含 macOS ICNS 图标，并为直接运行桌面可执行文件设置 Dock 图标。

主界面与钥匙串操作保持普通用户权限，管理员辅助程序只负责 NC 网络配置。控制通道核对用户和进程身份，NC 会话密钥通过内存通道传输。断开、关闭窗口或控制通道消失后，辅助程序清理本次路由、IPsec 状态和引擎进程；启动时会识别并回收属于 V5VPN 的孤立引擎。

`package-macos.sh` 会一并打包桌面程序、`v5vpn-nc-helper` 和包含多种尺寸的 ICNS 图标。使用时保留完整的 `.app` 包，脚本生成的应用包使用本机临时签名。

当前 macOS 构建目标为 Apple Silicon（`aarch64-apple-darwin`），已在 macOS 27.2 真机验证管理员授权、NC 隧道、授权 HTTP 网页访问、`Command+Q` 退出及网络清理。Intel Mac 和 macOS 下的远程桌面连接未纳入本轮验证。

需要开发联调时，可选用管理员命令行。将示例网关和账号替换为实际配置，终端会提示输入密码。

```sh
brew install strongswan
cargo build --locked --release --target aarch64-apple-darwin --bin v5vpn-client
sudo -- ./target/aarch64-apple-darwin/release/v5vpn-client \
  --no-browser --gateway 'https://vpn.example.test' --username 'your-account'
```

命令行 NC 联调前，先断开桌面端的网关会话。终端中 `sudo` 的密码提示对应 macOS 管理员密码，`VPN 口令：` 对应网关账号口令；管理员授权仍有效时可能跳过第一项。命令行显示 `NC/IPsec 隧道已启用。` 后，可直接访问授权网段，保持终端打开，结束时按 `Ctrl+C` 断开。桌面端与命令行分别持有会话，桌面界面不显示命令行隧道的状态。

macOS 的 NAT-T 端口尚未初始化时，客户端选用 UDP 4500，由私有 strongSwan 引擎初始化。已有非零端口保持原值；引擎退出后恢复本次更改，若配置已被其他进程改动则保留其当前值。

## 配置与凭据

| 平台 | 网关配置和已保存账号列表 | 已保存密码 |
| --- | --- | --- |
| Windows | `%LOCALAPPDATA%\V5VPN Desktop\settings.json` | Windows 凭据管理器 |
| macOS | `~/Library/Application Support/V5VPN Desktop/settings.json` | macOS 钥匙串 |

已保存密码按网关和账号区分。网关 TLS 默认使用系统信任链。若企业网关使用私有 CA、证书链不完整或证书未包含实际访问的 IP/域名，优先由网关管理员修复证书配置；也可先通过可信渠道核对网关叶证书的 SHA-256 指纹，再在桌面端「系统设置」中填写「网关证书 SHA-256 指纹」。指纹支持 64 位十六进制及冒号分隔格式，填写后仅接受匹配的证书；留空恢复系统信任链验证。更改地址或端口会清空编辑中的指纹，需要重新核对。不要只根据当前网络连接读到的证书就认定网关可信。命令行联调可用 `--ca-file` 或 `--gateway-cert-sha256` 指定额外的信任依据。浏览器独立验证内网站点证书。

## 参考

开发中参考了 Go 版文档的网关协议、资源转发和使用说明。[v5vpn-rea-client](https://github.com/hygkui/v5vpn-rea-client/)
