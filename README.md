# V5Vpn-Rust

V5Vpn-Rust 是一个独立的 V5VPN 兼容客户端，使用 Rust 实现账号登录、会话管理和授权资源访问，提供桌面界面与命令行工具。项目面向获授权使用企业 V5VPN 网关的场景。

## 已实现的功能

- **账号口令登录**。使用国际算法访问 HTTPS 网关，获取会话资源授权，并处理心跳和主动断开。桌面端可保存多个网关配置。
- **SSL VPN 网页访问**。桌面端为本次连接启用系统 PAC。本地代理转发授权范围内的 HTTP、HTTPS 和 WebSocket 请求。断开后恢复连接前的系统代理设置。
- **NC/IPsec 网络接入**。根据网关下发的 NC 授权建立 IKEv1/IPsec 隧道，并安装本次会话的 IPv4 授权路由。Windows 通过 WSL2 和 strongSwan 建立隧道，也能桥接按单一 IPv4 主机及 TCP 端口获授权的资源，供桌面程序使用。
- **记住账号和密码**。勾选保存选项并完成登录后，可以从当前网关的已保存账号菜单直接选择，也可移除保存记录。

## 适用范围

| 平台 | 接入方式与验证状态 |
| --- | --- |
| Windows x64 | 桌面版以单个 EXE 分发，内置界面和图标，使用系统 WebView2。SSL VPN 网页访问、NC 授权内网访问和堡垒机远程桌面已在实际网关场景验证。 |
| Apple Silicon macOS | 适配目标包含 macOS 27。桌面端提供网页转发，NC/IPsec 通过管理员权限下的命令行联调。代码已通过 Apple Silicon 目标类型检查，真机联通性待验证。 |

当前适用于使用国际算法、且仅要求账号口令的 V5VPN 网关。证书登录、匿名登录、国密和多因素认证尚未实现。可访问的资源和网段由网关当次授权决定。

## 构建与运行

### Windows

构建需要 Rust MSVC 工具链和 Windows SDK，运行桌面客户端需要 Microsoft Edge WebView2 Runtime。从仓库根目录构建并启动桌面端。

```powershell
cargo build --locked --release --bin v5vpn-desktop
.\target\release\v5vpn-desktop.exe
```

在「系统设置」中填写网关名称、地址和端口，再用账号口令登录。SSL VPN 网页转发就绪后，可用常用浏览器访问授权网页。

如需 NC/IPsec，先在管理员 PowerShell 中准备 WSL 组件。若系统要求重启，重启后再确认 WSL 状态。

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

在 Mac 上安装 Rust 工具链和 Xcode 命令行工具，再构建和运行桌面端。启用系统 PAC 时，macOS 可能要求授权。

```sh
cargo build --locked --release --target aarch64-apple-darwin --bin v5vpn-desktop
./target/aarch64-apple-darwin/release/v5vpn-desktop
```

NC/IPsec 联调使用 Apple Silicon Homebrew 安装的 strongSwan。将示例网关和账号替换为实际配置，终端会提示输入密码。

```sh
brew install strongswan
cargo build --locked --release --target aarch64-apple-darwin --bin v5vpn-client
sudo -- ./target/aarch64-apple-darwin/release/v5vpn-client \
  --no-browser --gateway 'https://vpn.example.test' --username 'your-account'
```

## 配置与凭据

| 平台 | 网关配置和已保存账号列表 | 已保存密码 |
| --- | --- | --- |
| Windows | `%LOCALAPPDATA%\V5VPN Desktop\settings.json` | Windows 凭据管理器 |
| macOS | `~/Library/Application Support/V5VPN Desktop/settings.json` | macOS 钥匙串 |

已保存密码按网关和账号区分。网关 TLS 使用系统信任链，旧配置中已确认的证书指纹在端点相同的情况下继续生效。命令行联调可用 `--ca-file` 或 `--gateway-cert-sha256` 为网关指定额外的信任依据。浏览器独立验证内网站点证书。

## 参考

开发中参考了 Go 版文档的网关协议、资源转发和使用说明。[v5vpn-rea-client](https://github.com/hygkui/v5vpn-rea-client/)
