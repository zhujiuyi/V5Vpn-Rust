use std::{
    collections::BTreeSet, env, io, net::Ipv4Addr, os::windows::process::CommandExt, path::PathBuf,
    process::Stdio, sync::Arc, time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Join, join},
    process::{Child, ChildStdin, ChildStdout, Command},
    time::timeout,
};
use windows_sys::Win32::{
    Foundation::CloseHandle,
    Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation},
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    nc::{gateway_ipv4, validate_routes},
    nc_policy::{Ipv4Cidr, NcPolicy},
    nc_vici::Vici,
    nc_windows_routes::Routes,
    proxy::Proxy,
};

#[path = "nc_windows_native.rs"]
mod native;
use native::NativeRelay;

const DISTRO: &str = "V5VPN-NC";
const RUNTIME: &str = include_str!("../support/wsl-nc-session.sh");
const NATIVE_HELPER: &str = include_str!("../support/wsl-native-relay.py");
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
type Transport = Join<BufReader<ChildStdout>, ChildStdin>;

pub(crate) struct Session {
    routes: Routes,
    native: Option<NativeRelay>,
    vici: Option<Vici<Transport>>,
    worker: Child,
    policy: NcPolicy,
}

#[derive(Deserialize)]
struct Route {
    gateway: Ipv4Addr,
    prefsrc: Ipv4Addr,
    dev: String,
}

pub(crate) async fn start(
    mut policy: NcPolicy,
    gateway_host: &str,
    proxy: Arc<Proxy>,
) -> Result<Session> {
    let peer = gateway_ipv4(gateway_host).await?;
    validate_routes(&policy, &[peer])?;
    verify_distribution().await?;
    ensure!(
        elevated()?,
        "Windows 安装 NC 路由需要管理员权限，请以管理员身份直接启动客户端"
    );

    let route = guest_route(peer).await?;
    ensure!(
        route.dev != "lo" && route.gateway != route.prefsrc,
        "专用 WSL2 发行版没有可用的 NAT 接口"
    );
    validate_routes(&policy, &[route.gateway, route.prefsrc])?;

    let excluded = [peer, route.gateway, route.prefsrc, policy.virtual_ip];
    let native_hosts: BTreeSet<_> = proxy
        .native_ipv4_hosts()
        .into_iter()
        .filter(|host| {
            !excluded.contains(host)
                && !policy.routes.iter().any(|network| {
                    let mask = u32::MAX << (32 - network.prefix);
                    u32::from(*host) & mask == u32::from(network.network)
                })
        })
        .collect();
    // Only the IPsec prefixes go to VICI. The other /32 routes reach the same
    // WSL adapter, where their TCP connections are redirected to the relay.
    let mut windows_routes = policy.routes.clone();
    windows_routes.extend(native_hosts.iter().map(|&address| Ipv4Cidr {
        network: address,
        prefix: 32,
    }));
    let (native, native_line) = if native_hosts.is_empty() {
        (None, Zeroizing::new("native 0 -\n".to_owned()))
    } else {
        let (relay, line) =
            NativeRelay::start(route.gateway, route.prefsrc, native_hosts, proxy).await?;
        (Some(relay), line)
    };

    let runtime = RUNTIME.replace("\r\n", "\n").replace(
        "__V5VPN_NATIVE_HELPER__",
        &NATIVE_HELPER.replace("\r\n", "\n"),
    );
    let mut worker = wsl()?
        .args(["/bin/sh", "-c", &runtime])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("无法启动专用 WSL2 NC 进程")?;
    let mut input = worker.stdin.take().context("无法打开 WSL2 控制管道")?;
    let mut output = BufReader::new(worker.stdout.take().context("无法读取 WSL2 控制管道")?);
    let mut first_line = format!(
        "{} {} {} {}",
        peer, policy.server_port, policy.virtual_ip, route.gateway
    );
    for network in &policy.routes {
        use std::fmt::Write;
        write!(first_line, " {}/{}", network.network, network.prefix)?;
    }
    first_line.push('\n');
    timeout(Duration::from_secs(15), async {
        input.write_all(first_line.as_bytes()).await?;
        input.write_all(native_line.as_bytes()).await?;
        drop(native_line);
        input.flush().await?;
        let mut ready = String::new();
        output.read_line(&mut ready).await?;
        match ready.trim() {
            "V5VPN_NC_READY" => Ok(()),
            "V5VPN_BUSY" | "V5VPN_NETWORK_BUSY" | "V5VPN_CHARON_EXISTS" => {
                bail!("WSL2 中已有 IPsec 或转发会话，请先结束占用专用运行环境的会话")
            }
            "V5VPN_UNMANAGED" => bail!("请先运行 support/setup-wsl.ps1 准备专用发行版"),
            "V5VPN_XFRM_FAILED" => bail!("WSL2 内核未提供可用的 XFRM/IPsec 接口"),
            "V5VPN_NATIVE_FAILED" => bail!("WSL2 未能启动原生 TCP 资源转发"),
            _ => bail!("WSL2 未完成 IPsec 启动，检查专用发行版和 strongSwan 安装"),
        }
    })
    .await
    .context("等待 WSL2 strongSwan 就绪超时")??;

    let mut vici = Vici::new(join(output, input));
    if let Err(error) = vici.establish(&policy, peer).await {
        finish_worker(&mut worker, vici, &policy).await.ok();
        return Err(error);
    }
    policy.psk.zeroize();
    match Routes::install(&windows_routes, route.prefsrc, route.gateway) {
        Ok(routes) => Ok(Session {
            routes,
            native,
            vici: Some(vici),
            worker,
            policy,
        }),
        Err(error) => {
            finish_worker(&mut worker, vici, &policy).await.ok();
            Err(error)
        }
    }
}

impl Session {
    pub(crate) async fn is_healthy(&mut self) -> Result<()> {
        ensure!(self.worker.try_wait()?.is_none(), "WSL2 NC 后端已退出");
        if let Some(native) = &self.native {
            native.is_healthy()?;
        }
        self.vici
            .as_mut()
            .context("NC 隧道已关闭")?
            .is_healthy(&self.policy)
            .await?;
        self.routes.renew()
    }

    pub(crate) async fn stop(&mut self) -> Result<()> {
        let routes = self.routes.remove();
        let native = match self.native.take() {
            Some(native) => native.stop().await,
            None => Ok(()),
        };
        let worker = match self.vici.take() {
            Some(vici) => finish_worker(&mut self.worker, vici, &self.policy).await,
            None => Ok(()),
        };
        routes.and(native).and(worker)
    }
}

async fn finish_worker(
    worker: &mut Child,
    mut vici: Vici<Transport>,
    policy: &NcPolicy,
) -> Result<()> {
    let stopped = vici.stop(policy).await;
    drop(vici);
    match timeout(Duration::from_secs(5), worker.wait()).await {
        Ok(status) => ensure!(status?.success(), "WSL2 NC 后端未确认完成清理"),
        Err(_) => {
            let _ = worker.kill().await;
            bail!("WSL2 NC 后端清理超时");
        }
    }
    stopped
}

async fn verify_distribution() -> Result<()> {
    let result = timeout(
        Duration::from_secs(12),
        wsl()?
            .args([
                "/usr/bin/test",
                "-f",
                "/etc/v5vpn-nc/managed-ubuntu-24.04-v1",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status(),
    )
    .await
    .context("启动专用 WSL2 发行版超时")??;
    ensure!(
        result.success(),
        "找不到专用 V5VPN-NC 发行版，请运行 support/setup-wsl.ps1"
    );
    Ok(())
}

async fn guest_route(peer: Ipv4Addr) -> Result<Route> {
    let result = timeout(
        Duration::from_secs(8),
        wsl()?
            .args([
                "/usr/sbin/ip",
                "-j",
                "-4",
                "route",
                "get",
                &peer.to_string(),
            ])
            .output(),
    )
    .await
    .context("查询 WSL2 NAT 路径超时")??;
    ensure!(result.status.success(), "无法查询 WSL2 的 IPv4 出口");
    serde_json::from_slice::<Vec<Route>>(&result.stdout)
        .context("无法取得 WSL2 NAT 的宿主和来宾地址")?
        .into_iter()
        .next()
        .context("WSL2 没有可用的 NAT 路径")
}

fn wsl() -> Result<Command> {
    let executable = PathBuf::from(env::var_os("SystemRoot").context("找不到 Windows 系统目录")?)
        .join("System32/wsl.exe");
    let mut command = std::process::Command::new(executable);
    command.creation_flags(CREATE_NO_WINDOW).args([
        "--distribution",
        DISTRO,
        "--user",
        "root",
        "--exec",
    ]);
    let mut command = Command::from(command);
    command.kill_on_drop(true);
    Ok(command)
}

fn elevated() -> io::Result<bool> {
    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut data = TOKEN_ELEVATION::default();
    let mut returned = 0;
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            (&mut data as *mut TOKEN_ELEVATION).cast(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    };
    let failure = (ok == 0).then(io::Error::last_os_error);
    unsafe { CloseHandle(token) };
    match failure {
        Some(error) => Err(error),
        None => Ok(data.TokenIsElevated != 0),
    }
}
