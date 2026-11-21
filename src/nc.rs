#[cfg(any(windows, target_os = "macos"))]
use std::{net::Ipv4Addr, time::Duration};

use anyhow::Result;

use crate::{nc_policy::NcPolicy, proxy::Proxy};
use std::sync::Arc;

#[cfg(windows)]
#[path = "nc_windows.rs"]
mod platform;
#[cfg(target_os = "macos")]
#[path = "nc_macos.rs"]
mod platform;

#[cfg(target_os = "macos")]
#[path = "nc_macos_elevated.rs"]
pub(crate) mod elevated;

#[cfg(target_os = "macos")]
pub(crate) use elevated::Session;
#[cfg(windows)]
pub(crate) use platform::Session;

#[cfg(windows)]
pub(crate) async fn start(
    policy: NcPolicy,
    gateway_host: &str,
    proxy: Arc<Proxy>,
) -> Result<Session> {
    platform::start(policy, gateway_host, proxy).await
}

#[cfg(target_os = "macos")]
pub(crate) async fn start(
    policy: NcPolicy,
    gateway_host: &str,
    _proxy: Arc<Proxy>,
) -> Result<Session> {
    elevated::start(policy, gateway_host).await
}

#[cfg(not(any(windows, target_os = "macos")))]
pub(crate) struct Session;

#[cfg(not(any(windows, target_os = "macos")))]
pub(crate) async fn start(
    _policy: NcPolicy,
    _gateway_host: &str,
    _proxy: Arc<Proxy>,
) -> Result<Session> {
    anyhow::bail!("NC/IPsec 后端支持 Windows 和 macOS")
}

#[cfg(not(any(windows, target_os = "macos")))]
impl Session {
    pub(crate) async fn is_healthy(&mut self) -> Result<()> {
        anyhow::bail!("当前系统无 NC/IPsec 后端")
    }

    pub(crate) async fn stop(&mut self) -> Result<()> {
        Ok(())
    }
}

#[cfg(any(windows, target_os = "macos"))]
pub(crate) async fn gateway_ipv4(host: &str) -> Result<Ipv4Addr> {
    use anyhow::Context;

    let usable = |ip: Ipv4Addr| !ip.is_unspecified() && !ip.is_multicast() && !ip.is_loopback();
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        anyhow::ensure!(usable(ip), "NC 网关需要可用的单播 IPv4 对端");
        return Ok(ip);
    }
    let mut addresses: Vec<_> =
        tokio::time::timeout(Duration::from_secs(5), tokio::net::lookup_host((host, 0)))
            .await
            .context("解析 NC 网关地址超时")??
            .filter_map(|address| match address.ip() {
                std::net::IpAddr::V4(ip) if usable(ip) => Some(ip),
                _ => None,
            })
            .collect();
    addresses.sort_unstable();
    addresses.dedup();
    match addresses.as_slice() {
        [address] => Ok(*address),
        _ => anyhow::bail!("NC 网关须有明确的 IPv4 对端，请使用网关的 IPv4 地址"),
    }
}

#[cfg(any(windows, target_os = "macos"))]
pub(crate) fn validate_routes(policy: &NcPolicy, excluded: &[Ipv4Addr]) -> Result<()> {
    anyhow::ensure!(
        policy.routes.iter().all(|route| {
            if route.prefix == 0 || route.prefix > 32 {
                return false;
            }
            let mask = u32::MAX << (32 - route.prefix);
            excluded
                .iter()
                .all(|address| u32::from(*address) & mask != u32::from(route.network))
        }),
        "NC 授权路由与网关出口或转发路径重叠"
    );
    Ok(())
}
