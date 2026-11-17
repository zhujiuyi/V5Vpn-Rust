use std::{
    future::{Future, pending},
    net::{Ipv4Addr, SocketAddrV4},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use tokio::net::TcpListener;
use url::Url;
use zeroize::Zeroizing;

use crate::{
    SystemProxyGuard, nc,
    nc_policy::NcPolicy,
    portal::Gateway,
    proxy::{PAC_PATH, Proxy},
};

pub struct ConnectionConfig {
    pub gateway: Url,
    pub username: String,
    pub resource: Url,
    pub resource_name: Option<String>,
    pub gateway_cert_sha256: Option<String>,
    pub ca_file: Option<PathBuf>,
}

pub struct GatewayConfig {
    pub gateway: Url,
    pub username: String,
    pub gateway_cert_sha256: Option<String>,
    pub ca_file: Option<PathBuf>,
}

pub struct PreparedGateway {
    gateway: Arc<Gateway>,
    username: String,
}

pub struct PreparedConnection {
    gateway: Arc<Gateway>,
    username: String,
    resource_url: Url,
    resource_name: Option<String>,
    address: Ipv4Addr,
    port: u16,
}

pub struct Session {
    gateway: Arc<Gateway>,
    proxy: Arc<Proxy>,
    listener: TcpListener,
    pac_url: String,
    web_resources: bool,
    nc_policy: Option<NcPolicy>,
    nc_error: Option<String>,
    nc: Option<nc::Session>,
}

pub enum NcStatus {
    NotGranted,
    Connected,
    Failed(String),
}

impl GatewayConfig {
    pub async fn prepare(self) -> Result<PreparedGateway> {
        let gateway = Arc::new(Gateway::new(
            self.gateway,
            self.ca_file.as_deref(),
            self.gateway_cert_sha256.as_deref(),
        )?);
        gateway.check_version().await?;
        ensure!(!self.username.trim().is_empty(), "登录账号不能为空");
        Ok(PreparedGateway {
            gateway,
            username: self.username,
        })
    }
}

impl ConnectionConfig {
    pub async fn prepare(self) -> Result<PreparedConnection> {
        let (address, port) = resource_address(&self.resource)?;
        let PreparedGateway { gateway, username } = GatewayConfig {
            gateway: self.gateway,
            username: self.username,
            gateway_cert_sha256: self.gateway_cert_sha256,
            ca_file: self.ca_file,
        }
        .prepare()
        .await?;
        Ok(PreparedConnection {
            gateway,
            username,
            resource_url: self.resource,
            resource_name: self.resource_name,
            address,
            port,
        })
    }
}

impl PreparedConnection {
    pub async fn connect(self, password: Zeroizing<String>) -> Result<Session> {
        login(&self.gateway, &self.username, password).await?;

        let result = self.bind_proxy().await;
        if result.is_err() {
            log_logout_failure(&self.gateway).await;
        }
        result
    }

    async fn bind_proxy(&self) -> Result<Session> {
        let resource = self
            .gateway
            .resource(self.address, self.port, self.resource_name.as_deref())
            .await
            .context("获取所选资源的授权失败")?;
        let proxy = Proxy::new(self.gateway.clone(), resource, self.resource_url.clone());
        Session::bind(self.gateway.clone(), proxy, true, None, None).await
    }
}

impl PreparedGateway {
    pub async fn connect(self, password: Zeroizing<String>) -> Result<Session> {
        login(&self.gateway, &self.username, password).await?;
        let result = async {
            let mut resources = self
                .gateway
                .authorized_resources()
                .await
                .context("读取网关授权失败")?;
            let web_resources = !resources.routes.is_empty();
            let nc_policy = resources.nc_policy.take();
            let nc_error = resources.nc_error.take();
            let proxy = Proxy::for_authorized(self.gateway.clone(), resources);
            Session::bind(
                self.gateway.clone(),
                proxy,
                web_resources,
                nc_policy,
                nc_error,
            )
            .await
        }
        .await;
        if result.is_err() {
            log_logout_failure(&self.gateway).await;
        }
        result
    }
}

impl Session {
    pub async fn connect_gateway(
        config: GatewayConfig,
        password: Zeroizing<String>,
    ) -> Result<Self> {
        config.prepare().await?.connect(password).await
    }

    async fn bind(
        gateway: Arc<Gateway>,
        proxy: Proxy,
        web_resources: bool,
        nc_policy: Option<NcPolicy>,
        nc_error: Option<String>,
    ) -> Result<Self> {
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .await
            .context("无法启动本地代理")?;
        let pac_url = format!("http://{}{PAC_PATH}", listener.local_addr()?);
        Ok(Self {
            gateway,
            proxy: Arc::new(proxy),
            listener,
            pac_url,
            web_resources,
            nc_policy,
            nc_error,
            nc: None,
        })
    }

    pub fn pac_url(&self) -> &str {
        &self.pac_url
    }

    pub fn has_web_resources(&self) -> bool {
        self.web_resources
    }

    pub fn nc_status(&self) -> NcStatus {
        if self.nc.is_some() {
            NcStatus::Connected
        } else if let Some(error) = &self.nc_error {
            NcStatus::Failed(error.clone())
        } else {
            NcStatus::NotGranted
        }
    }

    pub async fn start_nc(&mut self) -> Result<()> {
        if let Some(policy) = self.nc_policy.take() {
            match nc::start(policy, self.gateway.host(), self.proxy.clone()).await {
                Ok(session) => self.nc = Some(session),
                Err(error) => self.nc_error = Some(format!("{error:#}")),
            }
        }
        if !self.web_resources && self.nc.is_none() {
            anyhow::bail!(
                "NC/IPsec 连接失败：{}",
                self.nc_error
                    .as_deref()
                    .unwrap_or("网关未授权可用的网络资源")
            );
        }
        Ok(())
    }

    pub async fn run(self, stop: impl Future<Output = ()> + Send) -> Result<()> {
        self.run_until(async {
            stop.await;
            Ok(())
        })
        .await
    }

    pub async fn run_until(self, stop: impl Future<Output = Result<()>> + Send) -> Result<()> {
        self.run_connection(stop, None).await
    }

    pub fn enable_system_proxy(&self) -> Result<SystemProxyGuard> {
        SystemProxyGuard::activate(&self.pac_url).context("无法启用系统代理")
    }

    pub async fn run_with_system_proxy(
        self,
        guard: SystemProxyGuard,
        stop: impl Future<Output = ()> + Send,
    ) -> Result<()> {
        self.run_connection(
            async {
                stop.await;
                Ok(())
            },
            Some(guard),
        )
        .await
    }

    async fn run_connection(
        self,
        stop: impl Future<Output = Result<()>> + Send,
        mut system_proxy: Option<SystemProxyGuard>,
    ) -> Result<()> {
        let Self {
            gateway,
            listener,
            proxy,
            mut nc,
            ..
        } = self;
        let result = {
            let service = proxy.clone().serve(listener);
            tokio::pin!(service);
            let result = tokio::select! {
                biased;
                result = stop => result,
                result = &mut service => result,
                result = proxy.keepalive() => result,
                result = monitor_nc(nc.as_mut()) => result,
            };
            let restored = system_proxy
                .as_mut()
                .map_or(Ok(()), SystemProxyGuard::restore);
            result.and(restored.context("无法还原连接前的系统代理"))
        };
        let nc_result = stop_nc(nc).await;
        log_logout_failure(&gateway).await;
        result.and(nc_result)
    }

    pub async fn disconnect(self) -> Result<()> {
        let Self {
            gateway,
            listener,
            proxy,
            nc,
            ..
        } = self;
        drop(listener);
        drop(proxy);
        let stopped = stop_nc(nc).await;
        stopped.and(gateway.logout().await.context("网关退出未确认"))
    }
}

async fn monitor_nc(session: Option<&mut nc::Session>) -> Result<()> {
    let Some(session) = session else {
        return pending().await;
    };
    loop {
        tokio::time::sleep(Duration::from_secs(10)).await;
        session.is_healthy().await.context("NC/IPsec 隧道失效")?;
    }
}

async fn stop_nc(session: Option<nc::Session>) -> Result<()> {
    if let Some(mut session) = session {
        session.stop().await.context("清理 NC/IPsec 隧道失败")?;
    }
    Ok(())
}

async fn login(gateway: &Gateway, username: &str, password: Zeroizing<String>) -> Result<()> {
    ensure!(!password.is_empty(), "口令不能为空");
    gateway
        .login(username, &password)
        .await
        .context("网关口令登录失败")
}

async fn log_logout_failure(gateway: &Gateway) {
    if let Err(error) = gateway.logout().await {
        eprintln!("网关退出未确认：{error:#}");
    }
}

fn resource_address(url: &Url) -> Result<(Ipv4Addr, u16)> {
    ensure!(
        url.scheme() == "https" && url.username().is_empty() && url.password().is_none(),
        "资源地址必须是 HTTPS URL"
    );
    let Some(url::Host::Ipv4(address)) = url.host() else {
        anyhow::bail!("HTTPS 资源地址需要 IPv4");
    };
    let port = url
        .port_or_known_default()
        .filter(|&value| value != 0)
        .context("资源端口无效")?;
    Ok((address, port))
}
