use std::{future::pending, path::PathBuf};

use anyhow::{Context, Result, ensure};
use clap::Parser;
use url::Url;
use v5vpn_client::{
    browser,
    session::{ConnectionConfig, GatewayConfig, NcStatus},
};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(version, about = "使用 V5VPN 口令登录并打开已授权的 HTTPS 资源")]
struct Args {
    #[arg(long, help = "VPN 网关的 HTTPS 地址，可包含端口")]
    gateway: Url,
    #[arg(long, help = "VPN 登录账号")]
    username: String,
    #[arg(long, help = "联调时可将授权范围缩小到单个 HTTPS 地址")]
    resource: Option<Url>,
    #[arg(
        long,
        requires = "resource",
        help = "同一地址匹配多个资源时指定资源名称"
    )]
    resource_name: Option<String>,
    #[arg(long, help = "额外信任的网关 PEM CA 证书")]
    ca_file: Option<PathBuf>,
    #[arg(
        long,
        conflicts_with = "ca_file",
        help = "经确认的网关叶证书 SHA-256 指纹"
    )]
    gateway_cert_sha256: Option<String>,
    #[arg(
        long,
        value_name = "EXE",
        conflicts_with = "no_browser",
        requires = "resource",
        help = "Chrome 或 Edge 的可执行文件"
    )]
    browser: Option<PathBuf>,
    #[arg(long, help = "只启动回环代理并显示 PAC 地址")]
    no_browser: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let Some(resource_url) = args.resource.clone() else {
        let connection = GatewayConfig {
            gateway: args.gateway,
            username: args.username,
            gateway_cert_sha256: args.gateway_cert_sha256,
            ca_file: args.ca_file,
        }
        .prepare()
        .await?;
        let password = Zeroizing::new(rpassword::prompt_password("VPN 口令：")?);
        let mut session = connection.connect(password).await?;
        if let Err(error) = session.start_nc().await {
            let _ = session.disconnect().await;
            return Err(error);
        }
        match session.nc_status() {
            NcStatus::Connected => println!("NC/IPsec 隧道已启用。"),
            NcStatus::Failed(error) => eprintln!("NC/IPsec 未连接（{error}）。"),
            NcStatus::NotGranted => {}
        }
        if args.no_browser || !session.has_web_resources() {
            if session.has_web_resources() {
                println!("已登录并取得资源授权。PAC {}", session.pac_url());
            }
            return session
                .run_until(async {
                    tokio::signal::ctrl_c().await.context("监听退出信号失败")
                })
                .await;
        }
        let guard = match session.enable_system_proxy() {
            Ok(guard) => guard,
            Err(error) => {
                if let Err(logout_error) = session.disconnect().await {
                    eprintln!("{logout_error:#}");
                }
                return Err(error);
            }
        };
        println!("已登录并取得资源授权。系统代理已启用。按 Ctrl+C 断开。");
        return session
            .run_with_system_proxy(guard, async {
                if let Err(error) = tokio::signal::ctrl_c().await {
                    eprintln!("监听退出信号失败：{error}");
                }
            })
            .await;
    };
    let executable = if args.no_browser {
        None
    } else {
        Some(browser::executable(args.browser)?)
    };
    let connection = ConnectionConfig {
        gateway: args.gateway,
        username: args.username,
        resource: resource_url.clone(),
        resource_name: args.resource_name,
        gateway_cert_sha256: args.gateway_cert_sha256,
        ca_file: args.ca_file,
    }
    .prepare()
    .await?;
    let password = Zeroizing::new(rpassword::prompt_password("VPN 口令：")?);
    let session = connection.connect(password).await?;
    let mut browser = match executable
        .as_deref()
        .map(|exe| browser::launch(exe, session.pac_url(), &resource_url))
        .transpose()
    {
        Ok(browser) => browser,
        Err(error) => {
            if let Err(logout_error) = session.disconnect().await {
                eprintln!("{logout_error:#}");
            }
            return Err(error);
        }
    };
    println!("已登录并取得资源授权。PAC {}", session.pac_url());
    println!("资源地址 {}", resource_url.origin().ascii_serialization());
    println!("打开资源页面后即可核对连通性。按 Ctrl+C 断开。");
    let result = session
        .run_until(async {
            tokio::select! {
                signal = tokio::signal::ctrl_c() => signal.context("监听退出信号失败"),
                status = async {
                    match browser.as_mut() {
                        Some((child, _)) => child.wait().await,
                        None => pending().await,
                    }
                } => {
                    ensure!(status.context("浏览器进程异常")?.success(), "浏览器异常退出");
                    Ok(())
                }
            }
        })
        .await;
    if let Some((mut child, _profile)) = browser {
        let _ = child.kill().await;
    }
    result
}
