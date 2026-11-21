use std::{
    future::pending,
    sync::{Arc, mpsc},
    thread,
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use tokio::sync::oneshot;
use v5vpn_client::session::{GatewayConfig, NcStatus, Session};
use zeroize::Zeroizing;

#[cfg(windows)]
use super::{windows_nc_distribution, windows_nc_host};

type Post = Arc<dyn Fn(WorkerEvent) + Send + Sync>;

pub(super) enum WorkerEvent {
    #[cfg(windows)]
    Preparing(String),
    #[cfg(windows)]
    Relaunched,
    Connected {
        web_resources: bool,
        nc_status: NcStatus,
    },
    Finished(Option<String>),
}

pub(super) struct Worker {
    pub(super) events: mpsc::Receiver<WorkerEvent>,
    stop: Option<oneshot::Sender<()>>,
}

impl Worker {
    pub(super) fn start(
        config: GatewayConfig,
        password: Zeroizing<String>,
        wake: impl Fn() + Send + Sync + 'static,
    ) -> Result<Self> {
        let (send_event, events) = mpsc::channel();
        let (stop, stop_request) = oneshot::channel();
        thread::Builder::new()
            .name("v5vpn-session".into())
            .spawn(move || {
                let post: Post = Arc::new(move |event| {
                    let _ = send_event.send(event);
                    wake();
                });
                let result = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .context("无法启动连接服务")
                    .and_then(|runtime| {
                        runtime.block_on(run_session(config, password, stop_request, &post))
                    });
                post(WorkerEvent::Finished(
                    result.err().map(|error| format!("{error:#}")),
                ));
            })
            .context("无法启动连接线程")?;
        Ok(Self {
            events,
            stop: Some(stop),
        })
    }

    pub(super) fn stop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}

async fn run_session(
    config: GatewayConfig,
    password: Zeroizing<String>,
    mut stop: oneshot::Receiver<()>,
    post: &Post,
) -> Result<()> {
    #[cfg(windows)]
    let mut session = {
        let session = Session::connect_gateway(config.clone(), password.clone()).await?;
        let Some(session) = prepare_windows_nc(session, config, password, &mut stop, post).await?
        else {
            return Ok(());
        };
        session
    };
    #[cfg(not(windows))]
    let mut session = Session::connect_gateway(config, password).await?;
    if stop_requested(&mut stop) {
        return session.disconnect().await;
    }

    #[cfg(target_os = "macos")]
    let nc_result = tokio::select! {
        result = session.start_nc() => Some(result),
        _ = &mut stop => None,
    };
    #[cfg(not(target_os = "macos"))]
    let nc_result = Some(session.start_nc().await);
    let Some(nc_result) = nc_result else {
        return session.disconnect().await;
    };
    if let Err(error) = nc_result {
        let _ = session.disconnect().await;
        return Err(error);
    }
    if stop_requested(&mut stop) {
        return session.disconnect().await;
    }
    let nc_status = session.nc_status();
    let web_resources = session.has_web_resources();
    if !web_resources {
        post(WorkerEvent::Connected {
            web_resources,
            nc_status,
        });
        return session
            .run(async {
                let _ = stop.await;
            })
            .await;
    }

    let pac_url = session.pac_url().to_owned();
    let guard = match session.enable_system_proxy() {
        Ok(guard) => guard,
        Err(error) => {
            return match session.disconnect().await {
                Ok(()) => Err(error.context("无法启用系统代理")),
                Err(logout) => {
                    Err(error.context(format!("无法启用系统代理，网关登出未确认：{logout:#}")))
                }
            };
        }
    };

    let mut startup_error = None;
    let result = session
        .run_with_system_proxy(guard, async {
            tokio::select! {
                biased;
                _ = &mut stop => {}
                error = async {
                    if let Err(error) = verify_local_pac(&pac_url).await {
                        return error;
                    }
                    post(WorkerEvent::Connected { web_resources, nc_status });
                    pending().await
                } => { startup_error = Some(error); }
            }
        })
        .await;
    match startup_error {
        Some(error) => result.and(Err(error)),
        None => result,
    }
}

fn stop_requested(stop: &mut oneshot::Receiver<()>) -> bool {
    !matches!(stop.try_recv(), Err(oneshot::error::TryRecvError::Empty))
}

#[cfg(windows)]
async fn prepare_windows_nc(
    mut session: Session,
    config: GatewayConfig,
    password: Zeroizing<String>,
    stop: &mut oneshot::Receiver<()>,
    post: &Post,
) -> Result<Option<Session>> {
    if !session.has_nc_authorization() {
        return Ok(Some(session));
    }
    if stop_requested(stop) {
        return session.disconnect().await.map(|()| None);
    }
    match windows_nc_host::is_elevated() {
        Ok(false) => {
            post(WorkerEvent::Preparing(
                "NC/IPsec 需要 Windows 管理员授权。授权后请在新窗口重新登录。".into(),
            ));
            let launch = tokio::task::spawn_blocking(windows_nc_host::relaunch_elevated)
                .await
                .context("无法请求 Windows 管理员授权")
                .and_then(|result| result);
            match launch {
                Ok(true) => {
                    let result = session.disconnect().await;
                    post(WorkerEvent::Relaunched);
                    return result.map(|()| None);
                }
                Ok(false) => session.defer_nc(anyhow::anyhow!("已取消 Windows 管理员授权")),
                Err(error) => session.defer_nc(error),
            }
            return Ok(Some(session));
        }
        Err(error) => {
            session.defer_nc(error);
            return Ok(Some(session));
        }
        Ok(true) => {}
    }

    let readiness = tokio::task::spawn_blocking(|| -> Result<bool> {
        match windows_nc_host::ready_host()? {
            Some(wsl) => windows_nc_distribution::distribution_ready(&wsl),
            None => Ok(false),
        }
    })
    .await
    .context("无法检查 NC/IPsec 运行环境")
    .and_then(|result| result);
    match readiness {
        Ok(true) => return Ok(Some(session)),
        Err(error) => {
            session.defer_nc(error);
            return Ok(Some(session));
        }
        Ok(false) => {}
    }
    if stop_requested(stop) {
        return session.disconnect().await.map(|()| None);
    }

    // Preparing WSL can take longer than the gateway's unaided login session.
    let web_resources = session.has_web_resources();
    session.disconnect().await?;
    post(WorkerEvent::Preparing("正在准备 NC/IPsec 运行环境…".into()));
    let progress_events = Arc::clone(post);
    let setup = tokio::task::spawn_blocking(move || {
        let progress = |message: &str| {
            progress_events(WorkerEvent::Preparing(message.to_owned()));
        };
        let wsl = windows_nc_host::ensure_host(progress)?;
        windows_nc_distribution::ensure_distribution(&wsl, progress)
    })
    .await
    .context("无法完成 NC/IPsec 环境准备")
    .and_then(|result| result);
    if stop_requested(stop) {
        return Ok(None);
    }
    if !web_resources && let Err(error) = setup {
        return Err(error);
    }

    post(WorkerEvent::Preparing("正在重新连接网关…".into()));
    let mut session = Session::connect_gateway(config, password).await?;
    if let Err(error) = setup {
        session.defer_nc(error);
    }
    Ok(Some(session))
}

async fn verify_local_pac(pac_url: &str) -> Result<()> {
    let response = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(3))
        .redirect(reqwest::redirect::Policy::none())
        .build()?
        .get(pac_url)
        .send()
        .await
        .context("本地代理未响应")?;
    ensure!(
        response.status() == reqwest::StatusCode::OK,
        "本地代理未返回 PAC 文件"
    );
    let pac = response.bytes().await.context("无法读取本地 PAC 文件")?;
    ensure!(
        pac.starts_with(b"function FindProxyForURL("),
        "本地 PAC 文件无效"
    );
    Ok(())
}
