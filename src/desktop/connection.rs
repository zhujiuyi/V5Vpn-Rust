use std::{future::pending, sync::mpsc, thread, time::Duration};

use anyhow::{Context, Result, ensure};
use tokio::sync::oneshot;
use v5vpn_client::session::{GatewayConfig, NcStatus, Session};
use zeroize::Zeroizing;

pub(super) enum WorkerEvent {
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
                let post = |event| {
                    let _ = send_event.send(event);
                    wake();
                };
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
    post: &(impl Fn(WorkerEvent) + Sync),
) -> Result<()> {
    let mut session = Session::connect_gateway(config, password).await?;
    if !matches!(stop.try_recv(), Err(oneshot::error::TryRecvError::Empty)) {
        return session.disconnect().await;
    }

    if let Err(error) = session.start_nc().await {
        let _ = session.disconnect().await;
        return Err(error);
    }
    if !matches!(stop.try_recv(), Err(oneshot::error::TryRecvError::Empty)) {
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
