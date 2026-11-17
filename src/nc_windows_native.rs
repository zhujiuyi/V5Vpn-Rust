use std::{
    collections::BTreeSet,
    fmt::Write,
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::{JoinHandle, JoinSet},
    time::timeout,
};
use zeroize::Zeroizing;

use crate::proxy::Proxy;

const NONCE_LEN: usize = 32;
const HEADER_LEN: usize = NONCE_LEN + 4 + 2;
const IPC_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CONNECTIONS: usize = 32;

pub(super) struct NativeRelay {
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<Result<()>>,
}

struct RelayAuthorization {
    nonce: Zeroizing<[u8; NONCE_LEN]>,
    hosts: BTreeSet<Ipv4Addr>,
    proxy: Arc<Proxy>,
}

impl NativeRelay {
    pub(super) async fn start(
        host: Ipv4Addr,
        guest: Ipv4Addr,
        hosts: BTreeSet<Ipv4Addr>,
        proxy: Arc<Proxy>,
    ) -> Result<(Self, Zeroizing<String>)> {
        let listener = TcpListener::bind((host, 0))
            .await
            .context("无法监听 WSL2 NAT 接口的 TCP 转发端口")?;
        let mut nonce = Zeroizing::new([0; NONCE_LEN]);
        getrandom::fill(&mut nonce[..]).context("无法生成 WSL2 转发会话随机值")?;

        let port = listener.local_addr()?.port();
        let capacity = "native 65535 \n".len() + NONCE_LEN * 2 + hosts.len() * 16;
        let mut line = Zeroizing::new(String::with_capacity(capacity));
        write!(line, "native {port} ")?;
        for byte in nonce.iter() {
            write!(line, "{byte:02x}")?;
        }
        for address in &hosts {
            write!(line, " {address}")?;
        }
        line.push('\n');

        let authorization = Arc::new(RelayAuthorization {
            nonce,
            hosts,
            proxy,
        });
        let (shutdown, stopped) = oneshot::channel();
        let task = tokio::spawn(serve(listener, guest, authorization, stopped));
        Ok((
            Self {
                shutdown: Some(shutdown),
                task,
            },
            line,
        ))
    }

    pub(super) fn is_healthy(&self) -> Result<()> {
        ensure!(!self.task.is_finished(), "Windows 原生 TCP 转发已停止");
        Ok(())
    }

    pub(super) async fn stop(mut self) -> Result<()> {
        drop(self.shutdown.take());
        (&mut self.task)
            .await
            .context("Windows 原生 TCP 转发未正常退出")?
    }
}

impl Drop for NativeRelay {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve(
    listener: TcpListener,
    guest: Ipv4Addr,
    authorization: Arc<RelayAuthorization>,
    mut shutdown: oneshot::Receiver<()>,
) -> Result<()> {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                connections.shutdown().await;
                return Ok(());
            }
            accepted = listener.accept(), if connections.len() < MAX_CONNECTIONS => {
                let (stream, peer) = accepted.context("Windows 无法接收 WSL2 的 TCP 转发连接")?;
                if peer.ip() == IpAddr::V4(guest) {
                    let authorization = Arc::clone(&authorization);
                    connections.spawn(async move {
                        let _ = relay(stream, &authorization).await;
                    });
                }
            }
            _ = connections.join_next(), if !connections.is_empty() => {}
        }
    }
}

async fn relay(mut stream: TcpStream, authorization: &RelayAuthorization) -> Result<()> {
    stream.set_nodelay(true)?;
    let mut header = Zeroizing::new([0; HEADER_LEN]);
    timeout(IPC_TIMEOUT, stream.read_exact(&mut header[..])).await??;
    let difference = header[..NONCE_LEN]
        .iter()
        .zip(authorization.nonce.iter())
        .fold(0, |difference, (actual, expected)| {
            difference | (actual ^ expected)
        });
    ensure!(difference == 0, "WSL2 转发会话校验失败");
    let address = Ipv4Addr::new(
        header[NONCE_LEN],
        header[NONCE_LEN + 1],
        header[NONCE_LEN + 2],
        header[NONCE_LEN + 3],
    );
    let port = u16::from_be_bytes([header[HEADER_LEN - 2], header[HEADER_LEN - 1]]);
    drop(header);
    ensure!(
        port != 0 && authorization.hosts.contains(&address),
        "WSL2 转发目标未获本次会话授权"
    );

    let mut upstream = authorization
        .proxy
        .open_native_tunnel(address, port)
        .await?;
    timeout(IPC_TIMEOUT, stream.write_all(&[1])).await??;
    copy_bidirectional(&mut stream, &mut upstream).await?;
    Ok(())
}
