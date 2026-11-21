use std::{
    fs,
    net::Ipv4Addr,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    process::{Child, Command},
    signal::unix::{SignalKind, signal},
    time::timeout,
};
use zeroize::Zeroizing;

use super::{gateway_ipv4, platform, validate_routes};
use crate::nc_policy::{IkeId, Ipv4Cidr, NcPolicy};

const MAX_FRAME: usize = 64 * 1024;
const AUTH_TIMEOUT: Duration = Duration::from_secs(180);
const OP_TIMEOUT: Duration = Duration::from_secs(120);
const AUTH_SCRIPT: &str = r#"on run argv
    set helperPath to item 1 of argv
    set socketPath to item 2 of argv
    set ownerUid to item 3 of argv
    set ownerPid to item 4 of argv
    set commandText to "exec " & quoted form of helperPath & " --socket " & quoted form of socketPath & " --uid " & quoted form of ownerUid & " --parent-pid " & quoted form of ownerPid
    do shell script commandText with administrator privileges with prompt "V5VPN 需要管理员授权来建立 NC/IPsec 隧道。断开连接后会自动清理网络配置。"
end run"#;

#[derive(Serialize, Deserialize)]
struct WirePolicy {
    gateway: Ipv4Addr,
    server_id: Ipv4Addr,
    client_id: Zeroizing<Vec<u8>>,
    server_port: u16,
    virtual_ip: Ipv4Addr,
    routes: Vec<(Ipv4Addr, u8)>,
    psk: Zeroizing<Vec<u8>>,
    ike_lifetime: u32,
    esp_lifetime: u32,
    ike_proposal: String,
    esp_proposal: String,
}

impl WirePolicy {
    fn new(policy: NcPolicy, gateway: Ipv4Addr) -> Result<Self> {
        let IkeId::Ipv4(server_id) = policy.server_id else {
            bail!("NC 服务器身份类型无效")
        };
        let IkeId::KeyId(client_id) = policy.client_id else {
            bail!("NC 客户端身份类型无效")
        };
        Ok(Self {
            gateway,
            server_id,
            client_id,
            server_port: policy.server_port,
            virtual_ip: policy.virtual_ip,
            routes: policy
                .routes
                .iter()
                .map(|route| (route.network, route.prefix))
                .collect(),
            psk: policy.psk,
            ike_lifetime: policy.ike_lifetime,
            esp_lifetime: policy.esp_lifetime,
            ike_proposal: policy.ike_proposal.into(),
            esp_proposal: policy.esp_proposal.into(),
        })
    }

    fn into_policy(self) -> Result<(NcPolicy, Ipv4Addr)> {
        let unicast = |ip: Ipv4Addr| {
            !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast() && !ip.is_broadcast()
        };
        ensure!(
            unicast(self.gateway) && unicast(self.server_id) && unicast(self.virtual_ip),
            "NC 辅助进程收到无效地址"
        );
        ensure!(
            self.server_port != 0 && self.ike_lifetime != 0 && self.esp_lifetime != 0,
            "NC 辅助进程收到无效协商参数"
        );
        ensure!(
            (1..=4096).contains(&self.psk.len()) && (1..=4096).contains(&self.client_id.len()),
            "NC 会话凭据长度无效"
        );
        ensure!(
            self.ike_proposal == "aes128-sha1-modp1024" && self.esp_proposal == "aes128-sha1",
            "NC 协商提案不受支持"
        );
        ensure!(
            (1..=512).contains(&self.routes.len()),
            "NC 授权路由数量无效"
        );
        let routes = self
            .routes
            .into_iter()
            .map(|(network, prefix)| {
                ensure!((1..=32).contains(&prefix), "NC 授权路由前缀无效");
                ensure!(
                    u32::from(network) & (u32::MAX << (32 - prefix)) == u32::from(network),
                    "NC 授权路由不是规范网段"
                );
                ensure!(
                    !network.is_loopback() && !network.is_multicast(),
                    "NC 授权路由包含保留地址"
                );
                Ok(Ipv4Cidr { network, prefix })
            })
            .collect::<Result<Vec<_>>>()?;
        let policy = NcPolicy {
            server_id: IkeId::Ipv4(self.server_id),
            client_id: IkeId::KeyId(self.client_id),
            server_port: self.server_port,
            virtual_ip: self.virtual_ip,
            routes,
            psk: self.psk,
            ike_lifetime: self.ike_lifetime,
            esp_lifetime: self.esp_lifetime,
            ike_proposal: "aes128-sha1-modp1024",
            esp_proposal: "aes128-sha1",
        };
        validate_routes(
            &policy,
            &[
                self.gateway,
                Ipv4Addr::LOCALHOST,
                Ipv4Addr::UNSPECIFIED,
                Ipv4Addr::BROADCAST,
            ],
        )?;
        Ok((policy, self.gateway))
    }
}

#[derive(Serialize, Deserialize)]
enum Request {
    Start(WirePolicy),
    Check,
    Stop,
}
#[derive(Serialize, Deserialize)]
enum Response {
    Ready,
    Healthy,
    Stopped,
    Failed(String),
}

async fn send<T: Serialize>(stream: &mut UnixStream, value: &T) -> Result<()> {
    let bytes = Zeroizing::new(serde_json::to_vec(value).context("无法编码 NC 辅助协议")?);
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_FRAME,
        "NC 辅助协议消息过长"
    );
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(&bytes).await?;
    stream.flush().await?;
    Ok(())
}

async fn receive<T: DeserializeOwned>(stream: &mut UnixStream) -> Result<T> {
    let length = stream.read_u32().await? as usize;
    ensure!((1..=MAX_FRAME).contains(&length), "NC 辅助协议消息长度无效");
    let mut bytes = Zeroizing::new(vec![0; length]);
    stream.read_exact(&mut bytes).await?;
    serde_json::from_slice(&bytes).map_err(|_| anyhow::anyhow!("NC 辅助协议内容无效"))
}

fn peer_uid(stream: &UnixStream) -> Result<u32> {
    let mut uid = 0;
    let mut gid = 0;
    ensure!(
        unsafe { getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } == 0,
        "无法核对 NC 控制连接身份"
    );
    Ok(uid)
}

fn peer_pid(stream: &UnixStream) -> Result<u32> {
    let mut pid: i32 = 0;
    let mut size = size_of::<i32>() as u32;
    // SOL_LOCAL / LOCAL_PEERPID from the macOS SDK's sys/un.h.
    let result = unsafe {
        getsockopt(
            stream.as_raw_fd(),
            0,
            2,
            std::ptr::from_mut(&mut pid).cast(),
            &mut size,
        )
    };
    ensure!(
        result == 0 && size as usize == size_of::<i32>() && pid > 0,
        "无法核对 NC 控制连接进程"
    );
    Ok(pid as u32)
}

fn verify_peer(stream: &UnixStream, owner: u32, owner_pid: u32) -> Result<()> {
    ensure!(
        peer_uid(stream)? == owner && peer_pid(stream)? == owner_pid,
        "NC 控制连接不属于授权用户进程"
    );
    Ok(())
}

struct AuthorizationLaunch(Option<Child>);
impl Drop for AuthorizationLaunch {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.start_kill();
        }
    }
}

pub(crate) enum Session {
    Local(Box<platform::Session>),
    Remote(Box<RemoteSession>),
}

pub(crate) struct RemoteSession {
    // Taking the stream for each operation makes cancellation close the channel.
    stream: Option<UnixStream>,
    launcher: Child,
    _directory: tempfile::TempDir,
}

pub(crate) async fn start(policy: NcPolicy, gateway_host: &str) -> Result<Session> {
    if unsafe { geteuid() } == 0 {
        return platform::start(policy, gateway_host)
            .await
            .map(|session| Session::Local(Box::new(session)));
    }
    ensure!(
        Path::new("/opt/homebrew/opt/strongswan/libexec/ipsec/charon").is_file(),
        "NC 运行组件尚未安装，请先安装 strongSwan"
    );
    let helper = std::env::current_exe()?.with_file_name("v5vpn-nc-helper");
    ensure!(
        helper.is_file(),
        "缺少 NC 管理员辅助程序，请使用完整的 macOS 应用包"
    );
    let gateway = gateway_ipv4(gateway_host).await?;
    let request = Request::Start(WirePolicy::new(policy, gateway)?);
    let directory = tempfile::Builder::new().prefix("v5vpn-ui-").tempdir()?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
    let socket = directory.path().join("nc.sock");
    let listener = UnixListener::bind(&socket).context("无法创建 NC 控制通道")?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600))?;
    let child = Command::new("/usr/bin/osascript")
        .arg("-e")
        .arg(AUTH_SCRIPT)
        .arg(&helper)
        .arg(&socket)
        .arg(unsafe { geteuid() }.to_string())
        .arg(std::process::id().to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("无法请求 macOS 管理员授权")?;
    let mut launch = AuthorizationLaunch(Some(child));
    let child = launch.0.as_mut().expect("authorization child");
    let mut stream = timeout(AUTH_TIMEOUT, async {
        tokio::select! {
            result = listener.accept() => {
                let (stream, _) = result?;
                ensure!(peer_uid(&stream)? == 0, "NC 辅助程序没有管理员身份");
                Ok(stream)
            }
            status = child.wait() => {
                status?;
                let mut message = String::new();
                if let Some(stderr) = child.stderr.take() {
                    stderr.take(8192).read_to_string(&mut message).await?;
                }
                if message.contains("(-128)") { bail!("已取消管理员授权，NC 隧道未建立"); }
                bail!("NC 管理员辅助程序未能启动：{}", message.trim());
            }
        }
    })
    .await
    .context("等待管理员授权超时")??;
    let mut remote = RemoteSession {
        stream: None,
        launcher: launch.0.take().unwrap(),
        _directory: directory,
    };
    let ready = timeout(OP_TIMEOUT, async {
        send(&mut stream, &request).await?;
        match receive(&mut stream).await? {
            Response::Ready => Ok(()),
            Response::Failed(error) => bail!("{error}"),
            _ => bail!("NC 辅助程序启动响应无效"),
        }
    })
    .await
    .context("等待 NC 隧道建立超时")?;
    ready?;
    remote.stream = Some(stream);
    Ok(Session::Remote(Box::new(remote)))
}

impl Session {
    pub(crate) async fn is_healthy(&mut self) -> Result<()> {
        match self {
            Self::Local(session) => session.is_healthy().await,
            Self::Remote(session) => {
                let mut stream = session.stream.take().context("NC 管理通道已关闭")?;
                timeout(Duration::from_secs(15), async {
                    send(&mut stream, &Request::Check).await?;
                    match receive(&mut stream).await? {
                        Response::Healthy => Ok(()),
                        Response::Failed(error) => bail!("{error}"),
                        _ => bail!("NC 健康检查响应无效"),
                    }
                })
                .await
                .context("NC 辅助进程健康检查超时")??;
                session.stream = Some(stream);
                Ok(())
            }
        }
    }

    pub(crate) async fn stop(&mut self) -> Result<()> {
        match self {
            Self::Local(session) => session.stop().await,
            Self::Remote(session) => {
                let control = if let Some(mut stream) = session.stream.take() {
                    timeout(Duration::from_secs(25), async {
                        send(&mut stream, &Request::Stop).await?;
                        match receive(&mut stream).await? {
                            Response::Stopped => Ok(()),
                            Response::Failed(error) => bail!("{error}"),
                            _ => bail!("NC 辅助程序退出响应无效"),
                        }
                    })
                    .await
                    .context("等待 NC 网络配置恢复超时")
                    .and_then(|result| result)
                } else {
                    Ok(())
                };
                let exited = timeout(Duration::from_secs(30), session.launcher.wait())
                    .await
                    .context("等待 NC 管理员辅助程序退出超时")?;
                ensure!(exited?.success(), "NC 管理员辅助程序异常退出");
                control
            }
        }
    }
}

/// Entry point for the bundled helper. Its only root operations are NC lifecycle operations.
pub async fn run_helper(socket: PathBuf, owner: u32, owner_pid: u32) -> Result<()> {
    ensure!(
        unsafe { geteuid() } == 0 && owner != 0,
        "NC 辅助进程需要有效的管理员授权"
    );
    let parent = socket.parent().context("NC 控制通道路径无效")?;
    let metadata = fs::symlink_metadata(parent)?;
    ensure!(
        metadata.is_dir() && metadata.uid() == owner && metadata.permissions().mode() & 0o077 == 0,
        "NC 控制目录身份或权限无效"
    );
    let mut stream = timeout(Duration::from_secs(10), UnixStream::connect(&socket)).await??;
    verify_peer(&stream, owner, owner_pid)?;
    let mut terminate = signal(SignalKind::terminate())?;
    let mut hangup = signal(SignalKind::hangup())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    let request = timeout(Duration::from_secs(10), receive(&mut stream)).await??;
    let Request::Start(wire) = request else {
        bail!("NC 辅助程序缺少启动策略")
    };
    let (policy, gateway) = wire.into_policy()?;
    let mut session = match platform::start(policy, &gateway.to_string()).await {
        Ok(session) => session,
        Err(error) => {
            send(&mut stream, &Response::Failed(format!("{error:#}"))).await?;
            return Ok(());
        }
    };
    let operation = async {
        send(&mut stream, &Response::Ready).await?;
        loop {
            let request = tokio::select! {
                value = receive::<Request>(&mut stream) => match value {
                    Ok(value) => value,
                    Err(_) => return Ok(false),
                },
                _ = terminate.recv() => return Ok(false),
                _ = hangup.recv() => return Ok(false),
                _ = interrupt.recv() => return Ok(false),
            };
            match request {
                Request::Stop => return Ok(true),
                Request::Check => match session.is_healthy().await {
                    Ok(()) => send(&mut stream, &Response::Healthy).await?,
                    Err(error) => {
                        send(&mut stream, &Response::Failed(format!("{error:#}"))).await?;
                        return Ok(false);
                    }
                },
                Request::Start(_) => bail!("NC 辅助进程不允许重复启动"),
            }
        }
    }
    .await;
    let cleanup = session.stop().await;
    if matches!(operation, Ok(true)) {
        let response = match &cleanup {
            Ok(()) => Response::Stopped,
            Err(error) => Response::Failed(format!("清理 NC 网络配置失败：{error:#}")),
        };
        let _ = send(&mut stream, &response).await;
    }
    cleanup?;
    operation.map(|_| ())
}

unsafe extern "C" {
    fn geteuid() -> u32;
    fn getpeereid(socket: i32, uid: *mut u32, gid: *mut u32) -> i32;
    fn getsockopt(
        socket: i32,
        level: i32,
        name: i32,
        value: *mut std::ffi::c_void,
        length: *mut u32,
    ) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> WirePolicy {
        WirePolicy {
            gateway: Ipv4Addr::new(192, 0, 2, 1),
            server_id: Ipv4Addr::new(192, 0, 2, 1),
            client_id: Zeroizing::new(b"fixture".to_vec()),
            server_port: 500,
            virtual_ip: Ipv4Addr::new(10, 1, 0, 2),
            routes: vec![(Ipv4Addr::new(10, 2, 0, 0), 16)],
            psk: Zeroizing::new(vec![1; 16]),
            ike_lifetime: 3600,
            esp_lifetime: 1800,
            ike_proposal: "aes128-sha1-modp1024".into(),
            esp_proposal: "aes128-sha1".into(),
        }
    }

    #[test]
    fn accepts_scoped_policy_and_rejects_route_or_proposal_expansion() {
        assert!(policy().into_policy().is_ok());
        for routes in [
            vec![(Ipv4Addr::UNSPECIFIED, 0)],
            vec![(Ipv4Addr::new(192, 0, 2, 0), 24)],
            vec![(Ipv4Addr::new(10, 2, 0, 1), 16)],
            vec![(Ipv4Addr::LOCALHOST, 32)],
        ] {
            let mut invalid = policy();
            invalid.routes = routes;
            assert!(invalid.into_policy().is_err());
        }
        let mut invalid = policy();
        invalid.ike_proposal = "arbitrary-proposal".into();
        assert!(invalid.into_policy().is_err());
    }

    #[tokio::test]
    async fn bounds_frames_and_authenticates_local_peer_uid() -> Result<()> {
        let (mut left, mut right) = UnixStream::pair()?;
        assert_eq!(peer_uid(&left)?, unsafe { geteuid() });
        assert_eq!(peer_pid(&left)?, std::process::id());
        verify_peer(&left, unsafe { geteuid() }, std::process::id())?;
        assert!(verify_peer(&left, unsafe { geteuid() }, std::process::id() + 1).is_err());
        left.write_u32(MAX_FRAME as u32 + 1).await?;
        assert!(receive::<Request>(&mut right).await.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn policy_round_trip_and_disconnect_do_not_need_files() -> Result<()> {
        let (mut left, mut right) = UnixStream::pair()?;
        send(&mut left, &Request::Start(policy())).await?;
        let Request::Start(wire) = receive(&mut right).await? else {
            bail!("wrong request")
        };
        assert!(wire.into_policy().is_ok());
        drop(left);
        assert!(receive::<Request>(&mut right).await.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn canceled_health_check_closes_helper_channel() -> Result<()> {
        let (client, mut helper) = UnixStream::pair()?;
        let launcher = Command::new("/usr/bin/true").spawn()?;
        let mut session = Session::Remote(Box::new(RemoteSession {
            stream: Some(client),
            launcher,
            _directory: tempfile::tempdir()?,
        }));
        assert!(
            timeout(Duration::from_millis(25), session.is_healthy())
                .await
                .is_err()
        );
        assert!(matches!(
            receive::<Request>(&mut helper).await?,
            Request::Check
        ));
        assert!(receive::<Request>(&mut helper).await.is_err());
        let Session::Remote(remote) = &session else {
            unreachable!()
        };
        assert!(remote.stream.is_none());
        session.stop().await?;
        Ok(())
    }
}
