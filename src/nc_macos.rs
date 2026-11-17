use std::{
    ffi::{CStr, c_int, c_ulong, c_void},
    fs::{File, OpenOptions, TryLockError},
    io,
    net::{IpAddr, Ipv4Addr, UdpSocket},
    os::{
        fd::{FromRawFd, OwnedFd},
        unix::fs::OpenOptionsExt,
    },
    path::Path,
    process::Stdio,
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use tokio::{
    net::UnixStream,
    process::{Child, Command},
    time::{Instant, sleep, timeout},
};
use zeroize::Zeroize;

use crate::{
    nc::{gateway_ipv4, validate_routes},
    nc_policy::{Ipv4Cidr, NcPolicy},
    nc_vici::Vici,
};

const CHARON: &str = "/opt/homebrew/opt/strongswan/libexec/ipsec/charon";
const RUN_DIR: &str = "/private/var/run";
const COMMAND_TIMEOUT: Duration = Duration::from_secs(3);

pub(crate) struct Session {
    client: Vici<UnixStream>,
    policy: NcPolicy,
    daemon: Daemon,
    routes: InstalledRoutes,
    interface: Utun,
    _lock: File,
}

pub(crate) async fn start(mut policy: NcPolicy, gateway_host: &str) -> Result<Session> {
    // Root is required by the native kernel for utun, PF_KEY and routes. There
    // is no embedded password prompt or automatic privilege elevation.
    ensure!(
        unsafe { geteuid() } == 0,
        "macOS NC 需要管理员在终端授权启动命令行客户端；桌面版可继续使用网页转发"
    );
    ensure!(
        Path::new(CHARON).is_file(),
        "未找到 Apple Silicon Homebrew strongSwan，请先在 Mac 上安装 strongswan"
    );
    let lock = session_lock()?;
    ensure!(
        !Path::new("/private/var/run/charon.pid").try_exists()?,
        "系统已有 strongSwan 实例或 PID 记录，无法启动独立的 NC 实例"
    );

    let peer = gateway_ipv4(gateway_host).await?;
    validate_routes(&policy, &[peer])?;
    ensure!(
        !policy
            .routes
            .iter()
            .any(|route| route.prefix == 32 && route.network == policy.virtual_ip),
        "NC 授权路由与会话虚拟地址冲突，已停止配置"
    );
    let natt_port = system_esp_port().await?;
    ensure!(
        natt_port != policy.server_port,
        "系统 NAT-T 端口与 NC IKE 端口冲突，已停止配置"
    );
    // The original session used the gateway's nonstandard port on both sides
    // of the initial IKE exchange. Keep the existing macOS ESP socket port.
    check_udp_port(policy.server_port)?;
    check_udp_port(natt_port)?;
    let interface = Utun::open()?;
    interface.set_address(policy.virtual_ip).await?;
    let (mut daemon, stream) = Daemon::start(policy.server_port, natt_port).await?;
    let mut client = Vici::new(stream);

    let established = client.establish(&policy, peer).await;
    policy.psk.zeroize();
    let attached = match established {
        Ok(()) => InstalledRoutes::add(&interface.name, policy.virtual_ip, &policy.routes).await,
        Err(error) => Err(error),
    };

    let routes = match attached {
        Ok(routes) => routes,
        Err(error) => {
            // Gracefully stopping the disposable daemon also removes any partially
            // installed SAs and routes if VICI startup got interrupted.
            if let Err(cleanup) = daemon.stop().await {
                return Err(error).context(format!("退出 macOS NC 引擎失败：{cleanup:#}"));
            }
            return Err(error);
        }
    };

    Ok(Session {
        client,
        policy,
        daemon,
        routes,
        interface,
        _lock: lock,
    })
}

impl Session {
    pub(crate) async fn is_healthy(&mut self) -> Result<()> {
        ensure!(
            self.daemon.child.try_wait()?.is_none(),
            "macOS NC 引擎已退出"
        );
        self.client.is_healthy(&self.policy).await?;
        self.routes.verify(&self.interface.name).await
    }

    pub(crate) async fn stop(&mut self) -> Result<()> {
        let routes = self.routes.remove(&self.interface.name).await;
        let vici = timeout(Duration::from_secs(8), self.client.stop(&self.policy))
            .await
            .context("清理 macOS NC 会话超时")
            .and_then(|result| result);
        let daemon = self.daemon.stop().await;
        routes.and(daemon).and(vici)
    }
}

fn session_lock() -> Result<File> {
    const O_NOFOLLOW: c_int = 0x0100;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(O_NOFOLLOW)
        .open(Path::new(RUN_DIR).join("v5vpn-nc.lock"))
        .context("无法打开 macOS NC 会话锁")?;
    match lock.try_lock() {
        Ok(()) => Ok(lock),
        Err(TryLockError::WouldBlock) => bail!("另一个 V5VPN NC 会话正在使用 macOS 网络"),
        Err(TryLockError::Error(error)) => Err(error).context("无法锁定 macOS NC 会话"),
    }
}

async fn system_esp_port() -> Result<u16> {
    let mut command = Command::new("/usr/sbin/sysctl");
    command.args(["-n", "net.inet.ipsec.esp_port"]);
    let output = command_output(command, "无法读取系统 IPsec NAT-T 端口").await?;
    let port = output
        .trim()
        .parse::<u16>()
        .context("系统 IPsec NAT-T 端口无效")?;
    ensure!(port != 0, "系统未配置可保留的 NAT-T 端口");
    Ok(port)
}

fn check_udp_port(port: u16) -> Result<()> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, port))
        .context("macOS NC 所需的 UDP 端口无法绑定")?;
    drop(socket);
    Ok(())
}

struct Daemon {
    child: Child,
    _directory: tempfile::TempDir,
}

impl Daemon {
    async fn start(ike_port: u16, natt_port: u16) -> Result<(Self, UnixStream)> {
        let directory = tempfile::Builder::new()
            .prefix("v5vpn-nc-")
            .tempdir_in(RUN_DIR)
            .context("无法创建私有 NC 引擎目录")?;
        let socket = directory.path().join("vici");
        let config = directory.path().join("strongswan.conf");
        // Only runtime settings go into this root-owned temporary file.
        // Credentials and connection policy are delivered directly over VICI.
        std::fs::write(
            &config,
            format!(
                "charon {{\n  port = {ike_port}\n  port_nat_t = {natt_port}\n  \
                 load = openssl kdf nonce kernel-pfkey kernel-pfroute socket-default vici\n  \
                 install_virtual_ip = no\n  install_routes = no\n  plugins {{\n    \
                 socket-default {{\n      use_ipv6 = no\n    }}\n    \
                 vici {{\n      socket = unix://{}\n    }}\n  }}\n  \
                 syslog {{\n    daemon {{\n      default = -1\n    }}\n    \
                 auth {{\n      default = -1\n    }}\n  }}\n}}\n",
                socket.display(),
            ),
        )
        .context("无法准备 macOS NC 引擎配置")?;
        let child = Command::new(CHARON)
            .env_clear()
            .env("STRONGSWAN_CONF", config)
            .current_dir(directory.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("无法启动原生 strongSwan 引擎")?;
        let mut daemon = Self {
            child,
            _directory: directory,
        };
        let expires = Instant::now() + Duration::from_secs(8);
        while Instant::now() < expires {
            ensure!(
                daemon.child.try_wait()?.is_none(),
                "原生 strongSwan 无法启动，请检查端口、PF_KEY 支持和已安装的插件"
            );
            if let Ok(stream) = UnixStream::connect(&socket).await {
                return Ok((daemon, stream));
            }
            sleep(Duration::from_millis(80)).await;
        }
        if let Err(cleanup) = daemon.stop().await {
            bail!("macOS NC 引擎未就绪，退出失败：{cleanup:#}");
        }
        bail!("macOS NC 引擎未启动私有 VICI 服务")
    }

    fn signal_stop(&mut self) -> Result<()> {
        if self.child.try_wait()?.is_none()
            && let Some(pid) = self.child.id()
            && unsafe { kill(pid as c_int, 15) } != 0
        {
            return Err(io::Error::last_os_error()).context("无法停止私有 strongSwan 引擎");
        }
        Ok(())
    }

    async fn stop(&mut self) -> Result<()> {
        self.signal_stop()?;
        // Give charon a chance to remove its kernel policies before releasing
        // the utun. An indiscriminate kill/flush would risk other VPN traffic.
        timeout(Duration::from_secs(10), self.child.wait())
            .await
            .context("等待 strongSwan 清理路由和 SA 超时")??;
        Ok(())
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.signal_stop();
    }
}

struct Utun {
    _socket: OwnedFd,
    name: String,
}

impl Utun {
    fn open() -> Result<Self> {
        const AF_SYSTEM: c_int = 32;
        const SOCK_DGRAM: c_int = 2;
        const SYSPROTO_CONTROL: c_int = 2;
        const AF_SYS_CONTROL: u16 = 2;
        const UTUN_OPT_IFNAME: c_int = 2;
        const CTLIOCGINFO: c_ulong = 0xc064_4e03;
        const F_SETFD: c_int = 2;
        const FD_CLOEXEC: c_int = 1;
        const UTUN_CONTROL: &[u8] = b"com.apple.net.utun_control";

        // Darwin sys/kern_control.h and net/if_utun.h. Ownership of the
        // unique control descriptor also owns the utun interface.
        let raw = unsafe { socket(AF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL) };
        syscall(raw, "无法创建 macOS NC 的 utun 控制套接字")?;
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        syscall(
            unsafe { fcntl(raw, F_SETFD, FD_CLOEXEC) },
            "无法设置 utun 套接字句柄属性",
        )?;
        let mut info = CtlInfo {
            id: 0,
            name: [0; 96],
        };
        info.name[..UTUN_CONTROL.len()].copy_from_slice(UTUN_CONTROL);
        syscall(
            unsafe { ioctl(raw, CTLIOCGINFO, &mut info as *mut CtlInfo) },
            "macOS utun 控制服务不可用",
        )?;
        let addr = SockAddrCtl {
            len: size_of::<SockAddrCtl>() as u8,
            family: AF_SYSTEM as u8,
            sysaddr: AF_SYS_CONTROL,
            id: info.id,
            unit: 0,
            reserved: [0; 5],
        };
        syscall(
            unsafe {
                connect(
                    raw,
                    (&addr as *const SockAddrCtl).cast(),
                    u32::from(addr.len),
                )
            },
            "macOS 未允许创建 NC 隧道接口",
        )?;
        let mut interface_name = [0u8; 16];
        let mut size = interface_name.len() as u32;
        syscall(
            unsafe {
                getsockopt(
                    raw,
                    SYSPROTO_CONTROL,
                    UTUN_OPT_IFNAME,
                    interface_name.as_mut_ptr().cast(),
                    &mut size,
                )
            },
            "无法读取 NC 隧道接口名",
        )?;
        let name = CStr::from_bytes_until_nul(&interface_name)?
            .to_str()?
            .to_owned();
        ensure!(
            name.strip_prefix("utun").is_some_and(|unit| {
                !unit.is_empty() && unit.bytes().all(|byte| byte.is_ascii_digit())
            }),
            "macOS 返回的 NC 接口名无效"
        );
        Ok(Self { _socket: fd, name })
    }

    async fn set_address(&self, address: Ipv4Addr) -> Result<()> {
        let mut command = Command::new("/sbin/ifconfig");
        let address = address.to_string();
        // Use a host netmask so configuring the portal's address cannot
        // implicitly authorize its whole attachment subnet.
        command.args([
            &self.name,
            "inet",
            &address,
            &address,
            "netmask",
            "255.255.255.255",
            "up",
        ]);
        command_output(command, "无法设置 NC 会话的虚拟 IPv4 地址").await?;
        Ok(())
    }
}

struct InstalledRoutes {
    virtual_ip: Ipv4Addr,
    owned: Vec<Ipv4Cidr>,
}

impl InstalledRoutes {
    async fn add(interface: &str, virtual_ip: Ipv4Addr, routes: &[Ipv4Cidr]) -> Result<Self> {
        let mut staged = Self {
            virtual_ip,
            owned: Vec::with_capacity(routes.len()),
        };
        let source = virtual_ip.to_string();
        let result = async {
            for route in routes {
                ensure!(route.prefix > 0, "NC 授权包含默认路由，已停止配置");
                let mut command = Command::new("/sbin/route");
                command.args([
                    "-n",
                    "add",
                    "-inet",
                    "-net",
                    &route.to_string(),
                    "-interface",
                    interface,
                    "-ifa",
                    &source,
                ]);
                command_output(
                    command,
                    "无法添加授权 NC 路由，可能已有其他程序占用相同网段",
                )
                .await?;
                staged.owned.push(*route);
            }
            staged.verify(interface).await
        }
        .await;
        if let Err(error) = result {
            if let Err(cleanup) = staged.remove(interface).await {
                return Err(error).context(format!("还原部分 NC 路由失败：{cleanup:#}"));
            }
            return Err(error);
        }
        Ok(staged)
    }

    async fn verify(&self, interface: &str) -> Result<()> {
        for route in &self.owned {
            ensure!(
                Self::interface_for(route).await? == interface,
                "IPsec 协商完成，但 macOS 未将全部授权网段指向本会话，可能存在路由冲突"
            );
            self.verify_source(route)?;
        }
        Ok(())
    }

    fn verify_source(&self, route: &Ipv4Cidr) -> Result<()> {
        let first = u32::from(route.network) + u32::from(route.prefix < 31);
        let representative = Ipv4Addr::from(first + u32::from(first == u32::from(self.virtual_ip)));
        // UDP connect selects the source locally without sending a datagram.
        let probe =
            UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).context("无法准备 NC 路由源地址检查")?;
        probe
            .connect((representative, 9))
            .context("macOS 无法为授权网段选择 IPv4 出口")?;
        ensure!(
            probe.local_addr()?.ip() == IpAddr::V4(self.virtual_ip),
            "macOS 没有为授权网段选用网关分配的 NC 虚拟地址"
        );
        Ok(())
    }

    async fn remove(&mut self, interface: &str) -> Result<()> {
        let mut result = Ok(());
        while let Some(route) = self.owned.pop() {
            let current = Self::interface_for(&route).await;
            // Exact-prefix deletion is scoped to the interface we created.
            // Dropping the utun descriptor also detaches its interface routes
            // if lookup or deletion cannot be confirmed.
            match current {
                Ok(current) if current == interface => {
                    let mut command = Command::new("/sbin/route");
                    command.args([
                        "-n",
                        "delete",
                        "-inet",
                        "-net",
                        &route.to_string(),
                        "-interface",
                        interface,
                    ]);
                    let removed = command_output(command, "无法删除本会话的授权 NC 路由")
                        .await
                        .map(|_| ());
                    result = result.and(removed);
                }
                Ok(_) => {}
                Err(error) => result = result.and(Err(error)),
            }
        }
        result
    }

    async fn interface_for(route: &Ipv4Cidr) -> Result<String> {
        let mut command = Command::new("/sbin/route");
        command.args(["-n", "get", "-inet", "-net", &route.to_string()]);
        let output = command_output(command, "无法读取 NC 路由").await?;
        output
            .lines()
            .find_map(|line| line.trim_start().strip_prefix("interface:").map(str::trim))
            .map(str::to_owned)
            .context("macOS 路由查询未返回接口")
    }
}

async fn command_output(mut command: Command, context: &'static str) -> Result<String> {
    command
        .env_clear()
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let output = timeout(COMMAND_TIMEOUT, command.output())
        .await
        .context(context)??;
    ensure!(output.status.success(), "{context}");
    String::from_utf8(output.stdout).context(context)
}

fn syscall(value: c_int, message: &'static str) -> Result<()> {
    if value < 0 {
        Err(io::Error::last_os_error()).context(message)
    } else {
        Ok(())
    }
}

#[repr(C)]
struct CtlInfo {
    id: u32,
    name: [u8; 96],
}

#[repr(C)]
struct SockAddrCtl {
    len: u8,
    family: u8,
    sysaddr: u16,
    id: u32,
    unit: u32,
    reserved: [u32; 5],
}

const _: () = assert!(size_of::<CtlInfo>() == 100 && size_of::<SockAddrCtl>() == 32);

unsafe extern "C" {
    fn geteuid() -> u32;
    fn socket(domain: c_int, kind: c_int, protocol: c_int) -> c_int;
    fn fcntl(fd: c_int, command: c_int, ...) -> c_int;
    fn ioctl(fd: c_int, request: c_ulong, ...) -> c_int;
    fn connect(fd: c_int, addr: *const c_void, len: u32) -> c_int;
    fn getsockopt(fd: c_int, level: c_int, name: c_int, value: *mut c_void, len: *mut u32)
    -> c_int;
    fn kill(pid: c_int, signal: c_int) -> c_int;
}
