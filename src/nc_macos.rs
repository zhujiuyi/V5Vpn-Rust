use std::{
    ffi::{CStr, c_int, c_ulong, c_void},
    fs::{File, OpenOptions, TryLockError},
    io,
    net::{IpAddr, Ipv4Addr, UdpSocket},
    os::{
        fd::{FromRawFd, OwnedFd},
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
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

const REQUIRED_RUNTIME_FILES: &[&str] = &[
    "bin/charon",
    "lib/libstrongswan.0.dylib",
    "lib/libcharon.0.dylib",
    "lib/libcrypto.4.dylib",
    "openssl.cnf",
    "lib/plugins/libstrongswan-openssl.so",
    "lib/plugins/libstrongswan-kdf.so",
    "lib/plugins/libstrongswan-nonce.so",
    "lib/plugins/libstrongswan-kernel-pfkey.so",
    "lib/plugins/libstrongswan-kernel-pfroute.so",
    "lib/plugins/libstrongswan-socket-default.so",
    "lib/plugins/libstrongswan-vici.so",
    "lib/ossl-modules/legacy.dylib",
];

pub(super) struct Runtime {
    pub(super) executable: PathBuf,
    root: Option<PathBuf>,
}

pub(super) fn runtime() -> Result<Runtime> {
    runtime_for(&std::env::current_exe()?, Path::new(CHARON))
}

fn runtime_for(executable: &Path, fallback: &Path) -> Result<Runtime> {
    let contents = executable
        .parent()
        .and_then(Path::parent)
        .context("无法定位 NC 运行组件")?;
    let root = contents.join("Resources/NC");
    if root.exists() {
        for relative in REQUIRED_RUNTIME_FILES {
            ensure!(
                root.join(relative).is_file(),
                "应用包中的 NC 运行组件不完整，请重新安装"
            );
        }
        return Ok(Runtime {
            executable: root.join("bin/charon"),
            root: Some(root),
        });
    }
    ensure!(
        fallback.is_file(),
        "缺少 NC 运行组件，请使用完整的 macOS 安装包；源码运行可安装 Homebrew strongSwan"
    );
    Ok(Runtime {
        executable: fallback.to_path_buf(),
        root: None,
    })
}

fn known_engine(path: &Path) -> bool {
    path.ends_with("Contents/Resources/NC/bin/charon")
        || std::fs::canonicalize(path)
            .ok()
            .zip(std::fs::canonicalize(CHARON).ok())
            .is_some_and(|(actual, expected)| actual == expected)
}

pub(crate) async fn start(mut policy: NcPolicy, gateway_host: &str) -> Result<Session> {
    // The desktop starts this backend inside the per-session authorized helper.
    ensure!(unsafe { geteuid() } == 0, "macOS NC 网络组件需要管理员授权");
    runtime()?;
    let lock = session_lock()?;
    recover_stale_daemon().await?;
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
    let original_natt_port = system_esp_port().await?;
    let natt_port = select_natt_port(original_natt_port);
    ensure!(
        natt_port != policy.server_port,
        "系统 NAT-T 端口与 NC IKE 端口冲突，已停止配置"
    );
    // Keep an existing macOS ESP port. When it is unset, kernel-pfkey will
    // initialize it to the selected NAT-T port as the private daemon starts.
    check_udp_port(policy.server_port)?;
    check_udp_port(natt_port)?;
    let interface = Utun::open()?;
    interface.set_address(policy.virtual_ip).await?;
    let (mut daemon, stream) =
        Daemon::start(policy.server_port, natt_port, original_natt_port).await?;
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

async fn recover_stale_daemon() -> Result<()> {
    let pid_file = Path::new(RUN_DIR).join("charon.pid");
    let metadata = match std::fs::symlink_metadata(&pid_file) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    ensure!(
        metadata.is_file() && metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
        "现有 strongSwan PID 文件身份无效"
    );
    let pid_text = std::fs::read_to_string(&pid_file)?;
    let pid: c_int = pid_text
        .trim()
        .parse()
        .context("现有 strongSwan PID 无效")?;
    ensure!(pid > 1, "现有 strongSwan PID 无效");

    let mut process = Command::new("/bin/ps");
    process.args(["-p", &pid.to_string(), "-o", "ppid=", "-o", "comm="]);
    let identity = command_output(process, "无法核对现有 strongSwan 进程").await?;
    let fields: Vec<_> = identity.split_whitespace().collect();
    ensure!(
        fields.len() == 2 && fields[0] == "1" && known_engine(Path::new(fields[1])),
        "已有活动的 IPsec 引擎，请先断开原 VPN 会话"
    );

    let mut sockets = Command::new("/usr/sbin/lsof");
    sockets.args(["-nP", "-a", "-p", &pid.to_string(), "-U", "-Fn"]);
    let sockets = command_output(sockets, "无法核对孤立 NC 引擎的控制通道").await?;
    let private_directory = sockets
        .lines()
        .filter_map(|line| line.strip_prefix('n'))
        .map(Path::new)
        .filter(|socket| socket.file_name().is_some_and(|name| name == "vici"))
        .filter_map(|socket| socket.parent())
        .find(|directory| {
            directory.parent() == Some(Path::new(RUN_DIR))
                && directory
                    .file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with("v5vpn-nc-"))
                && std::fs::symlink_metadata(directory)
                    .is_ok_and(|data| data.is_dir() && data.uid() == 0 && data.mode() & 0o022 == 0)
                && std::fs::symlink_metadata(directory.join("strongswan.conf"))
                    .is_ok_and(|data| data.is_file() && data.uid() == 0 && data.mode() & 0o022 == 0)
        })
        .context("现有 IPsec 引擎不属于可回收的 V5VPN 会话")?
        .to_path_buf();
    ensure!(
        unsafe { kill(pid, 15) } == 0,
        "无法结束孤立的 V5VPN NC 引擎"
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    while unsafe { kill(pid, 0) } == 0 {
        ensure!(Instant::now() < deadline, "等待孤立 NC 引擎退出超时");
        sleep(Duration::from_millis(80)).await;
    }
    if std::fs::read_to_string(&pid_file).is_ok_and(|value| value.trim() == pid.to_string()) {
        std::fs::remove_file(&pid_file)?;
    }
    std::fs::remove_dir_all(private_directory).context("无法清理孤立 NC 引擎目录")?;
    Ok(())
}

async fn system_esp_port() -> Result<u16> {
    let mut command = Command::new("/usr/sbin/sysctl");
    command.args(["-n", "net.inet.ipsec.esp_port"]);
    let output = command_output(command, "无法读取系统 IPsec NAT-T 端口").await?;
    let port = output
        .trim()
        .parse::<u16>()
        .context("系统 IPsec NAT-T 端口无效")?;
    Ok(port)
}

fn select_natt_port(current: u16) -> u16 {
    if current == 0 { 4500 } else { current }
}

fn read_esp_port() -> Result<u16> {
    let mut value: c_int = 0;
    let mut size = size_of::<c_int>();
    let status = unsafe {
        sysctlbyname(
            c"net.inet.ipsec.esp_port".as_ptr(),
            std::ptr::from_mut(&mut value).cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if status != 0 {
        return Err(io::Error::last_os_error()).context("无法读取系统 IPsec NAT-T 端口");
    }
    ensure!(size == size_of::<c_int>(), "系统 IPsec NAT-T 端口长度无效");
    u16::try_from(value).context("系统 IPsec NAT-T 端口无效")
}

fn write_esp_port(port: u16) -> Result<()> {
    let mut value = c_int::from(port);
    let status = unsafe {
        sysctlbyname(
            c"net.inet.ipsec.esp_port".as_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::from_mut(&mut value).cast(),
            size_of::<c_int>(),
        )
    };
    if status != 0 {
        return Err(io::Error::last_os_error()).context("无法恢复系统 IPsec NAT-T 端口");
    }
    Ok(())
}

fn restore_natt_port(
    selected: u16,
    original: u16,
    read: impl FnOnce() -> Result<u16>,
    write: impl FnOnce(u16) -> Result<()>,
) -> Result<()> {
    if selected == original {
        return Ok(());
    }
    let current = read()?;
    if current == original {
        return Ok(());
    }
    ensure!(
        current == selected,
        "系统 IPsec NAT-T 端口已被其他进程更改，保留当前配置"
    );
    write(original)
}

#[cfg(test)]
mod natt_tests {
    use super::*;

    #[test]
    fn unset_port_selects_standard_natt_and_preserves_existing_port() {
        assert_eq!(select_natt_port(0), 4500);
        assert_eq!(select_natt_port(5500), 5500);
    }

    #[test]
    fn owned_natt_change_is_restored() {
        let written = std::cell::Cell::new(None);
        restore_natt_port(
            4500,
            0,
            || Ok(4500),
            |port| {
                written.set(Some(port));
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(written.get(), Some(0));
    }

    #[test]
    fn unchanged_and_already_restored_ports_are_not_written() {
        restore_natt_port(5500, 5500, || panic!("无需读取"), |_| panic!("无需写入")).unwrap();
        restore_natt_port(4500, 0, || Ok(0), |_| panic!("无需重复恢复")).unwrap();
    }

    #[test]
    fn another_process_port_change_is_preserved() {
        let result = restore_natt_port(4500, 0, || Ok(5500), |_| panic!("不可覆盖其他配置"));
        assert!(result.is_err());
    }

    #[test]
    fn bundled_runtime_is_preferred_and_incomplete_bundle_is_rejected() -> Result<()> {
        let folder = tempfile::tempdir()?;
        let contents = folder.path().join("V5VPN Test.app/Contents");
        let executable = contents.join("MacOS/v5vpn-nc-helper");
        let fallback = folder.path().join("homebrew-charon");
        std::fs::write(&fallback, [])?;
        let plain = runtime_for(&executable, &fallback)?;
        assert_eq!(plain.executable, fallback);
        assert!(plain.root.is_none());

        let root = contents.join("Resources/NC");
        std::fs::create_dir_all(&root)?;
        assert!(runtime_for(&executable, &fallback).is_err());
        for file in REQUIRED_RUNTIME_FILES {
            let path = root.join(file);
            std::fs::create_dir_all(path.parent().unwrap())?;
            std::fs::write(path, [])?;
        }
        let bundled = runtime_for(&executable, &fallback)?;
        assert_eq!(bundled.executable, root.join("bin/charon"));
        assert_eq!(bundled.root, Some(root));
        Ok(())
    }

    #[tokio::test]
    #[ignore = "需要管理员权限；检查本机 NC 引擎，不连接网关或提交口令"]
    async fn private_daemon_initializes_and_restores_natt_port() -> Result<()> {
        ensure!(unsafe { geteuid() } == 0, "此检查需要管理员权限");
        let _lock = session_lock()?;
        ensure!(
            !Path::new("/private/var/run/charon.pid").try_exists()?,
            "已有 strongSwan 实例，跳过引擎自检"
        );
        let original = read_esp_port()?;
        let selected = select_natt_port(original);
        check_udp_port(selected)?;
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
        let ike_port = socket.local_addr()?.port();
        drop(socket);
        let (mut daemon, stream) = Daemon::start(ike_port, selected, original).await?;
        drop(stream);
        let active_port = read_esp_port();
        daemon.stop().await?;
        ensure!(active_port? == selected, "引擎未初始化所选的 NAT-T 端口");
        ensure!(read_esp_port()? == original, "引擎退出后 NAT-T 端口未恢复");
        Ok(())
    }
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
    natt_port: u16,
    original_natt_port: u16,
}

impl Daemon {
    async fn start(
        ike_port: u16,
        natt_port: u16,
        original_natt_port: u16,
    ) -> Result<(Self, UnixStream)> {
        let directory = tempfile::Builder::new()
            .prefix("v5vpn-nc-")
            .tempdir_in(RUN_DIR)
            .context("无法创建私有 NC 引擎目录")?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
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
        let runtime = runtime()?;
        let mut command = Command::new(&runtime.executable);
        command
            .env_clear()
            .env("STRONGSWAN_CONF", config)
            .current_dir(directory.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if let Some(root) = &runtime.root {
            command
                .current_dir(root.join("lib"))
                .env("OPENSSL_MODULES", root.join("lib/ossl-modules"))
                .env("OPENSSL_CONF", root.join("openssl.cnf"));
        }
        let child = command.spawn().context("无法启动原生 strongSwan 引擎")?;
        let mut daemon = Self {
            child,
            _directory: directory,
            natt_port,
            original_natt_port,
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
        // Restore the global NAT-T setting only after our daemon has exited.
        timeout(Duration::from_secs(10), self.child.wait())
            .await
            .context("等待 strongSwan 清理路由和 SA 超时")??;
        restore_natt_port(
            self.natt_port,
            self.original_natt_port,
            read_esp_port,
            write_esp_port,
        )
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.signal_stop();
        if matches!(self.child.try_wait(), Ok(Some(_)))
            && let Err(error) = restore_natt_port(
                self.natt_port,
                self.original_natt_port,
                read_esp_port,
                write_esp_port,
            )
        {
            eprintln!("恢复 macOS NC 的 NAT-T 配置失败：{error:#}");
        }
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
    fn sysctlbyname(
        name: *const std::ffi::c_char,
        old_value: *mut c_void,
        old_size: *mut usize,
        new_value: *mut c_void,
        new_size: usize,
    ) -> c_int;
    fn geteuid() -> u32;
    fn socket(domain: c_int, kind: c_int, protocol: c_int) -> c_int;
    fn fcntl(fd: c_int, command: c_int, ...) -> c_int;
    fn ioctl(fd: c_int, request: c_ulong, ...) -> c_int;
    fn connect(fd: c_int, addr: *const c_void, len: u32) -> c_int;
    fn getsockopt(fd: c_int, level: c_int, name: c_int, value: *mut c_void, len: *mut u32)
    -> c_int;
    fn kill(pid: c_int, signal: c_int) -> c_int;
}
