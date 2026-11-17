use std::{
    ffi::{OsStr, OsString, c_void},
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::windows::{ffi::OsStringExt, fs::MetadataExt, process::CommandExt},
    path::{Component, Path, PathBuf, Prefix},
    process::{Command, ExitStatus, Stdio},
    ptr::{null, null_mut},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest, Sha256};
use tempfile::{Builder, TempPath};
use tokio::{io::AsyncWriteExt, time::timeout};
use v5vpn_client::desktop_settings;
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, ERROR_FILE_NOT_FOUND, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS, HANDLE,
        WAIT_ABANDONED, WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    Networking::WinHttp::{
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_FLAG_SECURE, WINHTTP_OPTION_REDIRECT_POLICY,
        WINHTTP_OPTION_REDIRECT_POLICY_NEVER, WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_QUERY_STATUS_CODE,
        WinHttpCloseHandle, WinHttpConnect, WinHttpOpen, WinHttpOpenRequest, WinHttpQueryHeaders,
        WinHttpReadData, WinHttpReceiveResponse, WinHttpSendRequest, WinHttpSetOption,
        WinHttpSetTimeouts,
    },
    System::{
        Registry::{
            HKEY, HKEY_CURRENT_USER, KEY_READ, RRF_RT_REG_DWORD, RRF_RT_REG_SZ, RegCloseKey,
            RegEnumKeyExW, RegGetValueW, RegOpenKeyExW,
        },
        Threading::{CreateMutexW, ReleaseMutex, WaitForSingleObject},
    },
};

const DISTRO: &str = "V5VPN-NC";
const OWNERSHIP_FILE: &str = "managed-ubuntu-24.04-v1";
const OWNERSHIP_MARK: &[u8] = b"V5VPN-NC ubuntu-24.04 v1";
const PROVISION: &str = include_str!("../../support/wsl-nc-provision.sh");
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const REPARSE_POINT: u32 = 0x400;

const IMAGE_HOST: &str = "cloud-images.ubuntu.com";
// SHA256SUMS in this dated Canonical directory lists this exact archive.
const IMAGE_PATH: &str =
    "/wsl/releases/24.04/20240423/ubuntu-noble-wsl-amd64-24.04lts.rootfs.tar.gz";
const IMAGE_SHA256: &str = "2a790896740b14d637dbdc583cce1ba081ac53b9e9cdb46dc09a2f73abbd9934";
const IMAGE_BYTES: usize = 356_736_729;

/// This probe only reads registration and checks the project's dedicated guest.
/// The caller runs it on a blocking thread.
pub(super) fn distribution_ready(wsl: &Path) -> Result<bool> {
    let Some(registration) = registration()? else {
        return Ok(false);
    };
    verify_ownership(&registration, &provision_directory()?)?;
    check_tools(wsl)
}

/// Installs only the dedicated guest. The caller resolves host setup and UAC.
pub(super) fn ensure_distribution(wsl: &Path, progress: impl Fn(&str)) -> Result<()> {
    let _lock = ProvisionLock::acquire()?;
    let root = provision_directory()?;
    let registered = match registration()? {
        Some(registered) => registered,
        None => {
            let app_data = root.parent().context("无法定位客户端数据目录")?;
            prepare_directory(app_data)?;
            prepare_directory(&root)?;
            let install = root.join(DISTRO);
            prepare_directory(&install)?;
            ensure!(
                fs::read_dir(&install)?.next().transpose()?.is_none(),
                "V5VPN-NC 安装目录已有文件。请检查上次导入结果或移走该目录后重试"
            );
            let stamp = root.join(OWNERSHIP_FILE);
            prepare_stamp(&stamp)?;
            let archive = download_image(&root, &progress)?;
            progress("正在导入专用 Ubuntu 24.04 WSL2 环境");
            let mut import = Command::new(wsl);
            import
                .args(["--import", DISTRO])
                .arg(&install)
                .arg(&archive)
                .args(["--version", "2"]);
            let status = run_wsl(import, Duration::from_secs(600), None)?;
            ensure!(
                status.success(),
                "导入专用 V5VPN-NC 失败（{status}）。请检查 WSL2 状态后重试"
            );
            registration()?.context("WSL 未返回专用 V5VPN-NC 的注册记录")?
        }
    };
    verify_ownership(&registered, &root)?;
    if check_tools(wsl)? {
        return Ok(());
    }

    progress("正在为 V5VPN-NC 安装 strongSwan 和网络工具");
    let mut install = guest_command(wsl);
    install.args(["/bin/sh", "-s"]);
    let script = PROVISION.replace("\r\n", "\n");
    let status = run_wsl(install, Duration::from_secs(900), Some(&script))?;
    match status.code() {
        Some(0) => Ok(()),
        Some(11) => bail!("V5VPN-NC 正在使用中，请先断开占用此环境的连接再试"),
        _ => bail!("无法安装 V5VPN-NC 组件（{status}）。请检查 Ubuntu 软件源能否访问"),
    }
}

struct Registration {
    path: PathBuf,
    version: u32,
}

fn provision_directory() -> Result<PathBuf> {
    let dir = desktop_settings::directory()?.join("WSL");
    ensure!(local_drive_path(&dir), "WSL2 安装目录需要位于本地磁盘");
    Ok(dir)
}

fn local_drive_path(path: &Path) -> bool {
    path.is_absolute()
        && matches!(
            path.components().next(),
            Some(Component::Prefix(part))
                if matches!(part.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
        )
}

fn verify_ownership(registration: &Registration, root: &Path) -> Result<()> {
    ensure!(registration.version == 2, "已注册的 V5VPN-NC 需要使用 WSL2");
    let expected = root.join(DISTRO);
    let registered = registration.path.to_string_lossy();
    let expected_text = expected.to_string_lossy();
    ensure!(
        local_drive_path(&registration.path)
            && dos_path(&registered).eq_ignore_ascii_case(dos_path(&expected_text)),
        "已注册的 V5VPN-NC 位于其他位置，请在 WSL 中处理同名发行版后重试"
    );
    verify_directory(root.parent().context("无法定位客户端数据目录")?)?;
    verify_directory(root)?;
    verify_directory(&expected)?;
    verify_stamp(&root.join(OWNERSHIP_FILE))
}

fn dos_path(value: &str) -> &str {
    value
        .strip_prefix(r"\\?\")
        .unwrap_or(value)
        .trim_end_matches('\\')
}

fn prepare_directory(path: &Path) -> Result<()> {
    match fs::create_dir(path) {
        Ok(()) => (),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => (),
        Err(error) => return Err(error).context("无法创建 V5VPN-NC 数据目录"),
    }
    verify_directory(path)
}

fn verify_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path).context("无法读取 V5VPN-NC 数据目录")?;
    ensure!(
        metadata.is_dir() && metadata.file_attributes() & REPARSE_POINT == 0,
        "V5VPN-NC 数据目录需要是本地普通目录"
    );
    Ok(())
}

fn prepare_stamp(path: &Path) -> Result<()> {
    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(mut file) => file
            .write_all(OWNERSHIP_MARK)
            .context("无法保存 V5VPN-NC 归属标记"),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => verify_stamp(path),
        Err(error) => Err(error).context("无法创建 V5VPN-NC 归属标记"),
    }
}

fn verify_stamp(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path).context("缺少 V5VPN-NC 归属标记")?;
    ensure!(
        metadata.is_file()
            && metadata.file_attributes() & REPARSE_POINT == 0
            && metadata.len() == OWNERSHIP_MARK.len() as u64
            && fs::read(path)? == OWNERSHIP_MARK,
        "V5VPN-NC 归属标记无效，请检查专用发行版的来源"
    );
    Ok(())
}

fn check_tools(wsl: &Path) -> Result<bool> {
    let mut check = guest_command(wsl);
    check.args(["/bin/sh", "-s", "--", "--check"]);
    let script = PROVISION.replace("\r\n", "\n");
    let status = run_wsl(check, Duration::from_secs(25), Some(&script))?;
    match status.code() {
        Some(0) => Ok(true),
        Some(10) => Ok(false),
        _ => bail!("无法检查专用 V5VPN-NC 环境（{status}）"),
    }
}

fn guest_command(path: &Path) -> Command {
    let mut command = Command::new(path);
    command.args(["--distribution", DISTRO, "--user", "root", "--exec"]);
    command
}

fn run_wsl(mut command: Command, limit: Duration, script: Option<&str>) -> Result<ExitStatus> {
    command
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(if script.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut command = tokio::process::Command::from(command);
    command.kill_on_drop(true);
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            timeout(limit, async {
                let mut child = command.spawn().context("无法启动 Windows WSL")?;
                if let Some(script) = script {
                    let mut input = child.stdin.take().context("无法写入专用 WSL 进程")?;
                    input
                        .write_all(script.as_bytes())
                        .await
                        .context("无法将安装脚本送入专用 WSL 进程")?;
                    input.shutdown().await?;
                }
                child.wait().await.context("无法取得 WSL 执行结果")
            })
            .await
            .context("等待 Windows WSL 执行超时")?
        })
}

struct ProvisionLock(HANDLE);

impl ProvisionLock {
    fn acquire() -> Result<Self> {
        let name = wide(&format!(
            "Local\\V5VPN-NC-bootstrap-{}",
            super::windows_nc_host::current_sid()?
        ));
        let handle = unsafe { CreateMutexW(null(), 0, name.as_ptr()) };
        ensure!(
            !handle.is_null(),
            "无法创建 V5VPN-NC 安装锁（{}）",
            io::Error::last_os_error()
        );
        let wait = unsafe { WaitForSingleObject(handle, 0) };
        match wait {
            WAIT_OBJECT_0 | WAIT_ABANDONED => Ok(Self(handle)),
            _ => {
                let error = io::Error::last_os_error();
                unsafe { CloseHandle(handle) };
                ensure!(wait != WAIT_TIMEOUT, "另一个客户端正在准备 V5VPN-NC");
                Err(error).context("无法取得 V5VPN-NC 安装锁")
            }
        }
    }
}

impl Drop for ProvisionLock {
    fn drop(&mut self) {
        unsafe {
            ReleaseMutex(self.0);
            CloseHandle(self.0);
        }
    }
}

struct RegistryKey(HKEY);

impl Drop for RegistryKey {
    fn drop(&mut self) {
        unsafe { RegCloseKey(self.0) };
    }
}

fn registration() -> Result<Option<Registration>> {
    let Some(root) = open_registry(
        HKEY_CURRENT_USER,
        &wide(r"Software\Microsoft\Windows\CurrentVersion\Lxss"),
    )?
    else {
        return Ok(None);
    };
    let mut found = None;
    for index in 0.. {
        let mut name = [0u16; 256];
        let mut length = name.len() as u32;
        let status = unsafe {
            RegEnumKeyExW(
                root.0,
                index,
                name.as_mut_ptr(),
                &mut length,
                null(),
                null_mut(),
                null_mut(),
                null_mut(),
            )
        };
        if status == ERROR_NO_MORE_ITEMS {
            break;
        }
        registry_result(status)?;
        let Some(key) = open_registry(root.0, &name)? else {
            continue;
        };
        let Some(distro) = registry_string(key.0, "DistributionName")? else {
            continue;
        };
        if !distro.to_string_lossy().eq_ignore_ascii_case(DISTRO) {
            continue;
        }
        ensure!(found.is_none(), "存在多个同名 V5VPN-NC 注册记录");
        found = Some(Registration {
            path: registry_string(key.0, "BasePath")?
                .context("V5VPN-NC 注册记录缺少安装路径")?
                .into(),
            version: registry_version(key.0)?,
        });
    }
    Ok(found)
}

fn open_registry(parent: HKEY, name: &[u16]) -> Result<Option<RegistryKey>> {
    let mut handle = null_mut();
    let status = unsafe { RegOpenKeyExW(parent, name.as_ptr(), 0, KEY_READ, &mut handle) };
    if status == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    registry_result(status)?;
    Ok(Some(RegistryKey(handle)))
}

fn registry_string(key: HKEY, name: &str) -> Result<Option<OsString>> {
    let name = wide(name);
    let mut bytes = 0;
    let status = unsafe {
        RegGetValueW(
            key,
            null(),
            name.as_ptr(),
            RRF_RT_REG_SZ,
            null_mut(),
            null_mut(),
            &mut bytes,
        )
    };
    if status == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    registry_result(status)?;
    ensure!(
        (2..=65_536).contains(&bytes) && bytes % 2 == 0,
        "专用 WSL2 注册项长度无效"
    );
    let mut value = vec![0u16; bytes as usize / 2];
    let status = unsafe {
        RegGetValueW(
            key,
            null(),
            name.as_ptr(),
            RRF_RT_REG_SZ,
            null_mut(),
            value.as_mut_ptr().cast(),
            &mut bytes,
        )
    };
    registry_result(status)?;
    let end = value
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(value.len());
    Ok(Some(OsString::from_wide(&value[..end])))
}

fn registry_version(key: HKEY) -> Result<u32> {
    let mut version = 0u32;
    let mut bytes = size_of::<u32>() as u32;
    let name = wide("Version");
    let status = unsafe {
        RegGetValueW(
            key,
            null(),
            name.as_ptr(),
            RRF_RT_REG_DWORD,
            null_mut(),
            (&mut version as *mut u32).cast(),
            &mut bytes,
        )
    };
    registry_result(status)?;
    Ok(version)
}

fn registry_result(status: u32) -> Result<()> {
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(status as i32)).context("无法读取 WSL 发行版注册信息")
    }
}

struct HttpHandle(*mut c_void);

impl HttpHandle {
    fn open(handle: *mut c_void) -> io::Result<Self> {
        if handle.is_null() {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(handle))
        }
    }
}

impl Drop for HttpHandle {
    fn drop(&mut self) {
        unsafe { WinHttpCloseHandle(self.0) };
    }
}

fn download_image(root: &Path, progress: &impl Fn(&str)) -> Result<TempPath> {
    progress("正在下载 Canonical 官方 Ubuntu 24.04 镜像");
    let mut file = Builder::new()
        .prefix("ubuntu-download-")
        .suffix(".tar.gz")
        .tempfile_in(root)
        .context("无法创建 Ubuntu 镜像下载文件")?;
    let agent = wide("V5Vpn-Rust");
    let session = HttpHandle::open(unsafe {
        WinHttpOpen(
            agent.as_ptr(),
            WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
            null(),
            null(),
            0,
        )
    })
    .context("无法初始化 Ubuntu 镜像下载")?;
    http_ok(unsafe { WinHttpSetTimeouts(session.0, 15_000, 20_000, 20_000, 60_000) })
        .context("无法设置 Ubuntu 镜像下载超时")?;
    let host = wide(IMAGE_HOST);
    let peer = HttpHandle::open(unsafe { WinHttpConnect(session.0, host.as_ptr(), 443, 0) })
        .context("无法连接 Canonical 镜像服务器")?;
    let verb = wide("GET");
    let path = wide(IMAGE_PATH);
    let request = HttpHandle::open(unsafe {
        WinHttpOpenRequest(
            peer.0,
            verb.as_ptr(),
            path.as_ptr(),
            null(),
            null(),
            null(),
            WINHTTP_FLAG_SECURE,
        )
    })
    .context("无法创建 Ubuntu 镜像请求")?;
    let redirect = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
    http_ok(unsafe {
        WinHttpSetOption(
            request.0,
            WINHTTP_OPTION_REDIRECT_POLICY,
            (&redirect as *const u32).cast(),
            size_of::<u32>() as u32,
        )
    })
    .context("无法限制 Ubuntu 镜像请求的目标")?;
    http_ok(unsafe { WinHttpSendRequest(request.0, null(), 0, null(), 0, 0, 0) })
        .context("无法请求 Ubuntu 镜像")?;
    http_ok(unsafe { WinHttpReceiveResponse(request.0, null_mut()) })
        .context("无法取得 Ubuntu 镜像响应")?;
    let mut code = 0u32;
    let mut length = size_of::<u32>() as u32;
    http_ok(unsafe {
        WinHttpQueryHeaders(
            request.0,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            null(),
            (&mut code as *mut u32).cast(),
            &mut length,
            null_mut(),
        )
    })
    .context("无法读取 Ubuntu 镜像响应状态")?;
    ensure!(code == 200, "Canonical 镜像下载返回 HTTP {code}");
    copy_image(&request, file.as_file_mut(), progress)?;
    Ok(file.into_temp_path())
}

fn copy_image(request: &HttpHandle, output: &mut File, progress: &impl Fn(&str)) -> Result<()> {
    const MIB: usize = 1024 * 1024;
    let deadline = Instant::now() + Duration::from_secs(900);
    let mut received = 0;
    let mut next_update = 32 * MIB;
    let mut hash = Sha256::new();
    let mut buffer = vec![0u8; 128 * 1024];
    loop {
        ensure!(Instant::now() < deadline, "下载 Ubuntu 镜像超时");
        let mut count = 0;
        http_ok(unsafe {
            WinHttpReadData(
                request.0,
                buffer.as_mut_ptr().cast(),
                buffer.len() as u32,
                &mut count,
            )
        })
        .context("读取 Ubuntu 镜像数据失败")?;
        if count == 0 {
            break;
        }
        received += count as usize;
        ensure!(received <= IMAGE_BYTES, "Ubuntu 镜像大小超出校验值");
        let chunk = &buffer[..count as usize];
        output
            .write_all(chunk)
            .context("无法保存 Ubuntu 镜像数据")?;
        hash.update(chunk);
        if received >= next_update {
            progress(&format!(
                "正在下载 Ubuntu 镜像（{}/{} MiB）",
                received / MIB,
                IMAGE_BYTES.div_ceil(MIB)
            ));
            next_update += 32 * MIB;
        }
    }
    ensure!(
        received == IMAGE_BYTES && format!("{:x}", hash.finalize()) == IMAGE_SHA256,
        "Ubuntu 镜像未通过 SHA-256 校验"
    );
    output.flush().context("无法完成 Ubuntu 镜像保存")?;
    Ok(())
}

fn http_ok(result: i32) -> io::Result<()> {
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn wide(value: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    OsStr::new(value).encode_wide().chain([0]).collect()
}
