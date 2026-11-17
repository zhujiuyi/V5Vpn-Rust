use std::{
    env,
    ffi::{OsStr, OsString},
    io,
    mem::size_of,
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    ptr::{null, null_mut},
    slice,
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use windows_sys::Win32::{
    Foundation::{
        ERROR_CANCELLED, ERROR_INSUFFICIENT_BUFFER, ERROR_SERVICE_DOES_NOT_EXIST,
        ERROR_SUCCESS_REBOOT_INITIATED, ERROR_SUCCESS_REBOOT_REQUIRED, LocalFree, WAIT_FAILED,
        WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    Security::{
        Authorization::ConvertSidToStringSidW, GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY,
        TOKEN_USER, TokenElevation, TokenUser,
    },
    System::{
        Com::{COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoInitializeEx, CoUninitialize},
        Services::{
            CloseServiceHandle, OpenSCManagerW, OpenServiceW, SC_HANDLE, SC_MANAGER_CONNECT,
            SERVICE_QUERY_STATUS,
        },
        SystemInformation::GetSystemDirectoryW,
        Threading::{CREATE_NO_WINDOW, GetCurrentProcess, OpenProcessToken, WaitForSingleObject},
    },
    UI::{
        Shell::{SEE_MASK_FLAG_NO_UI, SEE_MASK_NOASYNC, SHELLEXECUTEINFOW, ShellExecuteExW},
        WindowsAndMessaging::SW_SHOWNORMAL,
    },
};

const ELEVATED_ARGUMENT: &str = "--nc-elevated";
const PROBE_TIMEOUT: Duration = Duration::from_secs(12);
const INSTALL_TIMEOUT: Duration = Duration::from_secs(900);

pub(super) fn is_elevated() -> Result<bool> {
    let token = current_token()?;
    let mut data = TOKEN_ELEVATION::default();
    let mut length = 0;
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenElevation,
            (&mut data as *mut TOKEN_ELEVATION).cast(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut length,
        )
    } == 0
    {
        return Err(io::Error::last_os_error()).context("无法检查 Windows 管理员权限");
    }
    Ok(data.TokenIsElevated != 0)
}

pub(super) fn current_sid() -> Result<String> {
    let token = current_token()?;
    let mut length = 0;
    if unsafe { GetTokenInformation(token.as_raw_handle(), TokenUser, null_mut(), 0, &mut length) }
        == 0
    {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) {
            return Err(error).context("无法读取 Windows 用户身份");
        }
    }
    ensure!(
        length as usize >= size_of::<TOKEN_USER>(),
        "Windows 返回的用户身份无效"
    );

    // TOKEN_USER contains an aligned pointer to the SID in the same buffer.
    let mut data = vec![0_usize; (length as usize).div_ceil(size_of::<usize>())];
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            data.as_mut_ptr().cast(),
            length,
            &mut length,
        )
    } == 0
    {
        return Err(io::Error::last_os_error()).context("无法读取 Windows 用户身份");
    }
    let user = unsafe { &*data.as_ptr().cast::<TOKEN_USER>() };
    let mut sid = null_mut();
    if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut sid) } == 0 {
        return Err(io::Error::last_os_error()).context("无法转换 Windows 用户身份");
    }
    // The Windows-allocated SID string is null-terminated.
    let length = (0..)
        .take_while(|index| unsafe { *sid.add(*index) != 0 })
        .count();
    let identity = String::from_utf16(unsafe { slice::from_raw_parts(sid, length) });
    unsafe { LocalFree(sid.cast()) };
    identity.context("Windows 用户身份编码无效")
}

fn current_token() -> Result<OwnedHandle> {
    let mut token = null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error()).context("无法读取当前 Windows 进程的权限");
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(token) })
}

pub(super) fn verify_elevated_launch() -> Result<()> {
    let mut arguments = env::args_os().skip(1);
    if arguments.next().as_deref() != Some(OsStr::new(ELEVATED_ARGUMENT)) {
        return Ok(());
    }
    let expected_sid = arguments.next().context("缺少原 Windows 登录账户信息")?;
    ensure!(arguments.next().is_none(), "管理员启动参数无效");
    ensure!(is_elevated()?, "Windows 尚未授予管理员权限");
    ensure!(
        expected_sid == OsStr::new(&current_sid()?),
        "请使用同一 Windows 账户授权启动。WSL 发行版和已保存的账号仅属于原 Windows 账户"
    );
    Ok(())
}

pub(super) fn relaunch_elevated() -> Result<bool> {
    let executable = env::current_exe().context("无法定位当前客户端")?;
    let arguments = format!("{ELEVATED_ARGUMENT} {}", current_sid()?);
    let executable = wide(executable.as_os_str());
    let arguments = wide(OsStr::new(&arguments));
    let verb = wide(OsStr::new("runas"));
    let apartment = unsafe {
        CoInitializeEx(
            null(),
            (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) as u32,
        )
    };
    ensure!(
        apartment >= 0,
        "无法初始化 Windows 管理员授权（0x{:08X}）",
        apartment as u32
    );

    let mut execution = SHELLEXECUTEINFOW {
        cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_FLAG_NO_UI | SEE_MASK_NOASYNC,
        lpVerb: verb.as_ptr(),
        lpFile: executable.as_ptr(),
        lpParameters: arguments.as_ptr(),
        nShow: SW_SHOWNORMAL,
        ..Default::default()
    };
    let launched = unsafe { ShellExecuteExW(&mut execution) };
    let error = (launched == 0).then(io::Error::last_os_error);
    unsafe { CoUninitialize() };
    match error {
        None => Ok(true),
        Some(error) if error.raw_os_error() == Some(ERROR_CANCELLED as i32) => Ok(false),
        Some(error) => Err(error).context("无法以管理员身份重新打开客户端"),
    }
}

pub(super) fn ready_host() -> Result<Option<PathBuf>> {
    let wsl = system_wsl()?;
    Ok(host_ready(&wsl)?.then_some(wsl))
}

pub(super) fn ensure_host(progress: impl Fn(&str)) -> Result<PathBuf> {
    let wsl = system_wsl()?;
    if host_ready(&wsl)? {
        return Ok(wsl);
    }
    ensure!(is_elevated()?, "安装 WSL 2 需要 Windows 管理员权限");

    progress("正在通过微软安装 WSL 2 主机组件");
    let mut installer = start_wsl(&wsl, &["--install", "--no-distribution", "--web-download"])?;
    let status = wait_for_wsl(&mut installer, INSTALL_TIMEOUT)?
        .context("等待 WSL 2 安装超时。Windows 可能仍在安装组件，完成后重新打开客户端")?;
    let code = status.code().unwrap_or_default() as u32;
    if reboot_requested(code) {
        bail!("Windows 需要重启以完成 WSL 2 安装。保存工作并重启后重新打开客户端");
    }
    ensure!(status.success(), "微软 WSL 2 安装失败（0x{code:08X}）");
    ensure!(
        host_ready(&wsl)?,
        "WSL 2 安装完成但主机尚未就绪。重启 Windows 后重新打开客户端"
    );
    Ok(wsl)
}

fn reboot_requested(code: u32) -> bool {
    // Installers may return either a Win32 code or its HRESULT form.
    let code = if code >> 16 == 0x8007 {
        code & 0xFFFF
    } else {
        code
    };
    matches!(
        code,
        ERROR_SUCCESS_REBOOT_REQUIRED | ERROR_SUCCESS_REBOOT_INITIATED
    )
}

fn system_wsl() -> Result<PathBuf> {
    let mut buffer = vec![0_u16; 32768];
    let length = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    if length == 0 {
        return Err(io::Error::last_os_error()).context("无法定位 Windows 系统目录");
    }
    ensure!(length < buffer.len(), "Windows 系统目录路径过长");
    let wsl = PathBuf::from(OsString::from_wide(&buffer[..length])).join("wsl.exe");
    ensure!(
        wsl.is_file(),
        "系统中没有 wsl.exe，请在支持 WSL 2 的 Windows 版本上使用 NC/IPsec"
    );
    Ok(wsl)
}

fn host_ready(wsl: &Path) -> Result<bool> {
    // WSL --status can succeed without the compute service or any distributions.
    if !compute_service_present()? {
        return Ok(false);
    }
    let mut probe = start_wsl(wsl, &["--status"])?;
    match wait_for_wsl(&mut probe, PROBE_TIMEOUT)? {
        Some(status) => Ok(status.success()),
        None => {
            let _ = probe.kill();
            let _ = probe.wait();
            Ok(false)
        }
    }
}

struct ServiceHandle(SC_HANDLE);

impl Drop for ServiceHandle {
    fn drop(&mut self) {
        unsafe { CloseServiceHandle(self.0) };
    }
}

fn compute_service_present() -> Result<bool> {
    let manager = unsafe { OpenSCManagerW(null(), null(), SC_MANAGER_CONNECT) };
    if manager.is_null() {
        return Err(io::Error::last_os_error()).context("无法检查 Windows 虚拟机平台");
    }
    let manager = ServiceHandle(manager);
    let service = wide(OsStr::new("vmcompute"));
    let service = unsafe { OpenServiceW(manager.0, service.as_ptr(), SERVICE_QUERY_STATUS) };
    if service.is_null() {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST as i32) {
            return Ok(false);
        }
        return Err(error).context("无法检查 Windows 虚拟机计算服务");
    }
    let _service = ServiceHandle(service);
    Ok(true)
}

fn start_wsl(wsl: &Path, arguments: &[&str]) -> Result<Child> {
    Command::new(wsl)
        .args(arguments)
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("无法启动 Windows WSL")
}

fn wait_for_wsl(child: &mut Child, timeout: Duration) -> Result<Option<ExitStatus>> {
    match unsafe { WaitForSingleObject(child.as_raw_handle(), timeout.as_millis() as u32) } {
        WAIT_OBJECT_0 => child.wait().map(Some).context("无法取得 WSL 返回状态"),
        WAIT_TIMEOUT => Ok(None),
        WAIT_FAILED => Err(io::Error::last_os_error()).context("无法等待 WSL 返回"),
        value => bail!("Windows 返回未知的 WSL 等待状态（0x{value:08X}）"),
    }
}

fn wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}
