use std::{
    fs::{self, File, OpenOptions, TryLockError},
    io::{self, Write},
    path::{Path, PathBuf},
    ptr::{null, null_mut},
};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use url::Url;
use windows_sys::{
    Win32::{
        Foundation::{
            ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, ERROR_SUCCESS,
            GlobalFree,
        },
        Networking::{
            WinHttp::{
                WINHTTP_CURRENT_USER_IE_PROXY_CONFIG, WinHttpGetIEProxyConfigForCurrentUser,
            },
            WinInet::{
                INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED, InternetSetOptionW,
            },
        },
        System::Registry::{
            HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_SET_VALUE, REG_SZ, RRF_RT_REG_DWORD,
            RRF_RT_REG_SZ, RegCloseKey, RegDeleteValueW, RegGetValueW, RegOpenKeyExW,
            RegSetValueExW,
        },
    },
    core::PCWSTR,
};

use crate::{desktop_settings, proxy::PAC_PATH};

const RECOVERY_FILE: &str = "wininet-pac.json";
const LOCK_FILE: &str = "wininet-pac.lock";
const INTERNET_SETTINGS: PCWSTR =
    windows_sys::w!(r"Software\Microsoft\Windows\CurrentVersion\Internet Settings");
const AUTO_CONFIG_URL: PCWSTR = windows_sys::w!("AutoConfigURL");

pub(crate) struct SystemProxy {
    _lock: File,
    recovery_path: PathBuf,
    recovery: Option<Recovery>,
}

#[derive(Deserialize, Serialize)]
struct Recovery {
    #[serde(default)]
    had_empty_value: bool,
    pac_url: String,
}

#[derive(PartialEq, Eq)]
struct BrowserOptions {
    auto_detect: bool,
    manual_proxy: bool,
    pac_url: Option<String>,
}

impl SystemProxy {
    pub(crate) fn activate(pac_url: &str) -> Result<Self> {
        validate_pac_url(pac_url)?;
        ensure_per_user_proxy_settings()?;
        let folder = desktop_settings::directory()?;
        let lock = acquire_lock(&folder)?.context("另一个 V5VPN 会话正在使用 Windows 系统代理")?;
        let recovery_path = folder.join(RECOVERY_FILE);
        recover_previous_session(&recovery_path)?;

        let previous = read_browser_options()?;
        let old_pac = read_registered_pac()?;
        ensure!(
            !previous.auto_detect
                && !previous.manual_proxy
                && previous.pac_url.as_deref().is_none_or(str::is_empty)
                && old_pac.as_deref().is_none_or(str::is_empty),
            "Windows 已配置手动代理、自动检测或设置脚本。请确认原代理设置后再连接 V5VPN"
        );
        let recovery = Recovery {
            had_empty_value: old_pac.is_some(),
            pac_url: pac_url.to_owned(),
        };
        save_recovery(&folder, &recovery_path, &recovery)?;
        let mut lease = Self {
            _lock: lock,
            recovery_path,
            recovery: Some(recovery),
        };
        let result = (|| {
            ensure!(
                read_browser_options()? == previous && read_registered_pac()? == old_pac,
                "Windows 代理设置刚被修改，请重新连接"
            );
            write_registered_pac(Some(pac_url))?;
            notify_windows()?;
            ensure!(
                read_registered_pac()?.as_deref() == Some(pac_url),
                "Windows 未保存 V5VPN 代理设置脚本"
            );
            ensure!(
                read_browser_options()?.pac_url.as_deref() == Some(pac_url),
                "Windows 浏览器配置未读到 V5VPN 代理设置脚本"
            );
            Ok(())
        })();
        if let Err(error) = result {
            if let Err(rollback) = lease.restore() {
                return Err(error).context(format!("恢复 Windows 代理设置失败：{rollback:#}"));
            }
            return Err(error);
        }
        Ok(lease)
    }

    pub(crate) fn recover_stale() -> Result<()> {
        let folder = desktop_settings::directory()?;
        let path = folder.join(RECOVERY_FILE);
        if path.try_exists()?
            && let Some(_lock) = acquire_lock(&folder)?
        {
            recover_previous_session(&path)?;
        }
        Ok(())
    }

    pub(crate) fn restore(&mut self) -> Result<()> {
        if let Some(recovery) = &self.recovery {
            restore_owned_pac(recovery)?;
            remove_recovery(&self.recovery_path)?;
            self.recovery = None;
        }
        Ok(())
    }
}

impl Drop for SystemProxy {
    fn drop(&mut self) {
        if let Err(error) = self.restore() {
            eprintln!("恢复 Windows 系统代理失败：{error:#}");
        }
    }
}

fn acquire_lock(folder: &Path) -> Result<Option<File>> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(folder.join(LOCK_FILE))
        .context("无法打开 Windows 代理会话锁")?;
    match file.try_lock() {
        Ok(()) => Ok(Some(file)),
        Err(TryLockError::WouldBlock) => Ok(None),
        Err(TryLockError::Error(error)) => Err(error).context("无法锁定 Windows 代理会话"),
    }
}

fn validate_pac_url(pac_url: &str) -> Result<()> {
    let invalid = "系统代理仅接受本会话的回环 PAC 地址";
    let url = Url::parse(pac_url).context(invalid)?;
    ensure!(
        url.scheme() == "http"
            && url.host_str() == Some("127.0.0.1")
            && url.port().is_some_and(|port| port != 0)
            && url.path() == PAC_PATH
            && url.query().is_none()
            && url.fragment().is_none()
            && url.username().is_empty()
            && url.password().is_none(),
        invalid
    );
    Ok(())
}

fn recover_previous_session(path: &Path) -> Result<()> {
    let data = match fs::read(path) {
        Ok(data) => data,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("无法读取 Windows 代理恢复记录"),
    };
    let recovery: Recovery = serde_json::from_slice(&data).context("Windows 代理恢复记录无效")?;
    validate_pac_url(&recovery.pac_url)?;
    restore_owned_pac(&recovery).context("无法恢复上次会话的 Windows 代理设置")?;
    remove_recovery(path)
}

fn save_recovery(folder: &Path, path: &Path, recovery: &Recovery) -> Result<()> {
    let mut file =
        tempfile::NamedTempFile::new_in(folder).context("无法创建 Windows 代理恢复记录")?;
    serde_json::to_writer(file.as_file_mut(), recovery)?;
    file.flush()?;
    file.as_file().sync_all()?;
    file.persist_noclobber(path)
        .context("无法保存 Windows 代理恢复记录")?;
    Ok(())
}

fn remove_recovery(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("无法清理 Windows 代理恢复记录"),
    }
}

fn restore_owned_pac(recovery: &Recovery) -> Result<()> {
    if read_registered_pac()?.as_deref() == Some(recovery.pac_url.as_str()) {
        write_registered_pac(recovery.had_empty_value.then_some(""))?;
        notify_windows()?;
    }
    Ok(())
}

fn read_registered_pac() -> Result<Option<String>> {
    let mut buffer = [0u16; 4096];
    let mut size = size_of_val(&buffer) as u32;
    let status = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            INTERNET_SETTINGS,
            AUTO_CONFIG_URL,
            RRF_RT_REG_SZ,
            null_mut(),
            buffer.as_mut_ptr().cast(),
            &mut size,
        )
    };
    match status {
        ERROR_SUCCESS => {
            let length = buffer
                .iter()
                .position(|&unit| unit == 0)
                .unwrap_or(buffer.len());
            Ok(Some(
                String::from_utf16(&buffer[..length]).context("Windows PAC 地址格式无效")?,
            ))
        }
        ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => Ok(None),
        status => Err(io::Error::from_raw_os_error(status as i32))
            .context("无法读取当前用户的 Windows PAC 注册值"),
    }
}

fn write_registered_pac(pac_url: Option<&str>) -> Result<()> {
    ensure_per_user_proxy_settings()?;
    let mut key = null_mut();
    let opened = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            INTERNET_SETTINGS,
            0,
            KEY_SET_VALUE,
            &mut key,
        )
    };
    if opened != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(opened as i32)).context(
            if opened == ERROR_ACCESS_DENIED {
                "当前进程无权修改 Windows 代理，请从资源管理器直接启动客户端"
            } else {
                "无法打开当前用户的 Windows 代理设置"
            },
        );
    }
    let status = match pac_url {
        Some(pac_url) => {
            let value: Vec<u16> = pac_url.encode_utf16().chain([0]).collect();
            unsafe {
                RegSetValueExW(
                    key,
                    AUTO_CONFIG_URL,
                    0,
                    REG_SZ,
                    value.as_ptr().cast(),
                    size_of_val(value.as_slice()) as u32,
                )
            }
        }
        None => unsafe { RegDeleteValueW(key, AUTO_CONFIG_URL) },
    };
    unsafe {
        RegCloseKey(key);
    }
    match status {
        ERROR_SUCCESS => Ok(()),
        ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND if pac_url.is_none() => Ok(()),
        ERROR_ACCESS_DENIED => Err(io::Error::from_raw_os_error(status as i32))
            .context("当前进程无权修改 Windows 代理，请从资源管理器直接启动客户端"),
        status => Err(io::Error::from_raw_os_error(status as i32))
            .context("无法修改当前用户的 Windows PAC 注册值"),
    }
}

fn read_browser_options() -> Result<BrowserOptions> {
    let mut settings = WINHTTP_CURRENT_USER_IE_PROXY_CONFIG::default();
    let success = unsafe { WinHttpGetIEProxyConfigForCurrentUser(&mut settings) } != 0;
    let error = (!success).then(io::Error::last_os_error);
    let mut pac_url = None;
    let mut manual_proxy = false;
    if success {
        let value = settings.lpszAutoConfigUrl;
        if !value.is_null() {
            let mut length = 0;
            unsafe {
                while *value.add(length) != 0 {
                    length += 1;
                }
                pac_url = Some(String::from_utf16_lossy(std::slice::from_raw_parts(
                    value, length,
                )));
            }
        }
        manual_proxy = !settings.lpszProxy.is_null() && unsafe { *settings.lpszProxy != 0 };
    }
    for pointer in [
        settings.lpszAutoConfigUrl,
        settings.lpszProxy,
        settings.lpszProxyBypass,
    ] {
        if !pointer.is_null() {
            unsafe {
                GlobalFree(pointer.cast());
            }
        }
    }
    if let Some(error) = error {
        return Err(error).context("无法读取 Windows 浏览器代理配置");
    }
    Ok(BrowserOptions {
        auto_detect: settings.fAutoDetect != 0,
        manual_proxy,
        pac_url,
    })
}

fn ensure_per_user_proxy_settings() -> Result<()> {
    let mut enabled = 0u32;
    let mut size = size_of::<u32>() as u32;
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            windows_sys::w!(
                r"SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"
            ),
            windows_sys::w!("ProxySettingsPerUser"),
            RRF_RT_REG_DWORD,
            null_mut(),
            (&mut enabled as *mut u32).cast(),
            &mut size,
        )
    };
    match status {
        ERROR_SUCCESS => {
            ensure!(
                enabled != 0,
                "Windows 管理策略要求使用整机代理，本客户端仅配置当前用户代理"
            );
            Ok(())
        }
        ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => Ok(()),
        status => Err(io::Error::from_raw_os_error(status as i32))
            .context("无法读取 Windows 系统代理管理策略"),
    }
}

fn notify_windows() -> Result<()> {
    for option in [INTERNET_OPTION_SETTINGS_CHANGED, INTERNET_OPTION_REFRESH] {
        if unsafe { InternetSetOptionW(null(), option, null(), 0) } == 0 {
            return Err(io::Error::last_os_error()).context("无法通知 Windows 刷新系统代理");
        }
    }
    Ok(())
}

#[cfg(test)]
#[test]
#[ignore = "显式运行时短暂启用本机用户 PAC，只用于验证部署机器"]
fn sets_and_restores_user_pac() -> Result<()> {
    let baseline = read_browser_options()?;
    let old_registration = read_registered_pac()?;
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let pac_url = format!("http://{}{PAC_PATH}", listener.local_addr()?);
    let mut proxy = SystemProxy::activate(&pac_url)?;
    proxy.restore()?;
    ensure!(
        read_browser_options()? == baseline,
        "Windows 浏览器代理未恢复"
    );
    ensure!(
        read_registered_pac()? == old_registration,
        "Windows PAC 注册值未恢复"
    );
    Ok(())
}
