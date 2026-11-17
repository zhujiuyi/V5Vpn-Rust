use std::{
    ffi::{CStr, c_char, c_void},
    fs::{self, File, OpenOptions, TryLockError},
    io,
    path::{Path, PathBuf},
    ptr::{null, null_mut},
    thread,
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{desktop_settings, proxy::PAC_PATH};

const RECOVERY_FILE: &str = "macos-pac.json";
const LOCK_FILE: &str = "macos-pac.lock";
const PAC_ENABLE: &str = "ProxyAutoConfigEnable";
const PAC_URL: &str = "ProxyAutoConfigURLString";
const UTF8: u32 = 0x0800_0100;
const SINT32: isize = 3;

pub(crate) struct SystemProxy {
    _lock: File,
    authorization: Authorization,
    path: PathBuf,
    recovery: Option<Recovery>,
}

#[derive(Deserialize, Serialize)]
struct Recovery {
    service_id: String,
    pac_url: String,
    had_disabled_flag: bool,
    had_empty_url: bool,
}

impl Recovery {
    fn original(&self) -> PacState {
        PacState {
            enabled: self.had_disabled_flag.then_some(false),
            url: self.had_empty_url.then(String::new),
        }
    }

    fn owns(&self, pac: &PacState) -> bool {
        pac.enabled == Some(true) && pac.url.as_deref() == Some(self.pac_url.as_str())
    }
}

#[derive(PartialEq, Eq)]
struct PacState {
    enabled: Option<bool>,
    url: Option<String>,
}

impl SystemProxy {
    pub(crate) fn activate(pac_url: &str) -> Result<Self> {
        validate_url(pac_url)?;
        let folder = desktop_settings::directory()?;
        let lock = acquire_lock(&folder)?.context("另一个 V5VPN 会话正在使用 macOS 系统代理")?;
        let path = folder.join(RECOVERY_FILE);
        let mut authorization = None;
        if let Some(recovery) = read_recovery(&path)? {
            if requires_restore(&recovery)? {
                let auth = Authorization::network(true)?;
                restore_owned(&recovery, &auth)?;
                authorization = Some(auth);
            }
            remove_recovery(&path)?;
        }

        let service_id = active_service()?;
        ensure_direct(effective_proxies()?.get())?;
        let authorization = match authorization {
            Some(auth) => auth,
            None => Authorization::network(true)?,
        };
        let mut guard = Self {
            _lock: lock,
            authorization,
            path,
            recovery: None,
        };
        let result = (|| {
            let prefs = Preferences::update(&guard.authorization)?;
            ensure!(
                active_service()? == service_id,
                "当前网络服务已切换，请重新连接"
            );
            ensure_direct(effective_proxies()?.get())?;
            let protocol = prefs
                .protocol(&service_id)?
                .context("默认网络服务没有代理协议配置")?;
            ensure!(
                unsafe { SCNetworkProtocolGetEnabled(protocol.get()) } != 0,
                "默认网络服务的代理配置不可用"
            );
            let config = configuration(&protocol)?;
            let original = ensure_direct(config)?;
            let recovery = Recovery {
                service_id: service_id.clone(),
                pac_url: pac_url.to_owned(),
                had_disabled_flag: original.enabled.is_some(),
                had_empty_url: original.url.is_some(),
            };
            save_recovery(&folder, &guard.path, &recovery)?;
            guard.recovery = Some(recovery);
            prefs.write_pac(
                &protocol,
                config,
                PacState {
                    enabled: Some(true),
                    url: Some(pac_url.to_owned()),
                },
            )?;
            Ok(())
        })();
        let result = result.and_then(|()| verify_active_pac(&service_id, pac_url));
        if let Err(error) = result {
            if let Err(rollback) = guard.restore() {
                return Err(error).context(format!("还原 macOS 代理失败：{rollback:#}"));
            }
            return Err(error);
        }
        Ok(guard)
    }

    pub(crate) fn restore(&mut self) -> Result<()> {
        if let Some(recovery) = &self.recovery {
            restore_owned(recovery, &self.authorization)?;
            remove_recovery(&self.path)?;
            self.recovery = None;
        }
        Ok(())
    }

    pub(crate) fn recover_stale() -> Result<()> {
        let folder = desktop_settings::directory()?;
        let path = folder.join(RECOVERY_FILE);
        if !path.try_exists()? {
            return Ok(());
        }
        let Some(_lock) = acquire_lock(&folder)? else {
            return Ok(());
        };
        if let Some(recovery) = read_recovery(&path)? {
            if requires_restore(&recovery)? {
                // Opening the app alone must not display an administrator prompt.
                let authorization = Authorization::network(false)
                    .context("还原上次代理需要 macOS 网络设置授权，请点击连接以完成授权")?;
                restore_owned(&recovery, &authorization)?;
            }
            remove_recovery(&path)?;
        }
        Ok(())
    }
}

impl Drop for SystemProxy {
    fn drop(&mut self) {
        if let Err(error) = self.restore() {
            eprintln!("恢复 macOS 系统代理失败：{error:#}");
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
        .context("无法打开 macOS 代理会话锁")?;
    match file.try_lock() {
        Ok(()) => Ok(Some(file)),
        Err(TryLockError::WouldBlock) => Ok(None),
        Err(TryLockError::Error(error)) => Err(error).context("无法锁定 macOS 代理会话"),
    }
}

fn validate_url(pac_url: &str) -> Result<()> {
    let reason = "系统代理仅接受本会话的回环 PAC 地址";
    let url = Url::parse(pac_url).context(reason)?;
    let port = url.port().filter(|&port| port != 0).context(reason)?;
    ensure!(
        pac_url == format!("http://127.0.0.1:{port}{PAC_PATH}"),
        reason
    );
    Ok(())
}

fn valid_service(service: &str) -> bool {
    service.len() == 36
        && service.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

fn read_recovery(path: &Path) -> Result<Option<Recovery>> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("无法读取 macOS 代理恢复记录"),
    };
    let recovery: Recovery = serde_json::from_slice(&bytes).context("macOS 代理恢复记录无效")?;
    validate_url(&recovery.pac_url)?;
    ensure!(
        valid_service(&recovery.service_id),
        "macOS 网络服务标识无效"
    );
    Ok(Some(recovery))
}

fn save_recovery(folder: &Path, path: &Path, recovery: &Recovery) -> Result<()> {
    let file = tempfile::NamedTempFile::new_in(folder).context("无法创建 macOS 代理恢复记录")?;
    serde_json::to_writer(file.as_file(), recovery)?;
    file.as_file().sync_all()?;
    file.persist_noclobber(path)
        .context("无法保存 macOS 代理恢复记录")?;
    Ok(())
}

fn remove_recovery(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("无法清理 macOS 代理恢复记录"),
    }
}

fn active_service() -> Result<String> {
    fn primary(key: &str) -> Result<Option<String>> {
        let key = cf_string(key)?;
        let value = unsafe { SCDynamicStoreCopyValue(null(), key.get()) };
        if value.is_null() {
            return Ok(None);
        }
        let dictionary = Owned::new(value, "无法读取默认网络服务")?;
        dictionary_value(dictionary.get(), "PrimaryService")?
            .map(string_value)
            .transpose()
    }
    let ipv4 = primary("State:/Network/Global/IPv4")?;
    let ipv6 = primary("State:/Network/Global/IPv6")?;
    if let (Some(a), Some(b)) = (&ipv4, &ipv6) {
        ensure!(
            a == b,
            "IPv4 和 IPv6 使用不同默认网络服务，无法安全选择代理配置"
        );
    }
    let service = ipv4
        .or(ipv6)
        .context("macOS 没有可识别的活动默认网络服务")?;
    ensure!(valid_service(&service), "默认网络服务标识无效");
    Ok(service)
}

fn effective_proxies() -> Result<Owned> {
    Owned::new(
        unsafe { SCDynamicStoreCopyProxies(null()) },
        "无法读取 macOS 当前生效的代理",
    )
}

fn ensure_direct(dictionary: Cf) -> Result<PacState> {
    let state = pac_state(dictionary)?;
    ensure!(
        state.enabled != Some(true)
            && state.url.as_deref().is_none_or(str::is_empty)
            && dictionary_value(dictionary, "ProxyAutoConfigJavaScript")?.is_none(),
        "网络服务已有 PAC 配置，请先检查 macOS 网络代理设置"
    );
    for key in [
        "HTTPEnable",
        "HTTPSEnable",
        "SOCKSEnable",
        "FTPEnable",
        "RTSPEnable",
        "GopherEnable",
        "ProxyAutoDiscoveryEnable",
    ] {
        ensure!(
            bool_value(dictionary, key)? != Some(true),
            "网络服务已启用代理或自动发现，请先检查 macOS 网络代理设置"
        );
    }
    Ok(state)
}

fn verify_active_pac(service: &str, pac_url: &str) -> Result<()> {
    for _ in 0..20 {
        ensure!(
            active_service()? == service,
            "当前网络服务已切换，请重新连接"
        );
        let state = pac_state(effective_proxies()?.get())?;
        if state.enabled == Some(true) && state.url.as_deref() == Some(pac_url) {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }
    bail!("macOS 当前网络没有启用 V5VPN 代理脚本，请检查管理策略")
}

fn requires_restore(recovery: &Recovery) -> Result<bool> {
    let prefs = Preferences::read()?;
    if let Some(protocol) = prefs.protocol(&recovery.service_id)? {
        let state = pac_state(configuration(&protocol)?)?;
        return Ok(
            recovery.owns(&state) || (state == recovery.original() && effective_owned(recovery)?)
        );
    }
    Ok(false)
}

fn effective_owned(recovery: &Recovery) -> Result<bool> {
    // Compare the service as well as the URL to avoid updating another active connection.
    if active_service().as_deref().ok() != Some(recovery.service_id.as_str()) {
        return Ok(false);
    }
    Ok(recovery.owns(&pac_state(effective_proxies()?.get())?))
}

fn restore_owned(recovery: &Recovery, authorization: &Authorization) -> Result<()> {
    if !requires_restore(recovery)? {
        return Ok(());
    }
    let prefs = Preferences::update(authorization)?;
    if let Some(protocol) = prefs.protocol(&recovery.service_id)? {
        let config = configuration(&protocol)?;
        let state = pac_state(config)?;
        if recovery.owns(&state) {
            prefs.write_pac(&protocol, config, recovery.original())?;
        } else if state == recovery.original() && effective_owned(recovery)? {
            // A prior rollback committed the original values but did not apply them.
            prefs.apply()?;
        }
    }
    Ok(())
}

fn pac_state(dictionary: Cf) -> Result<PacState> {
    Ok(PacState {
        enabled: bool_value(dictionary, PAC_ENABLE)?,
        url: dictionary_value(dictionary, PAC_URL)?
            .map(string_value)
            .transpose()?,
    })
}

fn bool_value(dictionary: Cf, key: &str) -> Result<Option<bool>> {
    let Some(value) = dictionary_value(dictionary, key)? else {
        return Ok(None);
    };
    let mut integer = 0i32;
    unsafe {
        ensure!(
            CFGetTypeID(value) == CFNumberGetTypeID()
                && CFNumberGetValue(value, SINT32, (&mut integer as *mut i32).cast()) != 0
                && matches!(integer, 0 | 1),
            "macOS 代理配置的开关格式无效"
        );
    }
    Ok(Some(integer != 0))
}

struct Preferences {
    value: Owned,
    locked: bool,
}

impl Preferences {
    fn read() -> Result<Self> {
        Self::open(None)
    }

    fn update(authorization: &Authorization) -> Result<Self> {
        let mut prefs = Self::open(Some(authorization))?;
        sc_status(
            unsafe { SCPreferencesLock(prefs.value.get(), 0) },
            "无法锁定 macOS 网络设置，请检查授权或网络管理策略",
        )?;
        prefs.locked = true;
        Ok(prefs)
    }

    fn open(authorization: Option<&Authorization>) -> Result<Self> {
        let name = cf_string("V5VPN Desktop")?;
        let value = unsafe {
            match authorization {
                Some(auth) => {
                    SCPreferencesCreateWithAuthorization(null(), name.get(), null(), auth.0)
                }
                None => SCPreferencesCreate(null(), name.get(), null()),
            }
        };
        Ok(Self {
            value: Owned::new(value, "无法读取 macOS 网络设置")?,
            locked: false,
        })
    }

    fn protocol(&self, service_id: &str) -> Result<Option<Owned>> {
        let id = cf_string(service_id)?;
        let value = unsafe { SCNetworkServiceCopy(self.value.get(), id.get()) };
        if value.is_null() {
            return Ok(None);
        }
        let service = Owned::new(value, "无法读取 macOS 网络服务")?;
        let value =
            unsafe { SCNetworkServiceCopyProtocol(service.get(), kSCNetworkProtocolTypeProxies) };
        Ok(Some(Owned::new(
            value,
            "无法读取 macOS 网络服务的代理协议",
        )?))
    }

    fn write_pac(&self, protocol: &Owned, config: Cf, state: PacState) -> Result<()> {
        let dictionary = Owned::new(
            unsafe { CFDictionaryCreateMutableCopy(null(), 0, config) }.cast_const(),
            "无法复制 macOS 代理设置",
        )?;
        let mutable = dictionary.get().cast_mut();
        let enable_key = cf_string(PAC_ENABLE)?;
        let url_key = cf_string(PAC_URL)?;
        if let Some(enabled) = state.enabled {
            let number = i32::from(enabled);
            let value = Owned::new(
                unsafe { CFNumberCreate(null(), SINT32, (&number as *const i32).cast()) },
                "无法创建 macOS 代理开关",
            )?;
            unsafe {
                CFDictionarySetValue(mutable, enable_key.get(), value.get());
            }
        } else {
            unsafe {
                CFDictionaryRemoveValue(mutable, enable_key.get());
            }
        }
        if let Some(url) = state.url {
            let value = cf_string(&url)?;
            unsafe {
                CFDictionarySetValue(mutable, url_key.get(), value.get());
            }
        } else {
            unsafe {
                CFDictionaryRemoveValue(mutable, url_key.get());
            }
        }
        sc_status(
            unsafe { SCNetworkProtocolSetConfiguration(protocol.get(), dictionary.get()) },
            "无法修改当前 macOS 网络服务的 PAC",
        )?;
        sc_status(
            unsafe { SCPreferencesCommitChanges(self.value.get()) },
            "无法保存 macOS 网络设置，请检查授权或网络管理策略",
        )?;
        self.apply()
    }

    fn apply(&self) -> Result<()> {
        sc_status(
            unsafe { SCPreferencesApplyChanges(self.value.get()) },
            "无法应用 macOS 网络设置",
        )
    }
}

impl Drop for Preferences {
    fn drop(&mut self) {
        if self.locked {
            unsafe {
                SCPreferencesUnlock(self.value.get());
            }
        }
    }
}

fn configuration(protocol: &Owned) -> Result<Cf> {
    let value = unsafe { SCNetworkProtocolGetConfiguration(protocol.get()) };
    ensure!(!value.is_null(), "无法读取 macOS 系统代理配置");
    Ok(value)
}

fn sc_status(status: u8, message: &str) -> Result<()> {
    if status == 0 {
        bail!("{message}（状态 {}）", unsafe { SCError() });
    }
    Ok(())
}

struct Authorization(*mut c_void);

impl Authorization {
    fn network(interactive: bool) -> Result<Self> {
        const EXTEND_RIGHTS: u32 = 1 << 1;
        const INTERACTION_ALLOWED: u32 = 1 << 0;
        let mut handle = null_mut();
        let status = unsafe { AuthorizationCreate(null(), null(), 0, &mut handle) };
        ensure!(
            status == 0 && !handle.is_null(),
            "无法创建 macOS 授权会话（状态 {status}）"
        );
        let auth = Self(handle);
        let mut item = AuthorizationItem {
            name: c"system.services.systemconfiguration.network".as_ptr(),
            value_length: 0,
            value: null_mut(),
            flags: 0,
        };
        let rights = AuthorizationItemSet {
            count: 1,
            items: &mut item,
        };
        let flags = EXTEND_RIGHTS | if interactive { INTERACTION_ALLOWED } else { 0 };
        let status = unsafe { AuthorizationCopyRights(auth.0, &rights, null(), flags, null_mut()) };
        ensure!(
            status == 0,
            "未取得 macOS 网络设置管理员授权（状态 {status}）"
        );
        Ok(auth)
    }
}

impl Drop for Authorization {
    fn drop(&mut self) {
        unsafe {
            AuthorizationFree(self.0, 0);
        }
    }
}

type Cf = *const c_void;

struct Owned(Cf);

impl Owned {
    fn new(value: Cf, message: &str) -> Result<Self> {
        ensure!(!value.is_null(), "{message}");
        Ok(Self(value))
    }

    fn get(&self) -> Cf {
        self.0
    }
}

impl Drop for Owned {
    fn drop(&mut self) {
        unsafe {
            CFRelease(self.0);
        }
    }
}

fn cf_string(value: &str) -> Result<Owned> {
    Owned::new(
        unsafe { CFStringCreateWithBytes(null(), value.as_ptr(), value.len() as isize, UTF8, 0) },
        "无法创建 macOS 配置字符串",
    )
}

fn dictionary_value(dictionary: Cf, key: &str) -> Result<Option<Cf>> {
    let key = cf_string(key)?;
    unsafe {
        ensure!(
            !dictionary.is_null() && CFGetTypeID(dictionary) == CFDictionaryGetTypeID(),
            "macOS 网络配置格式无效"
        );
        let value = CFDictionaryGetValue(dictionary, key.get());
        Ok((!value.is_null()).then_some(value))
    }
}

fn string_value(value: Cf) -> Result<String> {
    unsafe {
        ensure!(
            CFGetTypeID(value) == CFStringGetTypeID(),
            "macOS 网络配置字符串格式无效"
        );
        let size = CFStringGetMaximumSizeForEncoding(CFStringGetLength(value), UTF8);
        ensure!((0..=16384).contains(&size), "macOS 网络配置字符串过长");
        let mut buffer = vec![0u8; size as usize + 1];
        ensure!(
            CFStringGetCString(
                value,
                buffer.as_mut_ptr().cast(),
                buffer.len() as isize,
                UTF8
            ) != 0,
            "无法读取 macOS 网络配置字符串"
        );
        Ok(CStr::from_ptr(buffer.as_ptr().cast()).to_str()?.to_owned())
    }
}

#[repr(C)]
struct AuthorizationItem {
    name: *const c_char,
    value_length: usize,
    value: *mut c_void,
    flags: u32,
}

#[repr(C)]
struct AuthorizationItemSet {
    count: u32,
    items: *mut AuthorizationItem,
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFRelease(value: Cf);
    fn CFGetTypeID(value: Cf) -> usize;
    fn CFStringGetTypeID() -> usize;
    fn CFStringCreateWithBytes(
        allocator: Cf,
        value: *const u8,
        size: isize,
        encoding: u32,
        external: u8,
    ) -> Cf;
    fn CFStringGetLength(value: Cf) -> isize;
    fn CFStringGetMaximumSizeForEncoding(length: isize, encoding: u32) -> isize;
    fn CFStringGetCString(value: Cf, buffer: *mut c_char, size: isize, encoding: u32) -> u8;
    fn CFDictionaryGetTypeID() -> usize;
    fn CFDictionaryGetValue(dictionary: Cf, key: Cf) -> Cf;
    fn CFDictionaryCreateMutableCopy(allocator: Cf, capacity: isize, dictionary: Cf)
    -> *mut c_void;
    fn CFDictionarySetValue(dictionary: *mut c_void, key: Cf, value: Cf);
    fn CFDictionaryRemoveValue(dictionary: *mut c_void, key: Cf);
    fn CFNumberGetTypeID() -> usize;
    fn CFNumberGetValue(value: Cf, number_type: isize, output: *mut c_void) -> u8;
    fn CFNumberCreate(allocator: Cf, number_type: isize, value: Cf) -> Cf;
}

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    fn AuthorizationCreate(
        rights: *const AuthorizationItemSet,
        environment: *const AuthorizationItemSet,
        flags: u32,
        output: *mut *mut c_void,
    ) -> i32;
    fn AuthorizationCopyRights(
        auth: *mut c_void,
        rights: *const AuthorizationItemSet,
        environment: *const AuthorizationItemSet,
        flags: u32,
        granted: *mut *mut AuthorizationItemSet,
    ) -> i32;
    fn AuthorizationFree(auth: *mut c_void, flags: u32) -> i32;
}

#[link(name = "SystemConfiguration", kind = "framework")]
unsafe extern "C" {
    static kSCNetworkProtocolTypeProxies: Cf;
    fn SCError() -> i32;
    fn SCDynamicStoreCopyValue(store: Cf, key: Cf) -> Cf;
    fn SCDynamicStoreCopyProxies(store: Cf) -> Cf;
    fn SCPreferencesCreate(allocator: Cf, name: Cf, prefs_id: Cf) -> Cf;
    fn SCPreferencesCreateWithAuthorization(
        allocator: Cf,
        name: Cf,
        prefs_id: Cf,
        auth: *mut c_void,
    ) -> Cf;
    fn SCPreferencesLock(prefs: Cf, wait: u8) -> u8;
    fn SCPreferencesUnlock(prefs: Cf) -> u8;
    fn SCPreferencesCommitChanges(prefs: Cf) -> u8;
    fn SCPreferencesApplyChanges(prefs: Cf) -> u8;
    fn SCNetworkServiceCopy(prefs: Cf, service_id: Cf) -> Cf;
    fn SCNetworkServiceCopyProtocol(service: Cf, protocol: Cf) -> Cf;
    fn SCNetworkProtocolGetEnabled(protocol: Cf) -> u8;
    fn SCNetworkProtocolGetConfiguration(protocol: Cf) -> Cf;
    fn SCNetworkProtocolSetConfiguration(protocol: Cf, configuration: Cf) -> u8;
}
