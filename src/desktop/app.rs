use std::{
    borrow::Cow,
    net::Ipv6Addr,
    sync::mpsc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Deserializer, Serialize};
use tao::{
    dpi::LogicalSize,
    event::{Event, WindowEvent},
    event_loop::{ControlFlow, EventLoopBuilder, EventLoopProxy},
    window::WindowBuilder,
};
use url::{Host, Url};
use v5vpn_client::{
    SystemProxyGuard, desktop_credentials,
    desktop_settings::{self, DesktopSettings, GatewayProfile, SavedAccount},
    session::{GatewayConfig, NcStatus},
};
use wry::{
    NewWindowResponse, WebContext, WebViewBuilder,
    http::{HeaderValue, Method, Response, StatusCode, header},
};
use zeroize::Zeroizing;

#[path = "connection.rs"]
mod connection;

use connection::{Worker, WorkerEvent};

const TITLE: &str = "V5VPN 客户端";
const PAGE_URL: &str = "v5vpn://localhost/index.html";
#[cfg(windows)]
const VIEW_URL: &str = "https://v5vpn.localhost/index.html";
#[cfg(target_os = "macos")]
const VIEW_URL: &str = PAGE_URL;
const ICON: &[u8] = include_bytes!("../../assets/v5vpn.png");
const PAGE: &str = include_str!("../desktop.html");

pub(super) fn run() -> Result<()> {
    let events = EventLoopBuilder::<AppEvent>::with_user_event().build();
    let event_proxy = events.create_proxy();
    let window = WindowBuilder::new()
        .with_title(TITLE)
        .with_decorations(false)
        .with_inner_size(LogicalSize::new(880, 612))
        .with_min_inner_size(LogicalSize::new(620, 520))
        .with_visible(false);

    #[cfg(windows)]
    let window = {
        use tao::{platform::windows::WindowBuilderExtWindows, window::Icon};

        let image =
            image::load_from_memory_with_format(ICON, image::ImageFormat::Png)?.into_rgba8();
        let (width, height) = image.dimensions();
        let icon = Icon::from_rgba(image.into_raw(), width, height)?;
        window
            .with_window_icon(Some(icon.clone()))
            .with_taskbar_icon(Some(icon))
    };
    let window = window.build(&events).context("无法创建客户端窗口")?;
    let mut desktop = Desktop::new();
    let html = PAGE.replace(
        "V5VPN_APP_ICON_DATA",
        &format!("data:image/png;base64,{}", STANDARD.encode(ICON)),
    );
    let profile_path = desktop_settings::directory()?.join("WebView");
    #[cfg(windows)]
    std::fs::create_dir_all(&profile_path).context("无法创建 WebView2 用户数据目录")?;
    let mut web_context = WebContext::new(Some(profile_path));
    let ipc = event_proxy.clone();
    let view = WebViewBuilder::new_with_web_context(&mut web_context)
        .with_custom_protocol("v5vpn".into(), move |_, request| {
            if request.method() != Method::GET || request.uri() != PAGE_URL {
                let mut response = Response::new(Cow::Borrowed(&[][..]));
                *response.status_mut() = StatusCode::NOT_FOUND;
                return response;
            }
            let mut response = Response::new(Cow::Owned(html.as_bytes().to_vec()));
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/html; charset=utf-8"),
            );
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response
        })
        .with_url(PAGE_URL)
        .with_incognito(true)
        .with_devtools(false)
        .with_autoplay(false)
        .with_hotkeys_zoom(false)
        .with_navigation_handler(|url| url == VIEW_URL)
        .with_new_window_req_handler(|_, _| NewWindowResponse::Deny)
        .with_ipc_handler(move |request| {
            if request.uri() != VIEW_URL {
                return;
            }
            let body = Zeroizing::new(request.into_body());
            if body.len() <= 128 * 1024
                && let Ok(action) = serde_json::from_str(&body)
            {
                let _ = ipc.send_event(AppEvent::Action(action));
            }
        });

    #[cfg(windows)]
    let view = {
        use wry::WebViewBuilderExtWindows;
        view.with_browser_accelerator_keys(false)
            .with_additional_browser_args("")
            .with_https_scheme(true)
    };
    let view = view.build(&window).context("无法启动系统 WebView")?;

    let mut ready = false;
    let startup_deadline = Instant::now() + Duration::from_secs(10);
    events.run(move |event, _, flow| {
        let _keep_web_context_alive = &web_context;
        if matches!(&event, Event::LoopDestroyed) {
            return;
        }
        let mut publish = true;
        match event {
            Event::UserEvent(AppEvent::Action(Action::Ready)) => {
                ready = true;
                window.set_visible(true);
            }
            Event::UserEvent(AppEvent::Action(Action::Minimize)) => window.set_minimized(true),
            Event::UserEvent(AppEvent::Action(Action::Drag)) => {
                let _ = window.drag_window();
            }
            Event::UserEvent(AppEvent::Action(Action::Close))
            | Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => {
                desktop.close_after_disconnect = true;
                desktop.disconnect();
            }
            Event::UserEvent(AppEvent::Action(action)) => desktop.act(action, &event_proxy),
            Event::UserEvent(AppEvent::Worker) => desktop.poll_worker(),
            _ => publish = false,
        }

        if desktop.close_after_disconnect && desktop.worker.is_none() {
            *flow = ControlFlow::Exit;
            return;
        }
        *flow = if ready {
            ControlFlow::Wait
        } else if Instant::now() < startup_deadline {
            ControlFlow::WaitUntil(startup_deadline)
        } else {
            show_startup_error("客户端界面未能完成加载。请关闭后重新启动。");
            ControlFlow::Exit
        };
        if publish
            && ready
            && let Ok(update) = serde_json::to_string(&desktop.state())
        {
            let _ = view.evaluate_script(&format!("window.v5vpnUpdate({update})"));
        }
    });
}

#[cfg(windows)]
pub(super) fn show_startup_error(message: &str) {
    use windows_sys::Win32::UI::WindowsAndMessaging::{MB_ICONERROR, MB_OK, MessageBoxW};

    let text = message.encode_utf16().chain([0]).collect::<Vec<_>>();
    let title = TITLE.encode_utf16().chain([0]).collect::<Vec<_>>();
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            text.as_ptr(),
            title.as_ptr(),
            MB_OK | MB_ICONERROR,
        )
    };
}

#[cfg(target_os = "macos")]
pub(super) fn show_startup_error(message: &str) {
    eprintln!("{TITLE}：{message}");
}

enum AppEvent {
    Action(Action),
    Worker,
}

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "camelCase")]
enum Action {
    Ready,
    SelectGateway {
        index: usize,
    },
    SaveSettings {
        profiles: Vec<VisibleGateway>,
        selected: usize,
    },
    Connect {
        username: String,
        #[serde(default, deserialize_with = "read_password")]
        password: Zeroizing<String>,
        remember: bool,
        #[serde(rename = "useSaved")]
        use_saved: bool,
    },
    Disconnect,
    ForgetAccount {
        username: String,
    },
    Minimize,
    Close,
    Drag,
}

fn read_password<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(deserializer).map(Zeroizing::new)
}

#[derive(Deserialize, Serialize)]
struct VisibleGateway {
    name: String,
    address: String,
    port: u16,
}

impl From<&GatewayProfile> for VisibleGateway {
    fn from(profile: &GatewayProfile) -> Self {
        Self {
            name: profile.name.clone(),
            address: profile.address.clone(),
            port: profile.port,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
enum Phase {
    Offline,
    Connecting,
    Online,
    Disconnecting,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct State<'a> {
    profiles: Vec<VisibleGateway>,
    selected: usize,
    accounts: Vec<&'a str>,
    phase: Phase,
    username: &'a str,
    error: Option<&'a str>,
    notice: Option<&'a str>,
    web_resources: bool,
    nc_status: &'static str,
    nc_error: Option<&'a str>,
    connected_seconds: u64,
}

struct Desktop {
    settings: DesktopSettings,
    username: String,
    phase: Phase,
    connected_since: Option<Instant>,
    web_resources: bool,
    nc_status: NcStatus,
    worker: Option<Worker>,
    close_after_disconnect: bool,
    pending_credential: Option<(SavedAccount, Option<Zeroizing<String>>)>,
    error: Option<String>,
    notice: Option<String>,
}

impl Desktop {
    fn new() -> Self {
        let error = SystemProxyGuard::recover_stale()
            .err()
            .map(|error| format!("无法恢复上次连接的系统代理：{error:#}"));
        Self {
            settings: desktop_settings::load(),
            username: String::new(),
            phase: Phase::Offline,
            connected_since: None,
            web_resources: false,
            nc_status: NcStatus::NotGranted,
            worker: None,
            close_after_disconnect: false,
            pending_credential: None,
            error,
            notice: None,
        }
    }

    fn state(&self) -> State<'_> {
        let accounts = self
            .selected_gateway()
            .map(|gateway| {
                self.settings
                    .saved_accounts
                    .iter()
                    .filter(|account| account.gateway == gateway.as_str())
                    .map(|account| account.username.as_str())
                    .collect()
            })
            .unwrap_or_default();
        let (nc_status, nc_error) = match &self.nc_status {
            NcStatus::NotGranted => ("notAuthorized", None),
            NcStatus::Connected => ("connected", None),
            NcStatus::Failed(error) => ("unavailable", Some(error.as_str())),
        };
        State {
            profiles: self.settings.profiles.iter().map(Into::into).collect(),
            selected: self.settings.selected,
            accounts,
            phase: self.phase,
            username: &self.username,
            error: self.error.as_deref(),
            notice: self.notice.as_deref(),
            web_resources: self.web_resources,
            nc_status,
            nc_error,
            connected_seconds: self
                .connected_since
                .map_or(0, |start| start.elapsed().as_secs()),
        }
    }

    fn selected_gateway(&self) -> Result<Url> {
        gateway_url(&self.settings.profiles[self.settings.selected])
    }

    fn act(&mut self, action: Action, proxy: &EventLoopProxy<AppEvent>) {
        match action {
            Action::Disconnect => self.disconnect(),
            action if self.phase == Phase::Offline => {
                self.error = None;
                self.notice = None;
                if let Err(error) = self.act_offline(action, proxy) {
                    self.error = Some(format!("{error:#}"));
                }
            }
            _ => {}
        }
    }

    fn act_offline(&mut self, action: Action, proxy: &EventLoopProxy<AppEvent>) -> Result<()> {
        match action {
            Action::SelectGateway { index } => {
                ensure!(index < self.settings.profiles.len(), "网关配置不存在");
                if index != self.settings.selected {
                    let mut updated = self.settings.clone();
                    updated.selected = index;
                    self.save_settings(updated)?;
                    self.username.clear();
                }
            }
            Action::SaveSettings { profiles, selected } => {
                self.update_profiles(profiles, selected)?
            }
            Action::Connect {
                username,
                password,
                remember,
                use_saved,
            } => self.connect(username, password, remember, use_saved, proxy)?,
            Action::ForgetAccount { username } => {
                let gateway = self.selected_gateway()?.to_string();
                self.forget(&SavedAccount { gateway, username })?;
                self.notice = Some("已移除保存的账号".into());
            }
            _ => {}
        }
        Ok(())
    }

    fn save_settings(&mut self, updated: DesktopSettings) -> Result<()> {
        desktop_settings::save(&updated)?;
        self.settings = updated;
        Ok(())
    }

    fn update_profiles(&mut self, profiles: Vec<VisibleGateway>, selected: usize) -> Result<()> {
        ensure!(selected < profiles.len(), "请至少保存一个网关");
        let previous_gateway = self.selected_gateway().ok();
        let mut updated = self.settings.clone();
        updated.profiles = profiles
            .into_iter()
            .enumerate()
            .map(|(index, visible)| {
                let result = (|| {
                    let mut profile = GatewayProfile {
                        name: visible.name.trim().to_owned(),
                        address: visible.address.trim().to_owned(),
                        port: visible.port,
                        ..Default::default()
                    };
                    ensure!(!profile.name.is_empty(), "请填写网关名称");
                    let endpoint = gateway_url(&profile)?;
                    let pin = self.settings.profiles.iter().find_map(|old| {
                        (!old.gateway_cert_sha256.trim().is_empty()
                            && gateway_url(old).ok().as_ref() == Some(&endpoint))
                        .then_some(&old.gateway_cert_sha256)
                    });
                    if let Some(pin) = pin {
                        profile.gateway_cert_sha256.clone_from(pin);
                    }
                    Ok(profile)
                })();
                result.with_context(|| format!("第 {} 个网关配置无效", index + 1))
            })
            .collect::<Result<_>>()?;
        updated.selected = selected;
        self.save_settings(updated)?;
        if self.selected_gateway().ok() != previous_gateway {
            self.username.clear();
        }
        self.notice = Some("设置已保存".into());
        Ok(())
    }

    fn connect(
        &mut self,
        username: String,
        mut password: Zeroizing<String>,
        remember: bool,
        use_saved: bool,
        proxy: &EventLoopProxy<AppEvent>,
    ) -> Result<()> {
        let username = username.trim();
        ensure!(!username.is_empty(), "请填写账号");
        let gateway = self.selected_gateway()?;
        let account = SavedAccount {
            gateway: gateway.to_string(),
            username: username.to_owned(),
        };
        let known = self.settings.saved_accounts.contains(&account);
        let using_saved = password.is_empty() && use_saved && known;
        if using_saved {
            password = desktop_credentials::load_password(&account.gateway, username)?
                .context("系统凭据库中没有该账号的口令，请重新输入")?;
        }
        ensure!(!password.is_empty(), "请填写口令");

        let pending_credential = match (remember, using_saved, known) {
            (true, false, _) => Some((account, Some(password.clone()))),
            (false, _, true) => Some((account, None)),
            _ => None,
        };
        let pin = self.settings.profiles[self.settings.selected]
            .gateway_cert_sha256
            .trim();
        let config = GatewayConfig {
            gateway,
            username: username.to_owned(),
            gateway_cert_sha256: (!pin.is_empty()).then(|| pin.to_owned()),
            ca_file: None,
        };
        let wake = proxy.clone();
        self.worker = Some(Worker::start(config, password, move || {
            let _ = wake.send_event(AppEvent::Worker);
        })?);
        self.pending_credential = pending_credential;
        self.username = username.to_owned();
        self.phase = Phase::Connecting;
        Ok(())
    }

    fn forget(&mut self, account: &SavedAccount) -> Result<()> {
        if !self.settings.saved_accounts.contains(account) {
            return Ok(());
        }
        let previous = self.settings.clone();
        let mut updated = previous.clone();
        updated.saved_accounts.retain(|saved| saved != account);
        self.save_settings(updated)?;
        if let Err(error) =
            desktop_credentials::delete_password(&account.gateway, &account.username)
        {
            if let Err(rollback) = self.save_settings(previous) {
                return Err(error)
                    .context(format!("移除口令失败，恢复账号列表也失败：{rollback:#}"));
            }
            return Err(error);
        }
        Ok(())
    }

    fn remember(&mut self, account: SavedAccount, password: &str) -> Result<()> {
        desktop_credentials::save_password(&account.gateway, &account.username, password)?;
        if !self.settings.saved_accounts.contains(&account) {
            let mut updated = self.settings.clone();
            updated.saved_accounts.push(account.clone());
            if let Err(error) = self.save_settings(updated) {
                if let Err(rollback) =
                    desktop_credentials::delete_password(&account.gateway, &account.username)
                {
                    return Err(error)
                        .context(format!("保存账号列表失败，撤回口令也失败：{rollback:#}"));
                }
                return Err(error);
            }
        }
        Ok(())
    }

    fn disconnect(&mut self) {
        if let Some(worker) = &mut self.worker {
            worker.stop();
            self.phase = Phase::Disconnecting;
            self.pending_credential = None;
            self.error = None;
            self.notice = None;
        }
    }

    fn poll_worker(&mut self) {
        while let Some(worker) = &self.worker {
            let event = match worker.events.try_recv() {
                Ok(event) => event,
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    WorkerEvent::Finished(Some("连接线程已退出".into()))
                }
            };
            match event {
                WorkerEvent::Connected {
                    web_resources,
                    nc_status,
                } if self.phase == Phase::Connecting => {
                    self.phase = Phase::Online;
                    self.connected_since = Some(Instant::now());
                    self.web_resources = web_resources;
                    self.nc_status = nc_status;
                    if let Some((account, password)) = self.pending_credential.take() {
                        let result = match password {
                            Some(password) => self.remember(account, &password),
                            None => self.forget(&account),
                        };
                        if let Err(error) = result {
                            self.notice = Some(format!("已连接，更新系统凭据失败：{error:#}"));
                        }
                    }
                }
                WorkerEvent::Connected { .. } => {}
                WorkerEvent::Finished(error) => {
                    self.worker = None;
                    self.pending_credential = None;
                    self.phase = Phase::Offline;
                    self.connected_since = None;
                    self.web_resources = false;
                    self.nc_status = NcStatus::NotGranted;
                    self.error = error;
                }
            }
        }
    }
}

impl Drop for Desktop {
    fn drop(&mut self) {
        if let Some(worker) = &mut self.worker {
            worker.stop();
        }
    }
}

fn gateway_url(profile: &GatewayProfile) -> Result<Url> {
    let address = profile.address.trim();
    ensure!(!address.is_empty(), "请填写网关地址");
    ensure!(profile.port != 0, "端口应为 1 到 65535");
    let host = match address.parse::<Ipv6Addr>() {
        Ok(ip) => Host::Ipv6(ip),
        Err(_) => Host::parse(address).context("请填写有效的网关 IP 或域名")?,
    };
    let endpoint = Url::parse(&format!("https://{host}:{}", profile.port))
        .context("无法解析网关 HTTPS 地址")?;
    if endpoint.host().is_none()
        || endpoint.path() != "/"
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
    {
        bail!("网关地址只填写 IP 或域名，端口单独填写");
    }
    Ok(endpoint)
}
