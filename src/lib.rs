pub mod browser;
pub mod desktop_credentials;
pub mod desktop_settings;
mod gateway_tls;
mod nc;
mod nc_policy;
#[cfg(any(windows, target_os = "macos"))]
mod nc_vici;
#[cfg(windows)]
mod nc_windows_routes;
mod portal;
mod proxy;
pub mod session;
mod system_proxy;

pub use system_proxy::SystemProxyGuard;
