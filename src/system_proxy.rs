use anyhow::Result;

#[cfg(windows)]
#[path = "system_proxy_windows.rs"]
mod platform;
#[cfg(target_os = "macos")]
#[path = "system_proxy_macos.rs"]
mod platform;

pub struct SystemProxyGuard {
    #[cfg(any(windows, target_os = "macos"))]
    proxy: platform::SystemProxy,
}

impl SystemProxyGuard {
    pub fn recover_stale() -> Result<()> {
        #[cfg(any(windows, target_os = "macos"))]
        {
            platform::SystemProxy::recover_stale()
        }
        #[cfg(not(any(windows, target_os = "macos")))]
        {
            Ok(())
        }
    }

    pub(crate) fn activate(pac_url: &str) -> Result<Self> {
        #[cfg(any(windows, target_os = "macos"))]
        {
            Ok(Self {
                proxy: platform::SystemProxy::activate(pac_url)?,
            })
        }
        #[cfg(not(any(windows, target_os = "macos")))]
        {
            let _ = pac_url;
            anyhow::bail!("系统代理接入支持 Windows 和 macOS");
        }
    }

    pub(crate) fn restore(&mut self) -> Result<()> {
        #[cfg(any(windows, target_os = "macos"))]
        {
            self.proxy.restore()
        }
        #[cfg(not(any(windows, target_os = "macos")))]
        {
            Ok(())
        }
    }
}
