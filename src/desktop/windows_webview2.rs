use std::{
    fs::{File, OpenOptions},
    io::Write,
    mem::size_of,
    os::windows::{ffi::OsStrExt, fs::OpenOptionsExt, io::AsRawHandle},
    path::Path,
    process::Stdio,
    ptr::{null, null_mut},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use reqwest::{Url, redirect};
use windows_sys::{
    Win32::{
        Foundation::{HANDLE, HWND, INVALID_HANDLE_VALUE},
        Security::{
            Cryptography::{
                CERT_CHAIN_POLICY_MICROSOFT_ROOT, CERT_CHAIN_POLICY_PARA, CERT_CHAIN_POLICY_STATUS,
                CERT_NAME_ATTR_TYPE, CertGetNameStringW, CertVerifyCertificateChainPolicy,
                MICROSOFT_ROOT_CERT_CHAIN_POLICY_CHECK_APPLICATION_ROOT_FLAG, szOID_COMMON_NAME,
            },
            WinTrust::{
                WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0,
                WINTRUST_FILE_INFO, WTD_CHOICE_FILE, WTD_DISABLE_MD2_MD4, WTD_MOTW,
                WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, WTD_REVOKE_WHOLECHAIN,
                WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE, WTD_UICONTEXT_INSTALL,
                WTHelperGetProvCertFromChain, WTHelperGetProvSignerFromChain,
                WTHelperProvDataFromStateData, WinVerifyTrust,
            },
        },
        System::Threading::CREATE_NO_WINDOW,
        UI::WindowsAndMessaging::{
            CreateWindowExW, DestroyWindow, DispatchMessageW, GetSystemMetrics, MSG, PM_REMOVE,
            PeekMessageW, SM_CXSCREEN, SM_CYSCREEN, TranslateMessage, WS_EX_APPWINDOW,
            WS_EX_DLGMODALFRAME, WS_POPUP, WS_VISIBLE,
        },
    },
    core::w,
};

// Microsoft WebView2 SDK sample AppWindow.cpp uses this Evergreen Bootstrapper URL.
const INSTALLER_URL: &str = "https://go.microsoft.com/fwlink/p/?LinkId=2124703";
const INSTALLER_NAME: &str = "MicrosoftEdgeWebview2Setup.exe";
const DOWNLOAD_LIMIT: u64 = 8 * 1024 * 1024;
const INSTALL_TIMEOUT: Duration = Duration::from_secs(600);
// Keep the file readable but deny writes and deletions while verifying and launching it.
const FILE_SHARE_READ: u32 = 0x0000_0001;

pub(super) fn ensure_runtime() -> Result<()> {
    if runtime_available() {
        return Ok(());
    }

    let progress = InstallProgress::show();
    let worker = thread::Builder::new()
        .name("v5vpn-webview2-setup".into())
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("无法启动 WebView2 安装任务")?
                .block_on(install_runtime())
        })
        .context("无法启动 WebView2 安装线程")?;
    while !worker.is_finished() {
        progress.pump_messages();
        thread::sleep(Duration::from_millis(25));
    }
    worker
        .join()
        .map_err(|_| anyhow::anyhow!("WebView2 安装线程异常退出"))?
}

fn runtime_available() -> bool {
    wry::webview_version().is_ok_and(|version| !version.trim().is_empty())
}

async fn install_runtime() -> Result<()> {
    let directory = tempfile::Builder::new()
        .prefix("v5vpn-webview2-")
        .tempdir()
        .context("无法创建 WebView2 安装临时目录")?;
    let installer = directory.path().join(INSTALLER_NAME);
    download_installer(&installer).await?;
    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(&installer)
        .context("无法读取 WebView2 安装程序")?;
    verify_signature(&installer, &file)?;
    if runtime_available() {
        return Ok(());
    }

    let mut child = tokio::process::Command::new(&installer)
        .args(["/silent", "/install"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .context("无法启动微软 WebView2 安装程序")?;
    let status = match tokio::time::timeout(INSTALL_TIMEOUT, child.wait()).await {
        Ok(result) => result.context("无法取得 WebView2 安装结果")?,
        Err(_) => {
            drop(file);
            // The official installer may still be finishing. Leave its own file available.
            let _ = directory.keep();
            bail!("WebView2 安装程序仍在运行，请稍后重新打开客户端");
        }
    };
    drop(file);

    let deadline = Instant::now() + Duration::from_secs(10);
    while !runtime_available() {
        if Instant::now() >= deadline {
            bail!("WebView2 安装后仍无法检测到可用运行时（退出状态 {status}）");
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    Ok(())
}

fn official_download_origin(url: &Url) -> bool {
    url.scheme() == "https"
        && url.port_or_known_default() == Some(443)
        && url.username().is_empty()
        && url.password().is_none()
        && url.host_str().is_some_and(|host| {
            host == "go.microsoft.com" || host.ends_with(".dl.delivery.mp.microsoft.com")
        })
}

async fn download_installer(path: &Path) -> Result<()> {
    let client = reqwest::Client::builder()
        .https_only(true)
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(120))
        .redirect(redirect::Policy::custom(|attempt| {
            if attempt.previous().len() >= 8 || !official_download_origin(attempt.url()) {
                attempt.error("WebView2 下载地址未指向微软的 HTTPS 分发服务")
            } else {
                attempt.follow()
            }
        }))
        .build()
        .context("无法初始化 WebView2 HTTPS 下载")?;
    let mut response = client
        .get(INSTALLER_URL)
        .send()
        .await
        .context("从微软下载 WebView2 安装程序失败")?
        .error_for_status()
        .context("微软 WebView2 下载服务返回错误")?;
    ensure!(
        !response
            .content_length()
            .is_some_and(|size| size > DOWNLOAD_LIMIT),
        "WebView2 安装程序超过预期大小"
    );

    let mut file = File::create_new(path).context("无法创建 WebView2 安装程序文件")?;
    let mut bytes = 0;
    while let Some(chunk) = response
        .chunk()
        .await
        .context("WebView2 安装程序下载中断")?
    {
        bytes += chunk.len() as u64;
        ensure!(bytes <= DOWNLOAD_LIMIT, "WebView2 安装程序超过预期大小");
        file.write_all(&chunk)
            .context("无法写入 WebView2 安装程序")?;
    }
    ensure!(bytes > 0, "微软下载服务返回了空的安装程序");
    file.flush().context("无法完成 WebView2 安装程序写入")
}

fn verify_signature(path: &Path, file: &File) -> Result<()> {
    let path = path
        .as_os_str()
        .encode_wide()
        .chain([0])
        .collect::<Vec<_>>();
    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: path.as_ptr(),
        hFile: file.as_raw_handle(),
        ..Default::default()
    };
    let mut trust = WINTRUST_DATA {
        cbStruct: size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_WHOLECHAIN,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 {
            pFile: &mut file_info,
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT | WTD_DISABLE_MD2_MD4 | WTD_MOTW,
        dwUIContext: WTD_UICONTEXT_INSTALL,
        ..Default::default()
    };
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    // The path, open file handle and nested trust data remain live until WinVerifyTrust closes them.
    let status = unsafe {
        WinVerifyTrust(
            INVALID_HANDLE_VALUE,
            &mut action,
            (&mut trust as *mut WINTRUST_DATA).cast(),
        )
    };
    let result = if status == 0 {
        verify_microsoft_publisher(trust.hWVTStateData)
    } else {
        Err(anyhow::anyhow!(
            "WebView2 安装程序未通过 Authenticode 校验（0x{:08X}）",
            status as u32
        ))
    };
    trust.dwStateAction = WTD_STATEACTION_CLOSE;
    unsafe {
        WinVerifyTrust(
            INVALID_HANDLE_VALUE,
            &mut action,
            (&mut trust as *mut WINTRUST_DATA).cast(),
        )
    };
    result
}

fn verify_microsoft_publisher(state: HANDLE) -> Result<()> {
    // These pointers are owned by the state returned from the successful WinVerifyTrust call.
    let provider = unsafe { WTHelperProvDataFromStateData(state) };
    ensure!(!provider.is_null(), "无法读取 WebView2 安装程序的签名信息");
    let signer = unsafe { WTHelperGetProvSignerFromChain(provider, 0, 0, 0) };
    let chain = unsafe { signer.as_ref() }
        .context("无法读取 WebView2 安装程序的签名者")?
        .pChainContext;
    let leaf = unsafe { WTHelperGetProvCertFromChain(signer, 0).as_ref() }
        .context("无法读取 WebView2 安装程序的签名证书")?;
    ensure!(
        !leaf.pCert.is_null() && !chain.is_null(),
        "WebView2 安装程序的证书链不完整"
    );

    let mut publisher = [0_u16; 128];
    let len = unsafe {
        CertGetNameStringW(
            leaf.pCert,
            CERT_NAME_ATTR_TYPE,
            0,
            szOID_COMMON_NAME.cast(),
            publisher.as_mut_ptr(),
            publisher.len() as u32,
        )
    };
    ensure!(
        len > 1
            && len as usize <= publisher.len()
            && publisher[..len as usize - 1]
                .iter()
                .copied()
                .eq("Microsoft Corporation".encode_utf16()),
        "WebView2 安装程序的签名发布者不是 Microsoft Corporation"
    );

    let trusted = [
        0,
        MICROSOFT_ROOT_CERT_CHAIN_POLICY_CHECK_APPLICATION_ROOT_FLAG,
    ]
    .into_iter()
    .any(|flags| {
        let policy = CERT_CHAIN_POLICY_PARA {
            cbSize: size_of::<CERT_CHAIN_POLICY_PARA>() as u32,
            dwFlags: flags,
            ..Default::default()
        };
        let mut status = CERT_CHAIN_POLICY_STATUS {
            cbSize: size_of::<CERT_CHAIN_POLICY_STATUS>() as u32,
            ..Default::default()
        };
        let ok = unsafe {
            CertVerifyCertificateChainPolicy(
                CERT_CHAIN_POLICY_MICROSOFT_ROOT,
                chain,
                &policy,
                &mut status,
            )
        };
        ok != 0 && status.dwError == 0
    });
    ensure!(trusted, "WebView2 安装程序的签名链未连接到微软根证书");
    Ok(())
}

struct InstallProgress(HWND);

impl InstallProgress {
    fn show() -> Self {
        const WIDTH: i32 = 500;
        const HEIGHT: i32 = 96;
        // Predefined STATIC window styles SS_CENTER and SS_CENTERIMAGE.
        const CENTERED_TEXT: u32 = 0x0000_0201;
        let window = unsafe {
            CreateWindowExW(
                WS_EX_DLGMODALFRAME | WS_EX_APPWINDOW,
                w!("STATIC"),
                w!("正在为 V5VPN 下载并安装 WebView2，请稍候…"),
                WS_POPUP | WS_VISIBLE | CENTERED_TEXT,
                (GetSystemMetrics(SM_CXSCREEN) - WIDTH) / 2,
                (GetSystemMetrics(SM_CYSCREEN) - HEIGHT) / 2,
                WIDTH,
                HEIGHT,
                null_mut(),
                null_mut(),
                null_mut(),
                null(),
            )
        };
        Self(window)
    }

    fn pump_messages(&self) {
        if self.0.is_null() {
            return;
        }
        let mut message = MSG::default();
        unsafe {
            while PeekMessageW(&mut message, self.0, 0, 0, PM_REMOVE) != 0 {
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }
    }
}

impl Drop for InstallProgress {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { DestroyWindow(self.0) };
        }
    }
}
