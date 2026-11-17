use std::{
    env,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use reqwest::Url;
use tempfile::TempDir;
use tokio::process::{Child, Command};

pub fn executable(configured: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = configured {
        ensure!(path.is_file(), "指定的浏览器可执行文件不存在");
        return Ok(path);
    }
    candidates()
        .into_iter()
        .find(|path| path.is_file())
        .context("找不到 Edge 或 Chrome，请用 --browser 指定浏览器可执行文件")
}

pub fn launch(executable: &Path, pac_url: &str, resource: &Url) -> Result<(Child, TempDir)> {
    let profile = tempfile::Builder::new()
        .prefix("v5vpn-browser-")
        .tempdir()
        .context("无法创建独立浏览器配置目录")?;
    let mut profile_option = std::ffi::OsString::from("--user-data-dir=");
    profile_option.push(profile.path());
    let child = Command::new(executable)
        .arg(profile_option)
        .arg(format!("--proxy-pac-url={pac_url}"))
        .args([
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-background-networking",
        ])
        .arg(resource.as_str())
        .kill_on_drop(true)
        .spawn()
        .context("无法打开独立浏览器窗口")?;
    Ok((child, profile))
}

#[cfg(target_os = "windows")]
fn candidates() -> Vec<PathBuf> {
    ["ProgramFiles(x86)", "ProgramFiles", "LOCALAPPDATA"]
        .into_iter()
        .filter_map(env::var_os)
        .flat_map(|base| {
            let base = PathBuf::from(base);
            [
                base.join(r"Microsoft\Edge\Application\msedge.exe"),
                base.join(r"Google\Chrome\Application\chrome.exe"),
            ]
        })
        .collect()
}

#[cfg(target_os = "macos")]
fn candidates() -> Vec<PathBuf> {
    [
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    ]
    .into_iter()
    .map(PathBuf::from)
    .chain(env::var_os("HOME").into_iter().flat_map(|home| {
        let apps = PathBuf::from(home).join("Applications");
        [
            apps.join("Google Chrome.app/Contents/MacOS/Google Chrome"),
            apps.join("Microsoft Edge.app/Contents/MacOS/Microsoft Edge"),
        ]
    }))
    .collect()
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn candidates() -> Vec<PathBuf> {
    Vec::new()
}
