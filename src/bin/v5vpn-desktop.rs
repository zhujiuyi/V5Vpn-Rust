#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

#[cfg(any(windows, target_os = "macos"))]
#[path = "../desktop/app.rs"]
mod app;

#[cfg(any(windows, target_os = "macos"))]
fn main() {
    if let Err(error) = app::run() {
        app::show_startup_error(&format!("{error:#}"));
    }
}

#[cfg(not(any(windows, target_os = "macos")))]
fn main() {
    eprintln!("桌面客户端支持 Windows 和 macOS。");
}
