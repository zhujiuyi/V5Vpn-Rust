use std::{
    cell::RefCell,
    ffi::{c_char, c_void},
};

use anyhow::{Context, Result, ensure};
use objc2::{
    AnyThread, MainThreadMarker, MainThreadOnly,
    rc::Retained,
    runtime::{AnyObject, Sel},
    sel,
};
use objc2_app_kit::{NSApplication, NSEventModifierFlags, NSImage, NSMenu, NSMenuItem};
use objc2_foundation::{NSData, NSString};
use tao::event_loop::EventLoopProxy;

use super::{Action, AppEvent, ICON};

thread_local! {
    static QUIT_PROXY: RefCell<Option<EventLoopProxy<AppEvent>>> = const { RefCell::new(None) };
}

pub(super) struct MacApplication {
    _menu: Retained<NSMenu>,
}

impl MacApplication {
    pub(super) fn new(proxy: EventLoopProxy<AppEvent>) -> Result<Self> {
        let main = MainThreadMarker::new().context("macOS 菜单必须在主线程初始化")?;
        let app = NSApplication::sharedApplication(main);
        let delegate = app.delegate().context("macOS 应用委托尚未初始化")?;
        QUIT_PROXY.with(|value| *value.borrow_mut() = Some(proxy));

        // Add a deferred termination hook to Tao's existing delegate, preserving
        // all of its window/event-loop callbacks. Cocoa must not exit before the
        // worker has logged out, restored PAC and stopped the privileged helper.
        let delegate_object: &AnyObject = AsRef::<AnyObject>::as_ref(&*delegate);
        let class = delegate_object.class();
        unsafe {
            ensure!(
                class_addMethod(
                    (class as *const objc2::runtime::AnyClass).cast(),
                    sel!(v5vpnRequestQuit:),
                    quit_action as *const () as *const c_void,
                    c"v@:@".as_ptr(),
                ),
                "无法注册 macOS 退出菜单操作"
            );
            ensure!(
                class_addMethod(
                    (class as *const objc2::runtime::AnyClass).cast(),
                    sel!(applicationShouldTerminate:),
                    should_terminate as *const () as *const c_void,
                    c"Q@:@".as_ptr(),
                ),
                "无法注册 macOS 安全退出处理"
            );
        }

        let menu = NSMenu::new(main);
        let app_menu = NSMenu::initWithTitle(NSMenu::alloc(main), &NSString::from_str("V5VPN"));
        let app_item = item(main, "V5VPN", None, "");
        app_item.setSubmenu(Some(&app_menu));
        menu.addItem(&app_item);
        let quit = item(main, "退出 V5VPN", Some(sel!(v5vpnRequestQuit:)), "q");
        quit.setKeyEquivalentModifierMask(NSEventModifierFlags::Command);
        unsafe {
            quit.setTarget(Some(delegate_object));
        }
        app_menu.addItem(&quit);

        let edit_menu = NSMenu::initWithTitle(NSMenu::alloc(main), &NSString::from_str("编辑"));
        let edit_item = item(main, "编辑", None, "");
        edit_item.setSubmenu(Some(&edit_menu));
        menu.addItem(&edit_item);
        for (label, action, key) in [
            ("剪切", sel!(cut:), "x"),
            ("复制", sel!(copy:), "c"),
            ("粘贴", sel!(paste:), "v"),
            ("全选", sel!(selectAll:), "a"),
        ] {
            let entry = item(main, label, Some(action), key);
            entry.setKeyEquivalentModifierMask(NSEventModifierFlags::Command);
            edit_menu.addItem(&entry);
        }
        app.setMainMenu(Some(&menu));

        // Also supply the icon at runtime for direct executable launches and
        // the Dock; Finder obtains the packaged ICNS from Info.plist.
        let image = NSImage::initWithData(NSImage::alloc(), &NSData::with_bytes(ICON))
            .context("无法加载 macOS 应用图标")?;
        unsafe {
            app.setApplicationIconImage(Some(&image));
        }
        Ok(Self { _menu: menu })
    }
}

fn item(
    main: MainThreadMarker,
    title: &str,
    action: Option<Sel>,
    key: &str,
) -> Retained<NSMenuItem> {
    unsafe {
        NSMenuItem::initWithTitle_action_keyEquivalent(
            NSMenuItem::alloc(main),
            &NSString::from_str(title),
            action,
            &NSString::from_str(key),
        )
    }
}

fn request_quit() {
    QUIT_PROXY.with(|value| {
        if let Some(proxy) = value.borrow().as_ref() {
            let _ = proxy.send_event(AppEvent::Action(Action::Close));
        }
    });
}

extern "C-unwind" fn quit_action(_: &AnyObject, _: Sel, _: Option<&AnyObject>) {
    request_quit();
}

extern "C-unwind" fn should_terminate(_: &AnyObject, _: Sel, _: Option<&AnyObject>) -> usize {
    request_quit();
    0 // NSTerminateCancel: the event loop exits after disconnect has completed.
}

#[link(name = "objc")]
unsafe extern "C" {
    fn class_addMethod(
        class: *const c_void,
        selector: Sel,
        implementation: *const c_void,
        types: *const c_char,
    ) -> bool;
}
