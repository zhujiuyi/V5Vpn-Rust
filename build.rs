use std::{env, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=assets/v5vpn.rc");
    println!("cargo:rerun-if-changed=assets/v5vpn.ico");

    let target = env::var("TARGET").expect("Cargo did not supply the target triple");
    if !target.ends_with("-windows-msvc") {
        return;
    }

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo did not supply OUT_DIR"));
    let resource = out_dir.join("v5vpn.res");
    let status = cc::windows_registry::find(&target, "rc.exe")
        .expect("Windows SDK resource compiler (rc.exe) was not found")
        .current_dir("assets")
        .args(["/nologo", "/fo"])
        .arg(&resource)
        .arg("v5vpn.rc")
        .status()
        .expect("Could not run the Windows SDK resource compiler");
    assert!(status.success(), "Windows icon resource compilation failed");
    println!(
        "cargo:rustc-link-arg-bin=v5vpn-desktop={}",
        resource.display()
    );
}
