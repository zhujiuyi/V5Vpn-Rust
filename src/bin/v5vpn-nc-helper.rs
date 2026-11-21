#[cfg(target_os = "macos")]
#[derive(clap::Parser)]
struct Args {
    #[arg(long)]
    socket: std::path::PathBuf,
    #[arg(long)]
    uid: u32,
    #[arg(long)]
    parent_pid: u32,
}

#[cfg(target_os = "macos")]
#[tokio::main]
async fn main() {
    use clap::Parser;
    let args = Args::parse();
    if let Err(error) =
        v5vpn_client::run_macos_nc_helper(args.socket, args.uid, args.parent_pid).await
    {
        eprintln!("NC 辅助程序退出：{error:#}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "macos"))]
fn main() {}
