mod cli;
mod discovery;
#[cfg(target_os = "linux")]
mod icmp_linux;
mod icmp_v3;

fn main() {
    if let Err(error) = cli::run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}
