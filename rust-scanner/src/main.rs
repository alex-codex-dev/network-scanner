mod cli;
mod discovery;
#[cfg(target_os = "linux")]
#[allow(dead_code)] // Backend is intentionally not connected to the CLI in this increment.
mod icmp_linux;
#[allow(dead_code)] // V3 is intentionally not connected to the CLI yet.
mod icmp_v3;

fn main() {
    if let Err(error) = cli::run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}
