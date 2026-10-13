use std::{net::Ipv4Addr, time::Duration};

use clap::Parser;

use crate::discovery::{self, ScanError};

const DEFAULT_MAX_HOSTS: usize = 256;
const DEFAULT_CONCURRENCY: usize = 32;

#[derive(Debug, Parser)]
#[command(about = "Discover ping-responsive hosts on an authorized IPv4 network")]
struct Arguments {
    /// IPv4 network in CIDR notation, for example 192.168.1.0/24
    network: String,
    /// Per-host timeout in seconds
    #[arg(long, default_value_t = 1.0, value_parser = positive_float)]
    timeout: f64,
    /// Maximum number of host addresses to check
    #[arg(long, default_value_t = DEFAULT_MAX_HOSTS, value_parser = positive_usize)]
    max_hosts: usize,
    /// Maximum number of concurrent ping workers
    #[arg(long, default_value_t = DEFAULT_CONCURRENCY, value_parser = positive_usize)]
    concurrency: usize,
}

fn positive_float(value: &str) -> Result<f64, String> {
    let parsed = value
        .parse::<f64>()
        .map_err(|_| "must be a number".to_owned())?;
    if parsed.is_finite() && parsed > 0.0 {
        Ok(parsed)
    } else {
        Err("must be greater than zero".to_owned())
    }
}

fn positive_usize(value: &str) -> Result<usize, String> {
    let parsed = value
        .parse::<usize>()
        .map_err(|_| "must be an integer".to_owned())?;
    if parsed > 0 {
        Ok(parsed)
    } else {
        Err("must be greater than zero".to_owned())
    }
}

fn parse_network(value: &str) -> Result<(Ipv4Addr, u8), String> {
    let (address, prefix) = value.split_once('/').ok_or("expected IPv4 CIDR notation")?;
    if prefix.contains('/') {
        return Err("expected one CIDR prefix".to_owned());
    }
    let address = address
        .parse::<Ipv4Addr>()
        .map_err(|_| "expected an IPv4 address")?;
    let prefix = prefix
        .parse::<u8>()
        .map_err(|_| "prefix must be between 0 and 32")?;
    if prefix > 32 {
        return Err("prefix must be between 0 and 32".to_owned());
    }
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    if u32::from(address) & mask != u32::from(address) {
        return Err("network address has host bits set".to_owned());
    }
    Ok((address, prefix))
}

pub fn run() -> Result<(), String> {
    let args = Arguments::try_parse().map_err(|error| error.to_string())?;
    let (network, prefix) = parse_network(&args.network)?;
    let host_count = if prefix < 31 {
        (1_u64 << (32 - prefix)) - 2
    } else {
        1_u64 << (32 - prefix)
    };
    if host_count > args.max_hosts as u64 {
        return Err(format!(
            "network contains {host_count} hosts, exceeding --max-hosts {}",
            args.max_hosts
        ));
    }

    println!("Scanning {network}/{prefix} ({host_count} host addresses)");
    let timeout = Duration::try_from_secs_f64(args.timeout)
        .map_err(|_| "--timeout is too large".to_owned())?;
    let reachable = discovery::discover(network, prefix, timeout, args.concurrency).map_err(
        |error| match error {
            ScanError::PingNotFound => "ping command was not found".to_owned(),
            ScanError::PingFailed => "could not start or wait for ping".to_owned(),
            ScanError::WorkerFailed => "a discovery worker failed".to_owned(),
        },
    )?;
    if reachable.is_empty() {
        println!("No ping-responsive hosts found.");
    } else {
        println!("Reachable hosts:");
        for address in reachable {
            println!("  {address}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_network_address_and_prefix() {
        assert_eq!(
            parse_network("192.0.2.0/24").unwrap(),
            (Ipv4Addr::new(192, 0, 2, 0), 24)
        );
    }

    #[test]
    fn rejects_host_bits_and_invalid_prefix() {
        assert!(parse_network("192.0.2.1/24").is_err());
        assert!(parse_network("192.0.2.0/33").is_err());
        assert!(parse_network("2001:db8::/32").is_err());
    }

    #[test]
    fn validates_positive_options() {
        assert!(positive_usize("0").is_err());
        assert!(positive_float("0").is_err());
        assert!(positive_float("NaN").is_err());
    }
}
