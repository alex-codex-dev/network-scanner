use std::{
    io,
    net::Ipv4Addr,
    process::{Command, Stdio},
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};

use wait_timeout::ChildExt;

#[derive(Debug, PartialEq, Eq)]
pub enum ScanError {
    PingNotFound,
    PingFailed,
    WorkerFailed,
}

fn host_addresses(network: Ipv4Addr, prefix: u8) -> Vec<Ipv4Addr> {
    let base = u32::from(network);
    let count = 1_u64 << (32 - prefix);
    let skip = usize::from(prefix < 31);
    let end = count as usize - skip;
    (skip..end)
        .map(|offset| Ipv4Addr::from(base + offset as u32))
        .collect()
}

fn ping_command(address: Ipv4Addr, timeout: Duration) -> Command {
    let mut command = Command::new("ping");
    #[cfg(target_os = "windows")]
    {
        command.args(["-n", "1", "-w"]);
        command.arg(timeout.as_millis().max(1).to_string());
    }
    #[cfg(target_os = "macos")]
    {
        command.args(["-c", "1", "-W"]);
        command.arg(timeout.as_millis().max(1).to_string());
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        command.args(["-c", "1", "-W"]);
        command.arg(timeout.as_secs().max(1).to_string());
    }
    command.arg(address.to_string());
    command.stdout(Stdio::null()).stderr(Stdio::null());
    command
}

fn is_reachable(address: Ipv4Addr, timeout: Duration) -> io::Result<bool> {
    run_command(ping_command(address, timeout), timeout)
}

fn run_command(mut command: Command, timeout: Duration) -> io::Result<bool> {
    let mut child = command.spawn()?;
    match child.wait_timeout(timeout + Duration::from_secs(1))? {
        Some(status) => Ok(status.success()),
        None => {
            child.kill()?;
            let _ = child.wait();
            Ok(false)
        }
    }
}

pub fn discover(
    network: Ipv4Addr,
    prefix: u8,
    timeout: Duration,
    concurrency: usize,
) -> Result<Vec<Ipv4Addr>, ScanError> {
    discover_with(network, prefix, timeout, concurrency, is_reachable)
}

fn discover_with<F>(
    network: Ipv4Addr,
    prefix: u8,
    timeout: Duration,
    concurrency: usize,
    check_host: F,
) -> Result<Vec<Ipv4Addr>, ScanError>
where
    F: Fn(Ipv4Addr, Duration) -> io::Result<bool> + Sync,
{
    let addresses = host_addresses(network, prefix);
    if addresses.is_empty() {
        return Ok(Vec::new());
    }

    let next = AtomicUsize::new(0);
    let found = Mutex::new(Vec::new());
    let failed = Mutex::new(None);
    let worker_count = concurrency.min(addresses.len());
    thread::scope(|scope| {
        let mut workers = Vec::with_capacity(worker_count);
        for _ in 0..worker_count {
            workers.push(scope.spawn(|| {
                loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some(address) = addresses.get(index).copied() else {
                        break;
                    };
                    match check_host(address, timeout) {
                        Ok(true) => found.lock().expect("results mutex poisoned").push(address),
                        Ok(false) => {}
                        Err(error) => {
                            let scan_error = if error.kind() == io::ErrorKind::NotFound {
                                ScanError::PingNotFound
                            } else {
                                ScanError::PingFailed
                            };
                            let mut failure = failed.lock().expect("error mutex poisoned");
                            if failure.is_none() || scan_error == ScanError::PingNotFound {
                                *failure = Some(scan_error);
                            }
                        }
                    }
                }
            }));
        }
        for worker in workers {
            if worker.join().is_err() {
                return Err(ScanError::WorkerFailed);
            }
        }
        Ok(())
    })?;

    if let Some(error) = failed.lock().expect("error mutex poisoned").take() {
        return Err(error);
    }
    let mut found = found.into_inner().expect("results mutex poisoned");
    found.sort_unstable();
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn enumerates_regular_and_small_networks() {
        assert_eq!(
            host_addresses("192.0.2.0".parse().unwrap(), 30),
            vec![
                "192.0.2.1".parse::<Ipv4Addr>().unwrap(),
                "192.0.2.2".parse::<Ipv4Addr>().unwrap(),
            ]
        );
        assert_eq!(host_addresses("192.0.2.0".parse().unwrap(), 31).len(), 2);
        assert_eq!(host_addresses("192.0.2.7".parse().unwrap(), 32).len(), 1);
    }

    #[test]
    fn discovers_reachable_hosts_and_sorts_results() {
        let result = discover_with(
            "192.0.2.0".parse().unwrap(),
            29,
            Duration::ZERO,
            3,
            |ip, _| Ok(ip.octets()[3] == 5 || ip.octets()[3] == 2),
        )
        .unwrap();
        assert_eq!(
            result,
            vec![
                "192.0.2.2".parse::<Ipv4Addr>().unwrap(),
                "192.0.2.5".parse::<Ipv4Addr>().unwrap(),
            ]
        );
    }

    #[test]
    fn returns_empty_when_no_hosts_are_reachable() {
        let result = discover_with(
            "192.0.2.0".parse().unwrap(),
            30,
            Duration::ZERO,
            2,
            |_, _| Ok(false),
        )
        .unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn limits_simultaneous_checks_to_worker_count() {
        let active = AtomicUsize::new(0);
        let maximum = AtomicUsize::new(0);
        let _ = discover_with(
            "192.0.2.0".parse().unwrap(),
            28,
            Duration::ZERO,
            2,
            |_, _| {
                let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                maximum.fetch_max(now, Ordering::SeqCst);
                thread::sleep(Duration::from_millis(5));
                active.fetch_sub(1, Ordering::SeqCst);
                Ok(true)
            },
        )
        .unwrap();
        assert_eq!(maximum.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn maps_missing_ping_and_other_check_errors() {
        let network = "192.0.2.0".parse().unwrap();
        assert_eq!(
            discover_with(network, 30, Duration::ZERO, 1, |_, _| {
                Err(io::ErrorKind::NotFound.into())
            }),
            Err(ScanError::PingNotFound)
        );
        assert_eq!(
            discover_with(network, 30, Duration::ZERO, 1, |_, _| {
                Err(io::ErrorKind::PermissionDenied.into())
            }),
            Err(ScanError::PingFailed)
        );
    }

    #[cfg(unix)]
    fn shell(command_text: &str) -> Command {
        let mut command = Command::new("sh");
        command.args(["-c", command_text]);
        command
    }

    #[cfg(unix)]
    #[test]
    fn handles_ping_process_failure_timeout_and_missing_executable() {
        assert!(!run_command(shell("exit 1"), Duration::from_secs(1)).unwrap());
        assert!(!run_command(shell("sleep 2"), Duration::from_millis(10)).unwrap());

        let error = run_command(
            Command::new("/definitely/not/a/real/ping"),
            Duration::from_secs(1),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }
}
