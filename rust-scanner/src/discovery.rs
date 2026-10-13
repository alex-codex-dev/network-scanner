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
    let mut child = ping_command(address, timeout).spawn()?;
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
                    match is_reachable(address, timeout) {
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
}
