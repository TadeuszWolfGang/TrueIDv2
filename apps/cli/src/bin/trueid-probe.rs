//! Minimal internal probe binary for container health checks.

use std::env;
use std::fs;
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

fn usage() -> &'static str {
    "Usage: trueid-probe tcp <host:port> | file-nonempty <path>"
}

fn probe_tcp(target: &str) -> Result<(), String> {
    let addr: SocketAddr = target
        .parse()
        .map_err(|err| format!("invalid socket address '{target}': {err}"))?;
    TcpStream::connect_timeout(&addr, Duration::from_secs(2))
        .map(|_| ())
        .map_err(|err| format!("TCP probe to {target} failed: {err}"))
}

fn probe_file_nonempty(path: &str) -> Result<(), String> {
    let meta = fs::metadata(Path::new(path))
        .map_err(|err| format!("metadata for '{path}' failed: {err}"))?;
    if meta.len() == 0 {
        return Err(format!("file '{path}' is empty"));
    }
    Ok(())
}

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let Some(mode) = args.next() else {
        eprintln!("{}", usage());
        return ExitCode::from(2);
    };
    let Some(target) = args.next() else {
        eprintln!("{}", usage());
        return ExitCode::from(2);
    };
    if args.next().is_some() {
        eprintln!("{}", usage());
        return ExitCode::from(2);
    }

    let result = match mode.as_str() {
        "tcp" => probe_tcp(&target),
        "file-nonempty" => probe_file_nonempty(&target),
        _ => {
            eprintln!("{}", usage());
            return ExitCode::from(2);
        }
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(1)
        }
    }
}
