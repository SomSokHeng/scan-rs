use clap::Parser;
use serde::Serialize;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{lookup_host, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::{timeout, Instant};

#[derive(Parser)]
#[command(name = "vso-scan", about = "Async TCP connect scanner")]
struct Cfg {
    #[arg(short, long)]
    tgt: String,
    #[arg(short, long, default_value = "1-1024")]
    ports: String,
    #[arg(short, long, default_value_t = 200)]
    conc: usize,
    #[arg(long, default_value_t = 1500)]
    tmo: u64,
    #[arg(long)]
    banner: bool,
    #[arg(long)]
    json: bool,
}

#[derive(Serialize)]
struct Res {
    port: u16,
    ms: u64,
    svc: &'static str,
    banner: Option<String>,
}

fn vld_host(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 253
        && h.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':'))
}

fn prs_ports(s: &str) -> Result<Vec<u16>, String> {
    let mut out: Vec<u16> = Vec::new();
    for p in s.split(',') {
        let p = p.trim();
        if let Some((a, b)) = p.split_once('-') {
            let a: u16 = a.parse().map_err(|_| "bad port")?;
            let b: u16 = b.parse().map_err(|_| "bad port")?;
            if a == 0 || a > b {
                return Err("bad range".into());
            }
            out.extend(a..=b);
        } else {
            let v: u16 = p.parse().map_err(|_| "bad port")?;
            if v == 0 {
                return Err("bad port".into());
            }
            out.push(v);
        }
    }
    out.sort_unstable();
    out.dedup();
    if out.is_empty() {
        return Err("no ports".into());
    }
    Ok(out)
}

fn svc_nm(p: u16) -> &'static str {
    match p {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        80 | 8000 | 8080 | 8888 => "http",
        110 => "pop3",
        143 => "imap",
        443 | 8443 => "https",
        3306 => "mysql",
        5432 => "pgsql",
        6379 => "redis",
        27017 => "mongo",
        _ => "unknown",
    }
}

async fn grb(s: &mut TcpStream, port: u16) -> Option<String> {
    if matches!(port, 80 | 8000 | 8080 | 8888) {
        let _ = timeout(
            Duration::from_millis(500),
            s.write_all(b"HEAD / HTTP/1.0\r\n\r\n"),
        )
        .await;
    }
    let mut buf = [0u8; 256];
    let n = timeout(Duration::from_millis(600), s.read(&mut buf))
        .await
        .ok()?
        .ok()?;
    if n == 0 {
        return None;
    }
    let txt: String = buf[..n]
        .iter()
        .map(|&b| if (32..127).contains(&b) { b as char } else { ' ' })
        .collect();
    let txt = txt.trim().to_string();
    if txt.is_empty() {
        None
    } else {
        Some(txt)
    }
}

async fn prb(ip: IpAddr, port: u16, tmo: Duration, bnr: bool) -> Option<Res> {
    let t = Instant::now();
    let mut s = timeout(tmo, TcpStream::connect(SocketAddr::new(ip, port)))
        .await
        .ok()?
        .ok()?;
    let ms = t.elapsed().as_millis() as u64;
    let banner = if bnr { grb(&mut s, port).await } else { None };
    Some(Res { port, ms, svc: svc_nm(port), banner })
}

#[tokio::main]
async fn main() {
    let cfg = Cfg::parse();
    if !vld_host(&cfg.tgt) {
        eprintln!("invalid target");
        std::process::exit(2);
    }
    if !(1..=1000).contains(&cfg.conc) || !(100..=10000).contains(&cfg.tmo) {
        eprintln!("conc must be 1-1000, tmo 100-10000");
        std::process::exit(2);
    }
    let ports = match prs_ports(&cfg.ports) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };
    let ip = match lookup_host((cfg.tgt.as_str(), 0)).await {
        Ok(mut it) => match it.next() {
            Some(a) => a.ip(),
            None => {
                eprintln!("resolve failed");
                std::process::exit(1);
            }
        },
        Err(_) => {
            eprintln!("resolve failed");
            std::process::exit(1);
        }
    };
    let sem = Arc::new(Semaphore::new(cfg.conc));
    let tmo = Duration::from_millis(cfg.tmo);
    let mut hdl = Vec::with_capacity(ports.len());
    for p in ports {
        let sem = sem.clone();
        let bnr = cfg.banner;
        hdl.push(tokio::spawn(async move {
            let _pmt = sem.acquire_owned().await.ok()?;
            prb(ip, p, tmo, bnr).await
        }));
    }
    let mut res: Vec<Res> = Vec::new();
    for h in hdl {
        if let Ok(Some(r)) = h.await {
            res.push(r);
        }
    }
    res.sort_by_key(|r| r.port);
    if cfg.json {
        println!("{}", serde_json::to_string_pretty(&res).unwrap_or_default());
    } else {
        println!("{} ({}) open: {}", cfg.tgt, ip, res.len());
        for r in &res {
            println!(
                "{:>5}/tcp  {:<8} {:>5}ms  {}",
                r.port,
                r.svc,
                r.ms,
                r.banner.as_deref().unwrap_or("")
            );
        }
    }
}
