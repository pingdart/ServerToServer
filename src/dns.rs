use serde::{Deserialize, Serialize};
use std::net::{TcpStream, ToSocketAddrs};
use std::process::Command;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DnsSnapshot {
    pub a_records: Vec<String>,
    pub aaaa_records: Vec<String>,
    pub mx_records: Vec<String>,
    pub txt_records: Vec<String>,
    pub srv_records: Vec<String>,
    pub ns_records: Vec<String>,
    pub cname_records: Vec<String>,
    pub https_reachable: Option<String>,
    pub http_reachable: Option<String>,
}

pub fn resolve_dns(domain: &str) -> DnsSnapshot {
    let mut snapshot = DnsSnapshot::default();

    // 1. Native socket resolution for A & AAAA
    let lookup_target = format!("{}:80", domain);
    if let Ok(addrs) = lookup_target.to_socket_addrs() {
        for addr in addrs {
            let ip_str = addr.ip().to_string();
            if addr.is_ipv4() {
                if !snapshot.a_records.contains(&ip_str) {
                    snapshot.a_records.push(ip_str);
                }
            } else if addr.is_ipv6() && !snapshot.aaaa_records.contains(&ip_str) {
                snapshot.aaaa_records.push(ip_str);
            }
        }
    }

    // 2. Query dig for MX, TXT, SRV, NS, CNAME
    snapshot.mx_records = query_dig(domain, "MX");
    snapshot.txt_records = query_dig(domain, "TXT");
    let srv_target = format!("_sds._udp.{}", domain);
    snapshot.srv_records = query_dig(&srv_target, "SRV");
    snapshot.ns_records = query_dig(domain, "NS");
    snapshot.cname_records = query_dig(domain, "CNAME");

    // Also fallback if A or AAAA were empty from socket
    if snapshot.a_records.is_empty() {
        snapshot.a_records = query_dig(domain, "A");
    }
    if snapshot.aaaa_records.is_empty() {
        snapshot.aaaa_records = query_dig(domain, "AAAA");
    }

    // 3. Connectivity check
    snapshot.https_reachable = Some(test_port(domain, 443));
    snapshot.http_reachable = Some(test_port(domain, 80));

    snapshot
}

fn query_dig(domain: &str, record_type: &str) -> Vec<String> {
    let output = Command::new("dig")
        .args(["+noall", "+answer", domain, record_type])
        .output();

    let mut results = Vec::new();
    if let Ok(out) = output {
        let stdout = String::from_utf8_lossy(&out.stdout);
        for line in stdout.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 5 {
                let rdata = parts[4..].join(" ");
                results.push(rdata);
            }
        }
    }
    results
}

fn test_port(domain: &str, port: u16) -> String {
    let target = format!("{}:{}", domain, port);
    let start = Instant::now();
    match TcpStream::connect_timeout(
        &target
            .to_socket_addrs()
            .ok()
            .and_then(|mut a| a.next())
            .unwrap_or_else(|| std::net::SocketAddr::from(([0, 0, 0, 0], port))),
        Duration::from_millis(2500),
    ) {
        Ok(_) => {
            let elapsed = start.elapsed().as_millis();
            format!("Reachable ({} ms)", elapsed)
        }
        Err(e) => format!("Unreachable ({})", e),
    }
}
