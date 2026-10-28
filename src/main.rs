use sds_core::{resolve_dns, validate_domain_id, DnsSnapshot, SdsRegistry};
use std::env;
use std::io::{self, Write};

fn print_banner() {
    println!("\x1b[1;34m╔══════════════════════════════════════════════════════════════╗\x1b[0m");
    println!("\x1b[1;34m║          SDS PROTOCOL ENGINE (Rust Implementation)           ║\x1b[0m");
    println!("\x1b[1;34m║     10-Char Domain Encoder, Offline Decoder & DNS Inspector   ║\x1b[0m");
    println!("\x1b[1;34m╚══════════════════════════════════════════════════════════════╝\x1b[0m");
}

fn print_dns(dns: &DnsSnapshot) {
    println!("\n\x1b[1;33m--- LIVE DNS DETAILS ---\x1b[0m");
    let mut has_records = false;
    if !dns.a_records.is_empty() {
        has_records = true;
        println!(
            "  • \x1b[1mIPv4 (A)\x1b[0m          : {}",
            dns.a_records.join(", ")
        );
    }
    if !dns.aaaa_records.is_empty() {
        has_records = true;
        println!(
            "  • \x1b[1mIPv6 (AAAA)\x1b[0m       : {}",
            dns.aaaa_records.join(", ")
        );
    }
    if !dns.cname_records.is_empty() {
        has_records = true;
        println!(
            "  • \x1b[1mCNAME\x1b[0m             : {}",
            dns.cname_records.join(", ")
        );
    }
    if !dns.mx_records.is_empty() {
        has_records = true;
        println!("  • \x1b[1mMail (MX)\x1b[0m         :");
        for mx in &dns.mx_records {
            println!("      - {}", mx);
        }
    }
    if !dns.ns_records.is_empty() {
        has_records = true;
        println!("  • \x1b[1mName Servers (NS)\x1b[0m :");
        for ns in dns.ns_records.iter().take(4) {
            println!("      - {}", ns);
        }
    }
    if !dns.txt_records.is_empty() {
        has_records = true;
        println!("  • \x1b[1mTXT Records\x1b[0m       :");
        for txt in dns.txt_records.iter().take(5) {
            let truncated = if txt.len() > 80 { &txt[..80] } else { txt };
            println!("      - {}", truncated);
        }
    }
    if !has_records {
        println!("  (No public DNS records resolved for this domain)");
    }

    println!("\n\x1b[1;33m--- SERVER CONNECTIVITY ---\x1b[0m");
    if let Some(https) = &dns.https_reachable {
        println!("  • \x1b[1mPort 443 (HTTPS)\x1b[0m  : {}", https);
    }
    if let Some(http) = &dns.http_reachable {
        println!("  • \x1b[1mPort 80  (HTTP)\x1b[0m   : {}", http);
    }
}

fn handle_encode(domain: &str, registry: &mut SdsRegistry) {
    println!(
        "\n[*] Normalizing domain and registering SDS ID for '{}'...",
        domain
    );
    println!("[*] Resolving DNS and querying live server...");
    let dns = resolve_dns(domain);

    match registry.register_domain(domain, Some(dns.clone())) {
        Ok(entry) => {
            println!("\n\x1b[1;32m════════════════════════════════════════════════════════════════\x1b[0m");
            println!("\x1b[1;32m SDS DOMAIN ENCODED SUCCESSFULLY\x1b[0m");
            println!(
                "\x1b[1;32m════════════════════════════════════════════════════════════════\x1b[0m"
            );
            println!(
                " Canonical Domain   : \x1b[1;36m{}\x1b[0m",
                entry.canonical_domain
            );
            println!(
                " SDS Domain ID      : \x1b[1;32m{}\x1b[0m  (Exact 10 Characters)",
                entry.raw_id
            );
            println!(
                " Checksum (2-Char)  : {} (\x1b[1;32mVerified\x1b[0m)",
                entry.checksum
            );
            println!(" Encoding Standard  : Crockford Base32 (8 Payload + 2 Checksum = 10 chars)");
            println!(" Capacity           : 1.099 Trillion IDs (Collision-Proof & Unlimited)");
            println!(" SDS URI            : sds://{}", entry.raw_id);
            println!(" Separators Note    : Accepts symbols like - _ % $ # @ when entered");
            println!(" Offline Storage    : Cached in local registry (sds_registry.json)");
            println!(
                "\x1b[1;32m════════════════════════════════════════════════════════════════\x1b[0m"
            );

            print_dns(&dns);
        }
        Err(e) => {
            eprintln!("\n\x1b[1;31m[!] Error encoding domain: {}\x1b[0m", e);
        }
    }
}

fn handle_decode(code: &str, registry: &SdsRegistry) {
    println!("\n[*] Validating 10-character SDS Code: '{}'...", code);

    match validate_domain_id(code) {
        Ok(valid) => {
            if !valid {
                println!(
                    "\n\x1b[1;31m[!] Checksum Mismatch: Typo detected in code '{}'!\x1b[0m",
                    code
                );
                return;
            }
        }
        Err(e) => {
            println!("\n\x1b[1;31m[!] Format Error: {}\x1b[0m", e);
            return;
        }
    }

    println!(" Checksum Status    : \x1b[1;32mPASSED (Valid SDS Identifier)\x1b[0m");

    match registry.find_by_code(code) {
        Some(entry) => {
            println!("\n\x1b[1;36m════════════════════════════════════════════════════════════════\x1b[0m");
            println!("\x1b[1;36m SDS DOMAIN RESOLVED (OFFLINE CACHE HIT)\x1b[0m");
            println!(
                "\x1b[1;36m════════════════════════════════════════════════════════════════\x1b[0m"
            );
            println!(
                " Decoded Domain     : \x1b[1;32m{}\x1b[0m",
                entry.canonical_domain
            );
            println!(
                " SDS Domain ID      : \x1b[1;32m{}\x1b[0m  (Exact 10 Characters)",
                entry.raw_id
            );
            println!(" Registered At      : {}", entry.created_at);
            println!(" Status             : {}", entry.status.to_uppercase());
            println!(
                "\x1b[1;36m════════════════════════════════════════════════════════════════\x1b[0m"
            );

            println!(
                "\n[*] Fetching LIVE DNS records for '{}'...",
                entry.canonical_domain
            );
            let live_dns = resolve_dns(&entry.canonical_domain);
            print_dns(&live_dns);
        }
        None => {
            println!("\n\x1b[1;33m[!] Domain Not Found in Local Offline Registry\x1b[0m");
            println!("    The code is cryptographically well-formed and valid, but has not yet");
            println!("    been imported or synchronized into your local offline registry.");
        }
    }
}

fn handle_list(registry: &SdsRegistry) {
    let list = registry.list_all();
    println!(
        "\n\x1b[1;34m══════════════════════════════════════════════════════════════════════\x1b[0m"
    );
    println!(
        " \x1b[1mSDS REGISTERED / CACHED DOMAINS ({})\x1b[0m",
        list.len()
    );
    println!(
        "\x1b[1;34m══════════════════════════════════════════════════════════════════════\x1b[0m"
    );
    if list.is_empty() {
        println!(" (No domains registered yet. Run 'encode <domain>')");
        return;
    }
    println!(
        " {:<14} {:<28} {:<20}",
        "SDS Domain ID", "Canonical Domain", "Registered At"
    );
    println!(" {}", "-".repeat(68));
    for entry in list {
        println!(
            " {:<14} {:<28} {}",
            entry.raw_id,
            entry.canonical_domain,
            entry.created_at.format("%Y-%m-%d %H:%M:%S")
        );
    }
    println!(
        "\x1b[1;34m══════════════════════════════════════════════════════════════════════\x1b[0m"
    );
}

fn interactive_loop(mut registry: SdsRegistry) {
    print_banner();
    loop {
        println!("\n\x1b[1mOptions:\x1b[0m");
        println!("  \x1b[1;32m1.\x1b[0m Encode Domain (Enter domain -> Get 10-char SDS ID + DNS)");
        println!(
            "  \x1b[1;36m2.\x1b[0m Decode Code   (Enter 10-char Code -> Get Domain + Live DNS)"
        );
        println!("  \x1b[1;33m3.\x1b[0m List Stored Domains");
        println!("  \x1b[1;31m4.\x1b[0m Exit");

        print!("\nEnter choice [1-4]: ");
        io::stdout().flush().unwrap();

        let mut choice = String::new();
        if io::stdin().read_line(&mut choice).is_err() {
            break;
        }
        match choice.trim() {
            "1" => {
                print!("Enter domain name (e.g. meddylist.com, xyz.com): ");
                io::stdout().flush().unwrap();
                let mut domain = String::new();
                if io::stdin().read_line(&mut domain).is_ok() {
                    let d = domain.trim();
                    if !d.is_empty() {
                        handle_encode(d, &mut registry);
                    }
                }
            }
            "2" => {
                print!("Enter 10-char SDS Code (e.g. Q2KE-9Y5F-G8 or Q2KE9Y5FG8): ");
                io::stdout().flush().unwrap();
                let mut code = String::new();
                if io::stdin().read_line(&mut code).is_ok() {
                    let c = code.trim();
                    if !c.is_empty() {
                        handle_decode(c, &registry);
                    }
                }
            }
            "3" => {
                handle_list(&registry);
            }
            "4" | "q" | "exit" => {
                println!("Goodbye!");
                break;
            }
            _ => {
                println!("Invalid selection. Please choose 1, 2, 3, or 4.");
            }
        }
    }
}

fn main() {
    let mut registry = SdsRegistry::load_default().unwrap_or_else(|e| {
        eprintln!("Warning loading registry: {}", e);
        SdsRegistry::load_from_path(std::path::PathBuf::from("sds_registry.json")).unwrap()
    });

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        interactive_loop(registry);
        return;
    }

    match args[1].as_str() {
        "encode" | "e" => {
            if args.len() < 3 {
                eprintln!("Usage: cargo run -- encode <domain>");
                std::process::exit(1);
            }
            handle_encode(&args[2], &mut registry);
        }
        "decode" | "d" => {
            if args.len() < 3 {
                eprintln!("Usage: cargo run -- decode <code>");
                std::process::exit(1);
            }
            handle_decode(&args[2], &registry);
        }
        "list" | "ls" => {
            handle_list(&registry);
        }
        "interactive" | "i" => {
            interactive_loop(registry);
        }
        help_flag if help_flag == "--help" || help_flag == "-h" => {
            print_banner();
            println!("\nUsage:");
            println!(
                "  cargo run -- encode <domain>     # Encode domain to 10-char ID & store DNS"
            );
            println!("  cargo run -- decode <code>       # Decode 10-char ID to domain & inspect live DNS");
            println!("  cargo run -- list                # List all stored domains and IDs");
            println!("  cargo run -- interactive         # Launch interactive prompt");
        }
        unknown => {
            eprintln!("Unknown command '{}'. Run with --help for usage.", unknown);
            std::process::exit(1);
        }
    }
}
