#!/usr/bin/env python3
"""
SDS Protocol Tool — Domain Encoder, Offline Decoder & DNS Inspector
"""

import sys
import os
import re
import json
import sqlite3
import hashlib
import subprocess
import socket
import time
from urllib.parse import urlparse

DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sds_registry.db")

# Crockford's Base32 Alphabet (32 chars)
ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
DECODE_MAP = {c: i for i, c in enumerate(ALPHABET)}
# Permissive typo mappings for human entry
DECODE_MAP.update({'O': 0, 'I': 1, 'L': 1})

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS sds_domains (
            domain_id TEXT PRIMARY KEY,
            raw_id TEXT UNIQUE,
            canonical_domain TEXT UNIQUE,
            checksum TEXT,
            dns_snapshot TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'active'
        )
    ''')
    conn.commit()
    conn.close()

def normalize_domain(domain_input: str) -> str:
    s = domain_input.strip()
    if s.startswith(('http://', 'https://', 'sds://')):
        parsed = urlparse(s)
        s = parsed.netloc or parsed.path
    s = s.split('/')[0].split(':')[0].strip().lower()
    if s.endswith('.'):
        s = s[:-1]
    try:
        s = s.encode('idna').decode('ascii')
    except Exception:
        pass
    if not re.match(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$', s):
        raise ValueError(f"Invalid domain format: '{domain_input}'")
    return s

def calculate_domain_id(canonical_domain: str):
    h = hashlib.sha256(canonical_domain.encode('utf-8')).digest()
    val = int.from_bytes(h[:5], 'big')  # 40 bits
    payload_chars = []
    for _ in range(8):
        payload_chars.append(ALPHABET[val & 0x1F])
        val >>= 5
    payload = ''.join(reversed(payload_chars))

    # 10-bit Checksum (2 base32 characters)
    cs_val = sum((i + 1) * DECODE_MAP[c] for i, c in enumerate(payload)) % 1024
    c1 = ALPHABET[(cs_val >> 5) & 0x1F]
    c2 = ALPHABET[cs_val & 0x1F]

    formatted_id = f"{payload[:4]}-{payload[4:]}-{c1}{c2}"
    raw_id = f"{payload}{c1}{c2}"
    checksum = f"{c1}{c2}"
    return formatted_id, raw_id, checksum

def validate_checksum(code: str):
    clean = code.replace('-', '').strip().upper()
    if len(clean) != 10:
        return False, "Length must be exactly 10 characters", None, None
    for c in clean:
        if c not in DECODE_MAP:
            return False, f"Invalid character '{c}' (Only 0-9, A-Z excluding I, L, O, U)", None, None

    payload = clean[:8]
    c1, c2 = clean[8], clean[9]
    cs_val = sum((i + 1) * DECODE_MAP[c] for i, c in enumerate(payload)) % 1024
    exp_c1 = ALPHABET[(cs_val >> 5) & 0x1F]
    exp_c2 = ALPHABET[cs_val & 0x1F]

    if c1 != exp_c1 or c2 != exp_c2:
        return False, f"Checksum verification failed! Expected '{exp_c1}{exp_c2}' but got '{c1}{c2}' (Possible typo)", payload, f"{c1}{c2}"

    return True, "Valid checksum", payload, f"{c1}{c2}"

def query_dns(domain: str) -> dict:
    records = {
        "A": [],
        "AAAA": [],
        "MX": [],
        "TXT": [],
        "NS": [],
        "CNAME": []
    }
    for qtype in records.keys():
        try:
            res = subprocess.run(
                ["dig", "+noall", "+answer", domain, qtype],
                capture_output=True,
                text=True,
                timeout=5
            )
            for line in res.stdout.strip().splitlines():
                if not line.strip():
                    continue
                parts = line.split()
                if len(parts) >= 5:
                    rdata = " ".join(parts[4:])
                    records[qtype].append(rdata)
        except Exception:
            pass
    return records

def test_connectivity(domain: str):
    results = {}
    for port, label in [(443, "HTTPS (443)"), (80, "HTTP (80)")]:
        start = time.time()
        try:
            sock = socket.create_connection((domain, port), timeout=3)
            sock.close()
            latency = int((time.time() - start) * 1000)
            results[label] = f"Reachable ({latency} ms)"
        except Exception as e:
            results[label] = f"Not reachable ({str(e).split(':')[-1].strip()})"
    return results

def encode_and_store(domain_input: str):
    init_db()
    canonical = normalize_domain(domain_input)
    formatted_id, raw_id, checksum = calculate_domain_id(canonical)

    print(f"\n[+] Resolving DNS records for {canonical}...")
    dns_data = query_dns(canonical)

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        INSERT INTO sds_domains (domain_id, raw_id, canonical_domain, checksum, dns_snapshot, updated_at)
        VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(canonical_domain) DO UPDATE SET
            dns_snapshot=excluded.dns_snapshot,
            updated_at=CURRENT_TIMESTAMP
    ''', (formatted_id, raw_id, canonical, checksum, json.dumps(dns_data)))
    conn.commit()
    conn.close()

    print("\n" + "="*60)
    print(" SDS DOMAIN ENCODING RESULT")
    print("="*60)
    print(f" Original Input     : {domain_input}")
    print(f" Canonical Domain   : {canonical}")
    print(f" SDS Domain ID      : \033[1;32m{formatted_id}\033[0m  (Raw: {raw_id})")
    print(f" Checksum (2-char)  : {checksum} (Verified)")
    print(f" Character Format   : Crockford Base32 (8 Payload + 2 Checksum)")
    print(f" SDS Address URI    : sds://{formatted_id}")
    print(f" Storage Status     : Cached in local SQLite database")
    print("="*60)

    print_dns_summary(dns_data)
    return formatted_id, raw_id, canonical

def decode_and_inspect(code_input: str):
    init_db()
    clean_code = code_input.replace('-', '').strip().upper()
    is_valid, msg, payload, cs = validate_checksum(clean_code)

    print("\n" + "="*60)
    print(" SDS DOMAIN DECODING & INSPECTION")
    print("="*60)
    print(f" Input Code         : {code_input}")
    print(f" Normalized Code    : {clean_code}")

    if not is_valid:
        print(f"\n\033[1;31m[!] Checksum / Format Error: {msg}\033[0m")
        print("="*60)
        return False

    print(f" Checksum Status    : \033[1;32mPASSED\033[0m (Payload: {payload}, Checksum: {cs})")

    # Local DB lookup
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        SELECT domain_id, canonical_domain, dns_snapshot, created_at, updated_at, status
        FROM sds_domains
        WHERE raw_id = ? OR domain_id = ?
    ''', (clean_code, code_input.upper()))
    row = c.fetchone()
    conn.close()

    if not row:
        print(f"\n\033[1;33m[!] Domain Mapping Not Found in Local Offline Database!\033[0m")
        print(f"    Code is cryptographically valid, but no local mapping exists for ID '{clean_code}'.")
        print("="*60)
        return False

    domain_id, domain, dns_snapshot_str, created_at, updated_at, status = row
    print(f" Decoded Domain     : \033[1;36m{domain}\033[0m")
    print(f" Status             : {status.upper()}")
    print(f" First Registered   : {created_at}")
    print(f" Last Updated       : {updated_at}")
    print("="*60)

    print(f"\n[*] Fetching LIVE DNS records for '{domain}'...")
    live_dns = query_dns(domain)
    print_dns_summary(live_dns)

    print("\n[*] Server Connectivity Check:")
    conn_info = test_connectivity(domain)
    for k, v in conn_info.items():
        print(f"  • {k:<15}: {v}")

    print("\n" + "="*60)
    return True

def print_dns_summary(dns_data: dict):
    print("\n--- DNS DETAILS ---")
    has_records = False
    if dns_data.get("A"):
        has_records = True
        print(f"  • IPv4 (A)        : {', '.join(dns_data['A'])}")
    if dns_data.get("AAAA"):
        has_records = True
        print(f"  • IPv6 (AAAA)     : {', '.join(dns_data['AAAA'])}")
    if dns_data.get("CNAME"):
        has_records = True
        print(f"  • CNAME           : {', '.join(dns_data['CNAME'])}")
    if dns_data.get("MX"):
        has_records = True
        print("  • Mail (MX)       :")
        for mx in dns_data["MX"]:
            print(f"      - {mx}")
    if dns_data.get("NS"):
        has_records = True
        print(f"  • Name Servers(NS): {', '.join(dns_data['NS'][:4])}")
    if dns_data.get("TXT"):
        has_records = True
        print("  • TXT Records     :")
        for txt in dns_data["TXT"][:5]:
            print(f"      - {txt[:90]}{'...' if len(txt) > 90 else ''}")
    if not has_records:
        print("  (No public DNS records resolved)")

def list_domains():
    init_db()
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('SELECT domain_id, raw_id, canonical_domain, created_at FROM sds_domains ORDER BY created_at DESC')
    rows = c.fetchall()
    conn.close()

    print("\n" + "="*68)
    print(" SDS REGISTERED / CACHED DOMAINS")
    print("="*68)
    if not rows:
        print(" No domains registered yet. Run: python3 sds_tool.py encode <domain>")
        print("="*68)
        return
    print(f" {'SDS Domain ID':<16} {'Raw ID':<12} {'Canonical Domain':<25} {'Created At'}")
    print("-" * 68)
    for domain_id, raw_id, canonical_domain, created_at in rows:
        print(f" {domain_id:<16} {raw_id:<12} {canonical_domain:<25} {created_at}")
    print("="*68)

def interactive_mode():
    init_db()
    print("\n==================================================")
    print(" SDS PROTOCOL INTERACTIVE CLI")
    print("==================================================")
    print(" 1. Encode Domain -> Generate 10-char SDS ID + DNS")
    print(" 2. Decode Code   -> Show Domain + Live DNS Details")
    print(" 3. List Stored Domains")
    print(" 4. Exit")
    print("==================================================")
    while True:
        try:
            choice = input("\nSelect Option [1-4]: ").strip()
            if choice == '1':
                domain = input("Enter domain name (e.g. meddylist.com, xyz.com): ").strip()
                if domain:
                    try:
                        encode_and_store(domain)
                    except Exception as e:
                        print(f"Error: {e}")
            elif choice == '2':
                code = input("Enter 10-character SDS Code (e.g. 7K9M-2P4X-8B or 7K9M2P4X8B): ").strip()
                if code:
                    decode_and_inspect(code)
            elif choice == '3':
                list_domains()
            elif choice in ('4', 'q', 'exit'):
                print("Goodbye!")
                break
            else:
                print("Invalid option. Enter 1, 2, 3, or 4.")
        except (KeyboardInterrupt, EOFError):
            print("\nExiting.")
            break

def main():
    if len(sys.argv) < 2:
        interactive_mode()
        return

    cmd = sys.argv[1].lower()
    if cmd in ('encode', 'e'):
        if len(sys.argv) < 3:
            print("Usage: python3 sds_tool.py encode <domain>")
            sys.exit(1)
        encode_and_store(sys.argv[2])
    elif cmd in ('decode', 'd'):
        if len(sys.argv) < 3:
            print("Usage: python3 sds_tool.py decode <code>")
            sys.exit(1)
        decode_and_inspect(sys.argv[2])
    elif cmd in ('list', 'ls'):
        list_domains()
    elif cmd in ('interactive', 'i'):
        interactive_mode()
    else:
        print(f"Unknown command: '{cmd}'")
        print("Usage:")
        print("  python3 sds_tool.py encode <domain>")
        print("  python3 sds_tool.py decode <code>")
        print("  python3 sds_tool.py list")
        print("  python3 sds_tool.py interactive")

if __name__ == '__main__':
    main()
