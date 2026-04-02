import dns.resolver
import dns.reversename
import argparse
import concurrent.futures

DKIM_SELECTORS = ["default", "selector1", "selector2", "google", "mail"]

TLDS = [
    "com", "net", "org",
    "fr", "lu", "be", "de",
    "nl", "es", "it", "pt", "ch", "at", "pl",
    "co", "io", "info", "biz",
    "us", "ca",
    "app", "dev", "tech", "cloud", "ai",
    "online", "site", "store"
]

# ---------------- DNS HELPERS ----------------

def domain_exists(domain):
    try:
        dns.resolver.resolve(domain, "NS")
        return True
    except:
        try:
            dns.resolver.resolve(domain, "SOA")
            return True
        except:
            return False

def get_mx_records(domain):
    try:
        answers = dns.resolver.resolve(domain, "MX")
        return sorted([(r.preference, r.exchange.to_text()) for r in answers])
    except:
        return []

def get_ptr(ip):
    try:
        rev_name = dns.reversename.from_address(ip)
        answers = dns.resolver.resolve(rev_name, "PTR")
        return [r.to_text() for r in answers]
    except:
        return []

def get_txt_record(domain):
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        return [b"".join(r.strings).decode() for r in answers]
    except:
        return []

# ---------------- SPF / DMARC / DKIM ----------------

def get_spf(domain):
    for r in get_txt_record(domain):
        if r.lower().startswith("v=spf1"):
            return r
    return None

def parse_dmarc_policy(record):
    if not record:
        return None
    parts = record.split(";")
    for p in parts:
        if p.strip().startswith("p="):
            return p.split("=")[1]
    return "unknown"

def get_dmarc(domain):
    for r in get_txt_record(f"_dmarc.{domain}"):
        if r.lower().startswith("v=dmarc1"):
            return r
    return None

def get_dkim(domain):
    for selector in DKIM_SELECTORS:
        try:
            records = get_txt_record(f"{selector}._domainkey.{domain}")
            for r in records:
                if "v=DKIM1" in r:
                    return True
        except:
            continue
    return False

# ---------------- SPOOF LOGIC ----------------

def is_spoofable(spf, dmarc, exists):
    if not exists:
        return "❌", "domain does not exist"

    if not spf:
        return "🟢", "no SPF"

    if not dmarc:
        return "🟡", "no DMARC"

    if "p=none" in dmarc.lower():
        return "🟡", "DMARC none"

    return "🔴", ""

# ---------------- ANALYSIS ----------------

def analyze_domain_variant(base, tld, check_mx=False, check_ptr=False):
    domain = f"{base}.{tld}"

    exists = domain_exists(domain)
    spf = get_spf(domain)
    dmarc = get_dmarc(domain)
    dkim = get_dkim(domain)

    dmarc_policy = parse_dmarc_policy(dmarc)

    if not dmarc:
        dmarc_display = "❌"
    elif dmarc_policy == "none":
        dmarc_display = "❗ (none)"
    else:
        dmarc_display = f"✅ ({dmarc_policy})"

    mx_records = get_mx_records(domain) if check_mx else []
    ptrs = []

    if check_ptr and mx_records:
        for _, mx in mx_records:
            try:
                ips = dns.resolver.resolve(mx, "A")
                for ip in ips:
                    ptrs.extend(get_ptr(ip.to_text()))
            except:
                continue

    spoof, reason = is_spoofable(spf, dmarc, exists)

    return {
        "domain": domain,
        "exists": "✅" if exists else "❌",
        "spf": "✅" if spf else "❌",
        "dmarc": dmarc_display,
        "dkim": "✅" if dkim else "❌",
        "mx": ",".join([m[1] for m in mx_records]) if mx_records else ("❌" if check_mx else ""),
        "ptr": ",".join(ptrs) if ptrs else ("❌" if check_ptr else ""),
        "reason": reason if reason else "-",
        "spoof": spoof
    }

# ---------------- OUTPUT ----------------

def print_results(results, check_mx=False, check_ptr=False):
    headers = ["Domain", "Ex", "SPF", "DMARC", "DKIM"]

    if check_mx:
        headers.append("MX")
    if check_ptr:
        headers.append("PTR")

    headers.extend(["Reason", "Spoof"])

    # Largeurs personnalisées (resserrées)
    widths = {
        "Domain": 25,
        "Ex": 3,
        "SPF": 3,
        "DMARC": 15,
        "DKIM": 4,
        "MX": 25,
        "PTR": 25,
        "Reason": 30,
        "Spoof": 5
    }

    # Header
    print(" ".join(f"{h:<{widths[h]}}" for h in headers))
    print("-" * sum(widths[h] + 1 for h in headers))

    # Rows
    for r in results:
        row_map = {
            "Domain": r["domain"],
            "Ex": r["exists"],
            "SPF": r["spf"],
            "DMARC": r["dmarc"],
            "DKIM": r["dkim"],
            "MX": r["mx"],
            "PTR": r["ptr"],
            "Reason": r["reason"],
            "Spoof": r["spoof"]
        }

        row = []
        for h in headers:
            row.append(f"{str(row_map[h]):<{widths[h]}}")

        print(" ".join(row))

    # -------- CONCLUSION --------
    spoofable_domains = [r["domain"] for r in results if r["spoof"] in ["🟢", "🟡"]]

    if spoofable_domains:
        print("\n📝 Conclusion : Les domaines suivants peuvent être spoofés :")
        print("👉 " + ", ".join(spoofable_domains))
    else:
        print("\n✅ Conclusion : Aucun domaine spoofable détecté.")

# ---------------- MAIN ----------------

def main():
    parser = argparse.ArgumentParser(description="Audit SPF/DMARC/DKIM multi-TLD")
    parser.add_argument("domain", help="Domaine de base (ex: test)")
    parser.add_argument("--threads", type=int, default=10)
    parser.add_argument("--mx", action="store_true")
    parser.add_argument("--ptr", action="store_true")

    args = parser.parse_args()

    results = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [
            executor.submit(analyze_domain_variant, args.domain, tld, args.mx, args.ptr)
            for tld in TLDS
        ]
        for f in concurrent.futures.as_completed(futures):
            results.append(f.result())

    results.sort(key=lambda x: x["domain"])
    print_results(results, args.mx, args.ptr)

if __name__ == "__main__":
    main()
