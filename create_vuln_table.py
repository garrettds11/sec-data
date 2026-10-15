#!/usr/bin/env python3
"""
Create a DynamoDB table of synthetic vulnerability-scan findings and load it.

Table design (one item = one finding on one asset):
  PK  host_name      FQDN of the scanned asset         (ECS: host.name)
  SK  finding_id     "<vulnerability_id>#<proto>/<port>"
  GSI severity-lastseen-index : vulnerability_severity (PK) + last_seen (SK)
  GSI vuln-host-index         : vulnerability_id (PK)       + host_name (SK)

Attribute names follow the ECS vulnerability field set, flattened with "_"
instead of "." (vulnerability.score.base -> vulnerability_score_base).
Fields ECS does not define (title, CWE, CVSS vector, EPSS, exploit flag,
plugin id, scan type/network, port/service, MAC, OS) use plain names.

Data notes:
  * CVE IDs/titles are real; CVSS scores are computed from the vector
    (CVSS 3.1 formula); EPSS values are illustrative, not live.
  * A few findings are deliberately "planted" so test questions have
    known answers. The summary printed at the end reports them.

Usage:
  python create_vuln_table.py --dry-run                 # no AWS calls
  python create_vuln_table.py --region us-east-1        # create + load
  python create_vuln_table.py --region us-east-1 --append
  python create_vuln_table.py --region us-east-1 --delete
Requires: boto3 (not needed for --dry-run).
"""
import argparse
import math
import random
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from decimal import Decimal

DEFAULT_TABLE = "aiwebdemo-vuln-findings"
GSI_SEVERITY = "severity-lastseen-index"
GSI_VULN = "vuln-host-index"


# --------------------------------------------------------------------------
# CVSS 3.1 base score calculator (so score and vector always agree)
# --------------------------------------------------------------------------
def _roundup(x):
    i = round(x * 100000)
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def cvss31(vector):
    p = dict(part.split(":") for part in vector.split("/")[1:])
    changed = p["S"] == "C"
    av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[p["AV"]]
    ac = {"L": 0.77, "H": 0.44}[p["AC"]]
    pr = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}[p["PR"]]
    ui = {"N": 0.85, "R": 0.62}[p["UI"]]
    cia = {"H": 0.56, "L": 0.22, "N": 0.0}
    iss = 1 - (1 - cia[p["C"]]) * (1 - cia[p["I"]]) * (1 - cia[p["A"]])
    if changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    if impact <= 0:
        return 0.0
    expl = 8.22 * av * ac * pr * ui
    raw = 1.08 * (impact + expl) if changed else impact + expl
    return _roundup(min(raw, 10))


def severity_for(score):
    if score == 0:
        return "Info"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


# --------------------------------------------------------------------------
# Vulnerability catalog
# --------------------------------------------------------------------------
def V(vid, title, desc, cwe, vector, port, proto, service, roles, cats,
      exploit, epss, family="any", local=False, planted_only=False, plugin=None):
    return dict(id=vid, title=title, desc=desc, cwe=cwe, vector=vector,
                port=port, proto=proto, service=service, roles=roles,
                cats=cats, exploit=exploit, epss=epss, family=family,
                local=local, planted_only=planted_only, plugin=plugin)


NET = "AV:N/AC:L/PR:N/UI:N/S:U"
CATALOG = [
    V("CVE-2023-48795", "OpenSSH Terrapin Attack Vulnerability",
      "Prefix truncation in the SSH transport protocol lets a network attacker downgrade connection security.",
      "CWE-354", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N", 22, "tcp", "OpenSSH 9.3p1",
      ["web", "app", "db", "bastion"], ["SSH"], False, 0.056, family="linux"),
    V("CVE-2021-44228", "Apache Log4j2 JNDI Remote Code Execution (Log4Shell)",
      "Crafted log messages trigger JNDI lookups that load attacker-controlled code.",
      "CWE-502", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 8080, "tcp",
      "Apache Tomcat 9.0.54 (log4j-core 2.14.1)", ["app"], ["Web Application", "Java"],
      True, 0.944, family="linux", planted_only=True),
    V("CVE-2014-0160", "OpenSSL Heartbleed Information Disclosure",
      "Missing bounds check in the TLS heartbeat extension leaks process memory.",
      "CWE-125", f"CVSS:3.1/{NET}/C:H/I:N/A:N", 443, "tcp", "OpenSSL 1.0.1f",
      ["web"], ["Web Server", "TLS"], True, 0.944, family="linux", planted_only=True),
    V("CVE-2017-0144", "Microsoft SMBv1 Remote Code Execution (EternalBlue, MS17-010)",
      "Crafted SMBv1 packets allow remote code execution on unpatched Windows hosts.",
      "CWE-20", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 445, "tcp", "Microsoft SMBv1",
      ["win", "dc"], ["Windows", "SMB"], True, 0.944, family="windows"),
    V("CVE-2022-22965", "Spring Framework Data Binding Remote Code Execution (Spring4Shell)",
      "Data binding on JDK 9+ can be abused to write a web shell to the application server.",
      "CWE-94", f"CVSS:3.1/{NET}/C:H/I:H/A:H", 8080, "tcp", "Spring Framework 5.3.17",
      ["app"], ["Web Application", "Java"], True, 0.943, family="linux"),
    V("CVE-2023-44487", "HTTP/2 Rapid Reset Denial of Service",
      "Rapid stream creation and cancellation exhausts server resources.",
      "CWE-400", f"CVSS:3.1/{NET}/C:N/I:N/A:H", 443, "tcp", "nginx 1.24.0",
      ["web"], ["Web Server"], True, 0.682, family="linux"),
    V("CVE-2021-41773", "Apache HTTP Server 2.4.49 Path Traversal",
      "Path normalization flaw allows reading files outside the document root.",
      "CWE-22", f"CVSS:3.1/{NET}/C:H/I:N/A:N", 80, "tcp", "Apache httpd 2.4.49",
      ["web"], ["Web Server"], True, 0.944, family="linux"),
    V("CVE-2024-3094", "XZ Utils liblzma Backdoor",
      "Malicious code in upstream xz release tarballs can compromise sshd authentication.",
      "CWE-506", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 22, "tcp",
      "OpenSSH 9.7p1 (xz-utils 5.6.0)", ["bastion"], ["SSH", "Supply Chain"],
      False, 0.092, family="linux", planted_only=True),
    V("CVE-2024-6387", "OpenSSH Signal Handler Race Condition (regreSSHion)",
      "Race condition in sshd signal handling can lead to unauthenticated remote code execution.",
      "CWE-364", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 22, "tcp", "OpenSSH 9.2p1",
      ["web", "app", "db", "bastion"], ["SSH"], False, 0.168, family="linux"),
    V("CVE-2020-1472", "Netlogon Elevation of Privilege (Zerologon)",
      "Weak cryptography in the Netlogon protocol lets an attacker impersonate a domain controller.",
      "CWE-330", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 445, "tcp", "Netlogon (MS-NRPC)",
      ["dc"], ["Windows", "Active Directory"], True, 0.943, family="windows", planted_only=True),
    V("CVE-2019-0708", "Remote Desktop Services Remote Code Execution (BlueKeep)",
      "Pre-authentication use-after-free in RDP allows remote code execution.",
      "CWE-416", f"CVSS:3.1/{NET}/C:H/I:H/A:H", 3389, "tcp", "Microsoft RDP",
      ["win"], ["Windows", "RDP"], True, 0.944, family="windows", planted_only=True),
    V("CVE-2023-4863", "libwebp Heap Buffer Overflow",
      "A crafted WebP image can trigger a heap overflow when processed.",
      "CWE-787", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 443, "tcp", "libwebp 1.3.1",
      ["web", "app"], ["Web Application", "Library"], False, 0.12, family="linux"),
    V("CVE-2021-3156", "sudo Heap-Based Buffer Overflow (Baron Samedit)",
      "A local user can gain root through a heap overflow in sudoedit argument parsing.",
      "CWE-122", "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 0, "local", "sudo 1.9.5p1",
      ["web", "app", "db", "bastion"], ["Linux", "Privilege Escalation"],
      True, 0.905, family="linux", local=True),
    V("CVE-2022-0847", "Linux Kernel Dirty Pipe Privilege Escalation",
      "Improper pipe buffer flag initialization lets local users overwrite read-only files.",
      "CWE-665", "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 0, "local", "Linux kernel 5.15.0",
      ["web", "app", "db", "bastion"], ["Linux", "Privilege Escalation"],
      True, 0.855, family="linux", local=True),
    V("CVE-2016-2183", "TLS 3DES Birthday Attack (Sweet32)",
      "64-bit block ciphers such as 3DES allow plaintext recovery in long-lived sessions.",
      "CWE-327", f"CVSS:3.1/{NET}/C:H/I:N/A:N", 443, "tcp", "TLS (3DES cipher suites)",
      ["web", "app"], ["TLS"], False, 0.013),
    V("CVE-2015-4000", "TLS DHE_EXPORT Downgrade (Logjam)",
      "A man-in-the-middle can downgrade TLS connections to 512-bit export-grade Diffie-Hellman.",
      "CWE-326", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N", 443, "tcp",
      "TLS (DHE_EXPORT)", ["web"], ["TLS"], False, 0.009),
    # Informational / plugin-only findings (no CVE)
    V("PLUGIN-104743", "TLS Version 1.0 Protocol Detection",
      "The service accepts connections encrypted with the deprecated TLS 1.0 protocol.",
      None, None, 443, "tcp", "TLS 1.0", ["web", "app", "win"], ["TLS"], False, None,
      plugin="104743"),
    V("PLUGIN-57582", "SSL Self-Signed Certificate",
      "The certificate chain is rooted in a self-signed certificate that clients cannot verify.",
      None, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N", 443, "tcp", "TLS certificate",
      ["web", "app", "win", "dc"], ["TLS"], False, None, plugin="57582"),
]

# (host short name, vulnerability id) -> forced status
PLANTED = {
    ("prod-app-01", "CVE-2021-44228"): "open",
    ("prod-app-02", "CVE-2021-44228"): "open",
    ("prod-app-03", "CVE-2021-44228"): "fixed",
    ("prod-web-02", "CVE-2014-0160"): "reopened",
    ("dc-01", "CVE-2020-1472"): "open",
    ("dc-02", "CVE-2020-1472"): "fixed",
    ("bastion-01", "CVE-2024-3094"): "open",
    ("bastion-01", "CVE-2024-6387"): "open",
    ("prod-rdp-01", "CVE-2019-0708"): "open",
}

# --------------------------------------------------------------------------
# Assets
# --------------------------------------------------------------------------
from common.assets import HOSTS, LINUX_OS, WIN_OS, VENDORS, ENV_OCTET, ROLE_OCTET, iso, build_hosts


def build_runs(rng, now):
    """Per vendor: 4 scan runs, newest first."""
    runs, counter = {}, 1
    for vendor in VENDORS:
        days = [rng.randint(1, 6)] + [14 + 14 * k + rng.randint(0, 3) for k in range(3)]
        vruns = []
        for d in days:
            dt = (now - timedelta(days=d)).replace(hour=2, minute=rng.randint(0, 30), second=0, microsecond=0)
            vruns.append(dict(dt=dt, report_id=f"{dt:%Y%m%d}.{counter:04d}"))
            counter += 1
        runs[vendor] = vruns
    return runs


def plugin_id(vendor, vid, plugin):
    if plugin:
        return plugin
    return str(100000 + (hash_stable(f"{vendor}:{vid}") % 900000))


def hash_stable(s):
    import zlib
    return zlib.crc32(s.encode())


def build_items(seed):
    rng = random.Random(seed)
    now = datetime.now(timezone.utc)
    hosts = build_hosts(rng)
    runs = build_runs(rng, now)
    items = []
    for h in hosts:
        for v in CATALOG:
            key = (h["short"], v["id"])
            if key in PLANTED:
                status = PLANTED[key]
            else:
                if v["planted_only"] or h["role"] not in v["roles"]:
                    continue
                if v["family"] not in ("any", h["family"]):
                    continue
                if v["local"] and not h["authenticated"]:
                    continue
                if rng.random() >= 0.55:
                    continue
                status = "fixed" if rng.random() < 0.28 else "open"

            vruns = runs[h["vendor"]]
            if status == "fixed":
                run = vruns[rng.choice([2, 3])]
            else:
                run = vruns[0] if rng.random() < 0.7 else vruns[1]
            last_seen = run["dt"] + timedelta(minutes=h["idx"] * 3)
            first_seen = last_seen - timedelta(days=rng.randint(5, 150))

            score = cvss31(v["vector"]) if v["vector"] else 0.0
            item = {
                "host_name": h["fqdn"],
                "finding_id": f"{v['id']}#{v['proto']}/{v['port']}",
                "environment": h["env"],
                "host_ip": h["ip"],
                "host_mac": h["mac"],
                "host_os_full": h["os"],
                "network_port": v["port"],
                "network_protocol": v["proto"],
                "service_name": v["service"],
                "vulnerability_id": v["id"],
                "vulnerability_enumeration": "CVE" if v["id"].startswith("CVE-") else "Plugin",
                "vulnerability_classification": "CVSS",
                "vulnerability_category": v["cats"],
                "vulnerability_description": v["desc"],
                "vulnerability_reference": (
                    [f"https://nvd.nist.gov/vuln/detail/{v['id']}", f"https://www.cve.org/CVERecord?id={v['id']}"]
                    if v["id"].startswith("CVE-")
                    else [f"https://www.tenable.com/plugins/nessus/{v['plugin']}"]
                ),
                "vulnerability_report_id": run["report_id"],
                "vulnerability_scanner_vendor": h["vendor"],
                "vulnerability_score_base": Decimal(str(score)),
                "vulnerability_score_version": "3.1",
                "vulnerability_severity": severity_for(score),
                "vulnerability_status": status,
                "title": v["title"],
                "scanner_plugin_id": plugin_id(h["vendor"], v["id"], v["plugin"]),
                "scan_type": "authenticated" if h["authenticated"] else "unauthenticated",
                "scan_network": "external" if h["external"] else "internal",
                "exploit_available": v["exploit"],
                "first_seen": iso(first_seen),
                "last_seen": iso(last_seen),
            }
            if v["vector"]:
                item["cvss_vector"] = v["vector"]
            if v["cwe"]:
                item["cwe_id"] = v["cwe"]
            if v["epss"] is not None:
                item["epss_score"] = Decimal(str(v["epss"]))
            items.append(item)
    return items


# --------------------------------------------------------------------------
# Summary
# --------------------------------------------------------------------------
def summarize(items):
    print(f"\nGenerated {len(items)} findings on {len({i['host_name'] for i in items})} hosts")
    order = ["Critical", "High", "Medium", "Low", "Info"]
    by = defaultdict(Counter)
    for i in items:
        by[i["vulnerability_severity"]][i["vulnerability_status"]] += 1
    print("\nSeverity x status")
    print(f"  {'severity':<10}{'open':>6}{'fixed':>7}{'reopened':>10}")
    for s in order:
        c = by[s]
        print(f"  {s:<10}{c['open']:>6}{c['fixed']:>7}{c['reopened']:>10}")

    def hosts_for(vid):
        return sorted(f"{i['host_name'].split('.')[0]} ({i['vulnerability_status']})"
                      for i in items if i["vulnerability_id"] == vid)

    print("\nPlanted facts you can test against")
    print("  Log4Shell CVE-2021-44228 :", ", ".join(hosts_for("CVE-2021-44228")))
    print("  Heartbleed CVE-2014-0160 :", ", ".join(hosts_for("CVE-2014-0160")))
    print("  Zerologon CVE-2020-1472  :", ", ".join(hosts_for("CVE-2020-1472")))
    print("  xz backdoor CVE-2024-3094:", ", ".join(hosts_for("CVE-2024-3094")))
    print("  BlueKeep CVE-2019-0708   :", ", ".join(hosts_for("CVE-2019-0708")))
    reopened = [i["host_name"].split(".")[0] + " / " + i["vulnerability_id"]
                for i in items if i["vulnerability_status"] == "reopened"]
    print("  Reopened findings        :", ", ".join(reopened) or "none")
    exploitable = {i["host_name"] for i in items
                   if i["vulnerability_status"] == "open" and i["exploit_available"]
                   and i["vulnerability_severity"] in ("Critical", "High")}
    print(f"  Hosts with an open Critical/High finding that has a public exploit: {len(exploitable)}")
    top = Counter(i["host_name"].split(".")[0] for i in items
                  if i["vulnerability_status"] in ("open", "reopened")
                  and i["vulnerability_severity"] == "Critical")
    print("  Open Critical count, top hosts      :", ", ".join(f"{h}={n}" for h, n in top.most_common(5)))


# --------------------------------------------------------------------------
# AWS
# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--table", default=DEFAULT_TABLE)
    ap.add_argument("--region")
    ap.add_argument("--profile")
    ap.add_argument("--project-tag", default="aiwebdemo", help="value for the project=<value> tag")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--dry-run", action="store_true", help="generate and summarize only; no AWS calls")
    ap.add_argument("--append", action="store_true", help="load into an existing table (same keys are overwritten)")
    ap.add_argument("--delete", action="store_true", help="delete the table (asks for confirmation)")
    args = ap.parse_args()

    if args.dry_run:
        items = build_items(args.seed)
        summarize(items)
        print("\nSample item:")
        for k, v in sorted(items[0].items()):
            print(f"  {k}: {v}")
        return

    try:
        import boto3
    except ImportError:
        sys.exit("boto3 is required: pip install boto3")

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    if not session.region_name:
        sys.exit("No region set. Pass --region or configure a default region.")
    client = session.client("dynamodb")
    ddb = session.resource("dynamodb")
    print(f"Account/region: {session.client('sts').get_caller_identity()['Account']} / {session.region_name}")

    exists = True
    try:
        client.describe_table(TableName=args.table)
    except client.exceptions.ResourceNotFoundException:
        exists = False

    if args.delete:
        if not exists:
            sys.exit(f"Table {args.table} does not exist.")
        if input(f"Type the table name '{args.table}' to confirm deletion: ").strip() != args.table:
            sys.exit("Aborted.")
        client.delete_table(TableName=args.table)
        client.get_waiter("table_not_exists").wait(TableName=args.table)
        print("Deleted.")
        return

    if exists and not args.append:
        sys.exit(f"Table {args.table} already exists. Use --append to load into it, or --delete first.")

    if not exists:
        print(f"Creating table {args.table} (on-demand)...")
        client.create_table(
            TableName=args.table,
            BillingMode="PAY_PER_REQUEST",
            AttributeDefinitions=[
                {"AttributeName": "host_name", "AttributeType": "S"},
                {"AttributeName": "finding_id", "AttributeType": "S"},
                {"AttributeName": "vulnerability_severity", "AttributeType": "S"},
                {"AttributeName": "last_seen", "AttributeType": "S"},
                {"AttributeName": "vulnerability_id", "AttributeType": "S"},
            ],
            KeySchema=[
                {"AttributeName": "host_name", "KeyType": "HASH"},
                {"AttributeName": "finding_id", "KeyType": "RANGE"},
            ],
            GlobalSecondaryIndexes=[
                {"IndexName": GSI_SEVERITY,
                 "KeySchema": [{"AttributeName": "vulnerability_severity", "KeyType": "HASH"},
                               {"AttributeName": "last_seen", "KeyType": "RANGE"}],
                 "Projection": {"ProjectionType": "ALL"}},
                {"IndexName": GSI_VULN,
                 "KeySchema": [{"AttributeName": "vulnerability_id", "KeyType": "HASH"},
                               {"AttributeName": "host_name", "KeyType": "RANGE"}],
                 "Projection": {"ProjectionType": "ALL"}},
            ],
            Tags=[{"Key": "project", "Value": args.project_tag}],
        )
        client.get_waiter("table_exists").wait(TableName=args.table)
        print("Table active.")

    items = build_items(args.seed)
    table = ddb.Table(args.table)
    print(f"Writing {len(items)} items...")
    with table.batch_writer() as batch:
        for item in items:
            batch.put_item(Item=item)
    print("Done.")
    summarize(items)


if __name__ == "__main__":
    main()
