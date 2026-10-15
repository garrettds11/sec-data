"""Shared synthetic asset inventory for vulnerability and compliance generators.

Keep RNG call order unchanged for compatibility with create_vuln_table.py.
"""
import random

HOSTS = (
    [(f"prod-web-{i:02d}", "web", "prod") for i in range(1, 5)]
    + [(f"stage-web-{i:02d}", "web", "stage") for i in range(1, 3)]
    + [("dev-web-01", "web", "dev")]
    + [(f"prod-app-{i:02d}", "app", "prod") for i in range(1, 5)]
    + [("stage-app-01", "app", "stage"), ("dev-app-01", "app", "dev"), ("dev-app-02", "app", "dev")]
    + [("prod-db-01", "db", "prod"), ("prod-db-02", "db", "prod"), ("dev-db-01", "db", "dev")]
    + [("dc-01", "dc", "prod"), ("dc-02", "dc", "prod")]
    + [("prod-file-01", "win", "prod"), ("prod-file-02", "win", "prod"), ("prod-rdp-01", "win", "prod")]
    + [("bastion-01", "bastion", "prod")]
)
LINUX_OS = ["Ubuntu 22.04 LTS", "Ubuntu 20.04 LTS", "Red Hat Enterprise Linux 8.9", "Debian 12"]
WIN_OS = ["Windows Server 2019", "Windows Server 2022"]
VENDORS = ["Tenable", "Qualys", "Rapid7"]
ENV_OCTET = {"prod": 10, "stage": 20, "dev": 30}
ROLE_OCTET = {"web": 1, "app": 2, "db": 3, "dc": 4, "win": 5, "bastion": 6}


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def build_hosts(rng):
    hosts = []
    for idx, (name, role, env) in enumerate(HOSTS):
        family = "windows" if role in ("dc", "win") else "linux"
        external = role == "web" and env == "prod"
        authenticated = False if external else rng.random() < 0.8
        hosts.append(dict(
            short=name, role=role, env=env, family=family,
            fqdn=f"{name}.corp.example.local",
            ip=f"10.{ENV_OCTET[env]}.{ROLE_OCTET[role]}.{10 + idx}",
            mac="00:50:56:%02x:%02x:%02x" % (rng.randint(0, 255), rng.randint(0, 255), rng.randint(0, 255)),
            os=rng.choice(WIN_OS if family == "windows" else LINUX_OS),
            vendor=rng.choice(VENDORS),
            external=external, authenticated=authenticated, idx=idx,
        ))
    return hosts

