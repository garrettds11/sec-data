"""Shared, deterministic identities and topology for synthetic runs."""

import hashlib
import json
import random
from ipaddress import ip_network

from common.assets import iter_hosts

VERSION = "1.0"
SERVICES = {
    "web": {22, 80, 443}, "app": {22, 8080}, "db": {22, 5432},
    "dc": {53, 88, 389, 445}, "win": {445, 3389}, "bastion": {22},
}
PUBLIC_IPS = {f"prod-web-{i:02d}": f"198.51.100.{10+i}" for i in range(1, 5)}
ENTITIES = (
    {"entity_id": "entity-external-scanner-01", "kind": "external_host",
     "name": "external-scanner-01", "ip": "203.0.113.50", "role": "scanner",
     "managed": False, "authorized": False},
    {"entity_id": "entity-approved-scanner-01", "kind": "internal_host",
     "name": "scanner-control.corp.example.local", "ip": "10.10.6.200",
     "role": "approved_scanner", "managed": True, "authorized": True},
    {"entity_id": "entity-enterprise-resolver-01", "kind": "internal_service",
     "name": "enterprise-resolver-01", "ip": "10.10.4.10",
     "role": "dns_resolver", "managed": True, "authorized": True},
)
ENTITY_IPS = {entity["entity_id"]: entity["ip"] for entity in ENTITIES}


def asset_id(host):
    """Inventory position is stable for a fixed seed and expansion count."""
    return f"asset-{host['idx']:07d}"


def run_id(seed, start_time, host_count, duration_minutes, campaign_count,
           recipe_sha256=""):
    key = json.dumps([VERSION, seed, start_time, host_count, duration_minutes,
                      campaign_count, recipe_sha256], separators=(",", ":"))
    return "run-" + hashlib.sha256(key.encode()).hexdigest()[:20]


def iter_assets(seed, host_count):
    for host in iter_hosts(random.Random(seed), host_count):
        yield {
            "asset_id": asset_id(host), "short_name": host["short"],
            "fqdn": host["fqdn"], "ip": host["ip"], "mac": host["mac"],
            "network_segment": str(ip_network(host["ip"] + "/24", strict=False)),
            "role": host["role"], "environment": host["env"],
            "os": host["os"], "family": host["family"],
            "externally_exposed": host["external"],
            "authenticated_scanning": host["authenticated"],
            "synthetic": True,
        }


def iter_entities():
    for entity in ENTITIES:
        yield {**entity, "synthetic": True}


def iter_relationships(seed, host_count):
    """Current-state edges; all IDs resolve in the exported world catalog."""
    for host in iter_hosts(random.Random(seed), host_count):
        aid = asset_id(host)
        yield {"relationship_id": f"{aid}-dns-a", "kind": "dns_a",
               "asset_id": aid, "name": host["fqdn"],
               "address": host["ip"]}
        for port in sorted(SERVICES[host["role"]]):
            yield {"relationship_id": f"{aid}-tcp-{port}", "kind": "listens_on",
                   "asset_id": aid, "transport": "tcp",
                   "port": port}
        if host["short"] in PUBLIC_IPS:
            for port in (80, 443):
                yield {"relationship_id": f"{aid}-public-tcp-{port}",
                       "kind": "public_exposure", "asset_id": aid,
                       "public_ip": PUBLIC_IPS[host["short"]],
                       "private_ip": host["ip"], "transport": "tcp", "port": port}
