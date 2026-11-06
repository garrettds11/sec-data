"""Deterministic routine sessions in source-specific CIM event streams."""

import hashlib
import json
from datetime import timedelta, timezone

VERSION = "2"
DEFAULT_MIX = {"web": 5, "file": 2, "egress": 2, "ingress": 1}
SESSION_SOURCES = {
    "web": ("resolver-dns.jsonl", "web-auth.jsonl", "eastwest-firewall.jsonl", "web-app.jsonl"),
    "file": ("windows-security.jsonl", "sysmon.jsonl", "windows-file.jsonl"),
    "egress": ("egress-firewall.jsonl", "zeek-conn.jsonl", "zeek-http.jsonl"),
    "ingress": ("ingress-firewall.jsonl", "ingress-zeek-conn.jsonl",
                "ingress-zeek-http.jsonl", "edge-proxy.jsonl"),
}
DATASETS = {
    "resolver-dns.jsonl": "Network_Resolution.DNS",
    "web-auth.jsonl": "Authentication.Authentication",
    "eastwest-firewall.jsonl": "Network_Traffic.All_Traffic",
    "web-app.jsonl": "Web.Web",
    "windows-security.jsonl": "Authentication.Authentication",
    "sysmon.jsonl": "Endpoint.Processes",
    "windows-file.jsonl": "Data_Access.Data_Access",
    "egress-firewall.jsonl": "Network_Traffic.All_Traffic",
    "zeek-conn.jsonl": "Network_Traffic.All_Traffic",
    "zeek-http.jsonl": "Web.Web",
    "ingress-firewall.jsonl": "Network_Traffic.All_Traffic",
    "ingress-zeek-conn.jsonl": "Network_Traffic.All_Traffic",
    "ingress-zeek-http.jsonl": "Web.Web",
    "edge-proxy.jsonl": "Web.Web",
}


def validate_mix(mix):
    if (not isinstance(mix, dict) or set(mix) != set(SESSION_SOURCES)
            or any(type(value) is not int or not 0 <= value <= 100
                   for value in mix.values()) or not any(mix.values())):
        raise ValueError("Background mix requires web, file, egress, and ingress integer weights "
                         "from 0 to 100, with at least one positive weight")
    return mix


def _id(run_id, *parts):
    return hashlib.sha256("|".join(map(str, (run_id, *parts))).encode()).hexdigest()[:24]


def _rows(path):
    with open(path, encoding="utf-8") as stream:
        return [json.loads(line) for line in stream if line.strip()]


def iter_events(seed, start, duration_minutes, count, assets_path, entities_path,
                run_id, mix=None):
    """Yield time-ordered sessions; each observation carries its sensor source."""
    if count < 0 or start.tzinfo is None or duration_minutes <= 0:
        raise ValueError("Background needs nonnegative count, aware start, positive duration")
    weights = validate_mix(DEFAULT_MIX if mix is None else mix)
    pattern = tuple(kind for kind in SESSION_SOURCES for _ in range(weights[kind]))
    assets, entities = _rows(assets_path), _rows(entities_path)
    clients = [r for r in assets if r["role"] in {"app", "win", "bastion"}]
    webs = [r for r in assets if r["role"] == "web"]
    files = [r for r in assets if r["short_name"].startswith("prod-file-")]
    bastions = [r for r in assets if r["role"] == "bastion"]
    resolver = next(r for r in entities if r["role"] == "dns_resolver")
    backup = next(r for r in entities if r["role"] == "backup_provider")
    monitor = next(r for r in entities if r["role"] == "external_monitor")
    if not (clients and webs and files and bastions):
        raise ValueError("Background inventory lacks required client, web, file, or bastion")
    number = session = 0
    while number < count:
        kind = pattern[session % len(pattern)]
        client, web = clients[(session + seed) % len(clients)], webs[(session + seed) % len(webs)]
        file_host, bastion = files[(session + seed) % len(files)], bastions[0]
        sid, port = _id(run_id, "session", session), 40000 + session % 20000
        for part, source in enumerate(SESSION_SOURCES[kind]):
            if number >= count:
                break
            event = {
                "time": (start + timedelta(milliseconds=number * duration_minutes * 60000 // max(count, 1)))
                        .astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
                "synthetic": True, "sec_data_source": source,
                "sec_data_cim_dataset": DATASETS[source],
                "event_id": _id(run_id, "event", number), "session_id": sid,
            }
            if kind == "web":
                if part == 0:
                    event.update(src=client["ip"], src_port=port, dest=resolver["ip"],
                                 dest_port=53, dvc=resolver["name"], query=web["fqdn"],
                                 query_type="A", record_type="A", answer=[web["ip"]],
                                 ttl=[300], answer_count=1, query_count=1, message_type="Response",
                                 reply_code="No Error", reply_code_id=0,
                                 transaction_id=session % 65536, transport="udp",
                                 response_time=0.003)
                elif part == 1:
                    event.update(src=client["ip"], dest=web["fqdn"], dvc=web["short_name"],
                                 user="LAB\\analyst", action="success", app="web")
                elif part == 2:
                    event.update(src=client["ip"], src_port=port, dest=web["ip"], dest_port=80,
                                 dvc="eastwest-fw-01", transport="tcp", action="allowed",
                                 app="http", duration=0.05, bytes_out=200, bytes_in=1200,
                                 bytes=1400)
                else:
                    event.update(src=client["ip"], src_port=port, dest=web["ip"], dest_port=80,
                                 dvc=web["short_name"], url=f"{web['fqdn']}/health",
                                 http_method="GET", status=200, bytes_in=200, bytes_out=1200)
            elif kind == "file":
                if part == 0:
                    event.update(src=bastion["ip"], dest=file_host["fqdn"],
                                 dvc=file_host["short_name"], user="LAB\\svc_backup",
                                 action="success", app="smb")
                elif part == 1:
                    event.update(dest=file_host["fqdn"], dvc=file_host["short_name"],
                                 user="LAB\\svc_backup",
                                 process="C:\\Windows\\System32\\robocopy.exe",
                                 process_id=2000 + session % 10000)
                else:
                    event.update(dest=file_host["fqdn"],
                                 dvc=file_host["short_name"], user="LAB\\svc_backup",
                                 object=f"archive-{session % 32:02d}.zip",
                                 object_path=f"C:\\Data\\archive-{session % 32:02d}.zip",
                                 action="read", access_result="success",
                                 object_category="file", signature_id=4663)
            elif kind == "egress":
                if part < 2:
                    event.update(src=client["ip"], src_port=port, dest=backup["ip"],
                                 dest_port=443, dvc="egress-fw-01" if part == 0 else "zeek-01",
                                 transport="tcp", action="allowed", duration=0.1,
                                 bytes_out=640, bytes_in=1200, bytes=1840)
                else:
                    event.update(src=client["ip"], src_port=port, dest=backup["ip"],
                                 dest_port=443, dvc="zeek-01", url=f"{backup['name']}/health",
                                 http_method="GET", status=200, bytes_in=640, bytes_out=1200)
            else:
                event.update(src=monitor["ip"], src_port=port, dest=web["ip"],
                             dest_port=80)
                if part < 2:
                    event.update(dvc="perimeter-fw-01" if part == 0 else "ingress-zeek-01",
                                 transport="tcp", action="allowed", app="http",
                                 bytes_out=180, bytes_in=512, bytes=692,
                                 duration=0.08)
                else:
                    event.update(dvc="ingress-zeek-01" if part == 2 else "edge-proxy-01",
                                 url=f"{web['fqdn']}/health", http_method="GET",
                                 status=200, bytes_in=180, bytes_out=512)
            yield event
            number += 1
        session += 1
