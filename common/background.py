"""Stream linked, benign CIM-shaped background sessions at a requested scale."""

import json
from datetime import timedelta
from itertools import islice


DATASETS = (
    "Network_Resolution.DNS", "Authentication.Authentication",
    "Network_Traffic.All_Traffic", "Web.Web",
)
VERSION = "1"


def iter_events(seed, start, duration_minutes, count, assets_path, entities_path,
                run_id):
    """Yield DNS, login, connection, and web observations without retaining rows."""
    if count < 0:
        raise ValueError("Background event count cannot be negative")
    with open(assets_path, encoding="utf-8") as stream:
        assets = [json.loads(line) for line in islice((line for line in stream
                                                      if line.strip()), 23)]
    with open(entities_path, encoding="utf-8") as stream:
        entities = [json.loads(line) for line in stream if line.strip()]
    servers = [asset for asset in assets if asset["role"] == "web"]
    if len(assets) < 2 or not servers:
        raise ValueError("Background sessions need a client and a web server")
    resolver = next(entity["ip"] for entity in entities
                    if entity["role"] == "dns_resolver")
    duration_ms = duration_minutes * 60 * 1000
    for number in range(count):
        session, kind = divmod(number, 4)
        client = assets[(session + seed) % len(assets)]
        server = servers[(session // len(assets) + seed) % len(servers)]
        if client["asset_id"] == server["asset_id"]:
            client = assets[(session + seed + 1) % len(assets)]
        session_id = f"bg-{run_id[-8:]}-{session:09d}"
        event = {
            "time": (start + timedelta(milliseconds=number * duration_ms // max(count, 1)))
                    .isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "synthetic": True,
            "sec_data_source": "background-session.jsonl",
            "sec_data_cim_dataset": DATASETS[kind],
            "event_id": f"{session_id}-{kind}",
            "session_id": session_id,
        }
        request_bytes = 180 + session % 120
        response_bytes = 1024 + session % 4096
        if kind == 0:
            event.update(src=client["ip"], src_port=40000 + session % 20000,
                         dest=resolver, dest_port=53, query=server["fqdn"],
                         query_type="A", record_type="A", answer=[server["ip"]],
                         ttl=[300], answer_count=1, query_count=1,
                         message_type="Response", reply_code="No Error",
                         reply_code_id=0, transaction_id=session % 65536,
                         transport="udp", response_time=0.003)
        elif kind == 1:
            event.update(src=client["ip"], dest=server["fqdn"],
                         user="LAB\\analyst", action="success", app="web")
        elif kind == 2:
            event.update(src=client["ip"], src_port=40000 + session % 20000,
                         dest=server["ip"], dest_port=80, transport="tcp",
                         action="allowed", app="http", duration=0.05,
                         bytes_out=request_bytes, bytes_in=response_bytes,
                         bytes=request_bytes + response_bytes)
        else:
            event.update(src=client["ip"], src_port=40000 + session % 20000,
                         dest=server["ip"], dest_port=80,
                         url=f"{server['fqdn']}/health", http_method="GET",
                         status=200, bytes_in=request_bytes,
                         bytes_out=response_bytes)
        yield event
