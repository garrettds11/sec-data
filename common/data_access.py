"""Source-shaped file auditing and network observations for a linked transfer fixture."""

from datetime import datetime, timedelta, timezone

VERSION = "1.0"
OBJECTS = (
    {"object_id": "object-finance-report", "asset_short": "prod-file-01",
     "path": r"D:\Shares\Projects\Q4-forecast.csv", "classification": "confidential",
     "size_bytes": 4096},
    {"object_id": "object-backup-manifest", "asset_short": "prod-file-01",
     "path": r"D:\Shares\Operations\backup-manifest.json", "classification": "internal",
     "size_bytes": 16384},
    {"object_id": "object-payroll", "asset_short": "prod-file-01",
     "path": r"D:\Shares\HR\payroll.csv", "classification": "restricted",
     "size_bytes": 2048},
)


def stamp(value):
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def generate(seed, assets, entities, identity_truth, windows_auth):
    """Keep analyst-facing records source-visible; object and session links live in truth."""
    by_short = {row["short_name"]: row for row in assets}
    file, bastion, dc = (by_short[name] for name in ("prod-file-01", "bastion-01", "dc-01"))
    by_entity = {row["entity_id"]: row for row in entities}
    sessions = {row["identity_id"]: row for row in identity_truth["sessions"]}
    logons = {row["TargetUserName"]: row for row in windows_auth
              if row["EventCode"] == 4624 and row["Computer"] == file["fqdn"]}
    objects = [{**item, "asset_id": file["asset_id"], "synthetic": True} for item in OBJECTS]
    windows, conn, http, firewall, accesses, transfers = [], [], [], [], [], []

    def file_event(object_index, identity_id, account, when, success):
        obj = objects[object_index]
        record_id = 300001 + len(windows)
        row = {"TimeCreated": stamp(when), "Channel": "Security",
               "Provider": "Microsoft-Windows-Security-Auditing",
               "EventCode": 4663 if success else 5145, "EventRecordID": record_id,
               "Computer": file["fqdn"], "Keywords": ("0x8020000000000000" if success else
                                                     "0x8010000000000000"),
               "SubjectDomainName": "LAB", "SubjectUserName": account,
               "SubjectLogonId": logons[account]["TargetLogonId"],
               "ObjectType": "File", "AccessMask": "0x1", "AccessList": "%%4416"}
        if success:
            row.update(ObjectServer="Security", ObjectName=obj["path"],
                       HandleId=f"0x{record_id:x}", ProcessId="0x4",
                       ProcessName=r"C:\Windows\System32\System")
        else:
            row.update(IpAddress=bastion["ip"], IpPort="50123", ShareName=r"\\*\Shares",
                       ShareLocalPath=r"D:\Shares", RelativeTargetName=r"HR\payroll.csv",
                       AccessReason="%%4416: %%1802")
        windows.append(row)
        event_id = f"windows-{file['short_name']}-{record_id}"
        accesses.append({"event_id": event_id, "object_id": obj["object_id"],
                         "identity_id": identity_id, "session_id": sessions[identity_id]["session_id"],
                         "asset_id": file["asset_id"], "at": row["TimeCreated"],
                         "action": "read", "result": "success" if success else "denied",
                         "source_asset_id": bastion["asset_id"] if identity_id != "identity-backup-01" else file["asset_id"]})
        return event_id

    operator_at = parse(sessions["identity-operator-01"]["started_at"])
    backup_at = parse(sessions["identity-backup-01"]["started_at"])
    admin_at = parse(sessions["identity-admin-01"]["started_at"])
    finance_read = file_event(0, "identity-operator-01", "operator", operator_at + timedelta(seconds=5), True)
    file_event(2, "identity-operator-01", "operator", operator_at + timedelta(seconds=6), False)
    backup_read = file_event(1, "identity-backup-01", "svc_backup", backup_at + timedelta(seconds=4), True)

    def outbound(label, source, entity_id, when, method, body_bytes, response_bytes,
                 disposition, session_id, identity_id, read_event_id=None):
        entity = by_entity[entity_id]
        uid = f"C{seed:08x}{len(firewall)+1:04x}"
        port = 51000 + len(firewall)
        network_bytes = body_bytes + (380 if disposition == "allow" else 0)
        flow = {"ts": round(when.timestamp(), 3), "uid": uid, "id.orig_h": source["ip"],
                "id.orig_p": port, "id.resp_h": entity["ip"], "id.resp_p": 80,
                "proto": "tcp", "service": "http", "duration": 0.2,
                "orig_ip_bytes": network_bytes, "resp_ip_bytes": response_bytes + 240,
                "conn_state": "SF", "local_orig": True, "local_resp": False}
        if disposition == "allow":
            conn.append(flow)
            http.append({"ts": round((when + timedelta(milliseconds=50)).timestamp(), 3),
                         "uid": uid, "id.orig_h": source["ip"], "id.orig_p": port,
                         "id.resp_h": entity["ip"], "id.resp_p": 80, "method": method,
                         "host": entity["name"], "uri": "/api/upload" if method == "POST" else "/docs/policy.pdf",
                         "version": "1.1", "status_code": 200,
                         "request_body_len": body_bytes, "response_body_len": response_bytes})
        firewall.append({"time": stamp(when), "device": "edge-fw-01", "action": disposition,
                         "src_ip": source["ip"], "src_port": port, "dest_ip": entity["ip"],
                         "dest_port": 80, "protocol": "tcp",
                         "bytes_out": network_bytes if disposition == "allow" else 0,
                         "bytes_in": flow["resp_ip_bytes"] if disposition == "allow" else 0,
                         "rule": "egress-http" if disposition == "allow" else "deny-unapproved"})
        transfers.append({"transfer_id": label, "uid": uid if disposition == "allow" else None,
                          "firewall_index": len(firewall)-1, "source_asset_id": source["asset_id"],
                          "destination_entity_id": entity_id, "session_id": session_id,
                          "identity_id": identity_id, "at": stamp(when), "method": method,
                          "body_bytes": body_bytes if disposition == "allow" else 0,
                          "result": disposition, "related_read_event_id": read_event_id,
                          "evidence_limit": "correlated timing and size; content identity not observed" if read_event_id else None})

    outbound("transfer-finance", bastion, "entity-external-upload-01",
             operator_at + timedelta(seconds=10), "POST", 4096, 80, "allow",
             sessions["identity-operator-01"]["session_id"], "identity-operator-01", finance_read)
    outbound("transfer-blocked", bastion, "entity-denied-egress-01",
             operator_at + timedelta(seconds=12), "POST", 2048, 0, "block",
             sessions["identity-operator-01"]["session_id"], "identity-operator-01")
    outbound("transfer-backup", file, "entity-backup-provider-01",
             backup_at + timedelta(seconds=5), "POST", 16384, 80, "allow",
             sessions["identity-backup-01"]["session_id"], "identity-backup-01", backup_read)
    outbound("transfer-admin-download", dc, "entity-backup-provider-01",
             admin_at + timedelta(seconds=4), "GET", 0, 1024, "allow",
             sessions["identity-admin-01"]["session_id"], "identity-admin-01")
    windows.sort(key=lambda row: (row["TimeCreated"], row["EventRecordID"]))
    conn.sort(key=lambda row: row["ts"])
    http.sort(key=lambda row: row["ts"])
    firewall.sort(key=lambda row: row["time"])
    # Keep the explicit event key stable after firewall sorting.
    by_key = {(row["time"], row["src_ip"], row["dest_ip"]): index
              for index, row in enumerate(firewall)}
    for transfer in transfers:
        entity = by_entity[transfer["destination_entity_id"]]
        source = next(row for row in assets if row["asset_id"] == transfer["source_asset_id"])
        transfer["firewall_index"] = by_key[(transfer["at"], source["ip"], entity["ip"])]
    transfers.sort(key=lambda row: (row["at"], row["transfer_id"]))
    return {"objects": objects, "windows": windows, "conn": conn, "http": http,
            "firewall": firewall, "truth": {"schema_version": VERSION,
            "accesses": accesses, "transfers": transfers,
            "notes": ["Object payloads are not generated", "HTTP observes byte counts, not file identity"]}}
