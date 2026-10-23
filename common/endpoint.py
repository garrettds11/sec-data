"""Small Sysmon-shaped endpoint sequence tied to shared sessions and recon."""

from datetime import datetime, timedelta, timezone
from uuid import NAMESPACE_URL, uuid5


VERSION = "1.0"
SOURCE = "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
PROVIDER = "Microsoft-Windows-Sysmon"
CHANNEL = "Microsoft-Windows-Sysmon/Operational"
ENABLED_CODES = [1, 3, 5, 11, 13]


def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def stamp(value):
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def utc_field(value):
    return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def guid(seed, asset_id, label):
    return "{" + str(uuid5(NAMESPACE_URL, f"sec-data:{VERSION}:{seed}:{asset_id}:{label}")) + "}"


def generate(seed, start, assets, identity_truth, windows_auth, recon_truth, recon_events):
    by_short = {asset["short_name"]: asset for asset in assets}
    file = by_short["prod-file-01"]
    if file["family"] != "windows":
        raise ValueError("Sysmon fixture requires a Windows file host")
    coverage = [{"asset_id": asset["asset_id"], "sensor": "sysmon",
                 "enabled": asset["asset_id"] == file["asset_id"],
                 "event_codes": ENABLED_CODES if asset["asset_id"] == file["asset_id"] else [],
                 "valid_from": stamp(start), "valid_until": None}
                for asset in assets]
    sessions = {row["identity_id"]: row for row in identity_truth["sessions"]}
    logons = {row["TargetUserName"]: row for row in windows_auth
              if row["EventCode"] == 4624 and row["Computer"] == file["fqdn"]}
    for account in ("analyst", "operator", "svc_backup"):
        if account not in logons:
            raise ValueError(f"Missing Windows logon for {account}")
    internal = next(op for op in recon_truth["operations"] if op["family"] == "internal")
    recon_ids = set(internal["event_ids"])
    process_observation = next(event for event in recon_events if
                               event["event_id"] in recon_ids and
                               event["event_type"] == "process" and
                               event["host_name"] == file["fqdn"])
    connections = [event for event in recon_events if event["event_id"] in recon_ids and
                   event["event_type"] == "network_connection" and event["src_ip"] == file["ip"]]
    if not connections:
        raise ValueError("Internal recon has no file-host network observations")
    records, links = [], []

    def emit(when, code, identity_id, session_id, **fields):
        record_id = 200000 + len(records) + 1
        row = {"TimeCreated": stamp(when), "Channel": CHANNEL, "Provider": PROVIDER,
               "EventCode": code, "EventRecordID": record_id, "Computer": file["fqdn"],
               "UtcTime": utc_field(when), **fields}
        records.append(row)
        link = {"event_id": f"sysmon-{file['short_name']}-{record_id}",
                "asset_id": file["asset_id"], "identity_id": identity_id,
                "session_id": session_id, "at": row["TimeCreated"],
                "event_code": code}
        links.append(link)
        return link

    def process(label, when, pid, image, command, user, logon_id,
                identity_id, session_id, parent=None):
        pguid = guid(seed, file["asset_id"], label)
        fields = {"ProcessGuid": pguid, "ProcessId": pid, "Image": image,
                  "CommandLine": command, "User": user, "LogonId": logon_id,
                  "LogonGuid": guid(seed, file["asset_id"], session_id),
                  "IntegrityLevel": "Medium"}
        if parent:
            fields.update(ParentProcessGuid=parent["guid"], ParentProcessId=parent["pid"],
                          ParentImage=parent["image"])
        link = emit(when, 1, identity_id, session_id, **fields)
        link["process_guid"] = pguid
        if parent:
            link["parent_process_guid"] = parent["guid"]
        return {"guid": pguid, "pid": pid, "image": image, "link": link}

    analyst = sessions["identity-analyst-01"]
    analyst_logon = logons["analyst"]
    login_at = parse_time(analyst["started_at"])
    root = process("analyst-wsm", login_at + timedelta(seconds=1), 4100,
                   r"C:\Windows\System32\wsmprovhost.exe", "wsmprovhost.exe",
                   "LAB\\analyst", analyst_logon["TargetLogonId"],
                   "identity-analyst-01", analyst["session_id"])
    shell = process("analyst-shell", login_at + timedelta(seconds=2), 4104,
                    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    "powershell.exe -NoProfile -Command Get-ChildItem",
                    "LAB\\analyst", analyst_logon["TargetLogonId"],
                    "identity-analyst-01", analyst["session_id"], root)
    scan_at = parse_time(process_observation["timestamp"])
    scan = process("analyst-scan", scan_at, 4108,
                   r"C:\Program Files\InventoryTools\netscan.exe",
                   r"netscan.exe --scope corp.example.local --output C:\ProgramData\SecData\inventory-summary.txt",
                   "LAB\\analyst", analyst_logon["TargetLogonId"],
                   "identity-analyst-01", analyst["session_id"], shell)
    scan["link"]["related_recon_event_id"] = process_observation["event_id"]
    for number, event in enumerate(connections):
        link = emit(parse_time(event["timestamp"]), 3, "identity-analyst-01", analyst["session_id"],
                    ProcessGuid=scan["guid"], ProcessId=scan["pid"], Image=scan["image"],
                    User="LAB\\analyst", Protocol="tcp", Initiated="true",
                    SourceIp=file["ip"], SourcePort=50000 + number,
                    DestinationIp=event["dst_ip"], DestinationPort=event["dst_port"])
        link["process_guid"] = scan["guid"]
        link["related_recon_event_id"] = event["event_id"]
    finish = max(parse_time(event["timestamp"]) for event in connections) + timedelta(seconds=2)
    output_path = r"C:\ProgramData\SecData\inventory-summary.txt"
    link = emit(finish, 11, "identity-analyst-01", analyst["session_id"],
                ProcessGuid=scan["guid"], ProcessId=scan["pid"], Image=scan["image"],
                TargetFilename=output_path, CreationUtcTime=utc_field(finish), User="LAB\\analyst")
    link.update(process_guid=scan["guid"], created_file=output_path)
    emit(finish + timedelta(seconds=1), 5, "identity-analyst-01", analyst["session_id"],
         ProcessGuid=scan["guid"], ProcessId=scan["pid"], Image=scan["image"], User="LAB\\analyst")

    operator = sessions["identity-operator-01"]
    operator_at = parse_time(operator["started_at"]) + timedelta(seconds=2)
    config = process("operator-config", operator_at, 4200,
                     r"C:\Program Files\SecDataLab\config-helper.exe",
                     "config-helper.exe --set-autostart AuditHelper", "LAB\\operator",
                     logons["operator"]["TargetLogonId"], "identity-operator-01",
                     operator["session_id"])
    registry_at = operator_at + timedelta(seconds=2)
    key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\AuditHelper"
    link = emit(registry_at, 13, "identity-operator-01", operator["session_id"],
                ProcessGuid=config["guid"], ProcessId=config["pid"], Image=config["image"],
                EventType="SetValue", TargetObject=key,
                Details=r"C:\Program Files\SecDataLab\audit-helper.exe", User="LAB\\operator")
    link.update(process_guid=config["guid"], registry_key=key)
    emit(registry_at + timedelta(seconds=1), 5, "identity-operator-01", operator["session_id"],
         ProcessGuid=config["guid"], ProcessId=config["pid"], Image=config["image"], User="LAB\\operator")

    backup = sessions["identity-backup-01"]
    backup_at = parse_time(backup["started_at"]) + timedelta(seconds=2)
    job = process("backup-job", backup_at, 4300,
                  r"C:\Program Files\BackupAgent\backup.exe", "backup.exe --status-only",
                  "LAB\\svc_backup", logons["svc_backup"]["TargetLogonId"],
                  "identity-backup-01", backup["session_id"])
    status_at = backup_at + timedelta(seconds=2)
    link = emit(status_at, 11, "identity-backup-01", backup["session_id"],
                ProcessGuid=job["guid"], ProcessId=job["pid"], Image=job["image"],
                TargetFilename=r"C:\ProgramData\BackupAgent\last-run.txt",
                CreationUtcTime=utc_field(status_at), User="LAB\\svc_backup")
    link["process_guid"] = job["guid"]
    emit(status_at + timedelta(seconds=1), 5, "identity-backup-01", backup["session_id"],
         ProcessGuid=job["guid"], ProcessId=job["pid"], Image=job["image"], User="LAB\\svc_backup")
    records.sort(key=lambda row: (row["TimeCreated"], row["EventRecordID"]))
    links.sort(key=lambda row: (row["at"], row["event_id"]))
    return {"coverage": coverage, "records": records,
            "truth": {"schema_version": VERSION, "source": SOURCE,
                      "interactions": links, "monitored_asset_id": file["asset_id"],
                      "related_recon_operation_id": internal["operation_id"]}}
