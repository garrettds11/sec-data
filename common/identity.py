"""Deterministic identities and source-visible authentication observations."""

import hashlib
import xml.etree.ElementTree as ET
from datetime import timedelta, timezone

from common.world import ENTITY_IPS, asset_id


VERSION = "1.0"
WINDOWS_EVENT_NS = "http://schemas.microsoft.com/win/2004/08/events/event"
ET.register_namespace("", WINDOWS_EVENT_NS)
IDENTITIES = (
    {"identity_id": "identity-analyst-01", "account": "LAB\\analyst", "kind": "user",
     "groups": ["File Readers"], "enabled": True},
    {"identity_id": "identity-operator-01", "account": "LAB\\operator", "kind": "user",
     "groups": [], "enabled": True},
    {"identity_id": "identity-admin-01", "account": "LAB\\admin", "kind": "user",
     "groups": ["Domain Admins"], "enabled": True},
    {"identity_id": "identity-backup-01", "account": "LAB\\svc_backup", "kind": "service_account",
     "groups": ["Backup Operators"], "enabled": True},
)


def stamp(value):
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def stable_id(seed, *parts):
    value = "|".join(map(str, (VERSION, seed, *parts)))
    return hashlib.sha256(value.encode()).hexdigest()[:20]


def iter_identities():
    for row in IDENTITIES:
        yield {**row, "synthetic": True}


def render_windows_xml(row):
    """Render a Windows Security XML event projection for TA-Windows inspection."""
    def node(parent, name, value=None, **attrs):
        element = ET.SubElement(parent, f"{{{WINDOWS_EVENT_NS}}}{name}", attrs)
        if value is not None:
            element.text = str(value)
        return element

    event = ET.Element(f"{{{WINDOWS_EVENT_NS}}}Event")
    system = node(event, "System")
    node(system, "Provider", Name=row["Provider"])
    node(system, "EventID", row["EventCode"])
    node(system, "Version", 2)
    node(system, "Level", 0)
    if "Keywords" in row:
        node(system, "Keywords", row["Keywords"])
    node(system, "TimeCreated", SystemTime=row["TimeCreated"])
    node(system, "EventRecordID", row["EventRecordID"])
    node(system, "Channel", row["Channel"])
    node(system, "Computer", row["Computer"])
    data = node(event, "EventData")
    for key, value in sorted(row.items()):
        if key not in {"TimeCreated", "Channel", "Provider", "EventCode", "Computer", "EventRecordID", "Keywords"}:
            node(data, "Data", value, Name=key)
    return ET.tostring(event, encoding="unicode", short_empty_elements=True)


def generate(seed, start, duration_minutes, campaign_count, hosts):
    """Return a small linked auth fixture; truth is separate from source logs."""
    if start.tzinfo is None or duration_minutes < 4 * campaign_count or campaign_count < 1:
        raise ValueError("Identity run requires a timezone and valid recon duration")
    needed = ("prod-web-02", "prod-file-01", "dc-01", "bastion-01")
    if any(name not in hosts for name in needed):
        raise ValueError("Identity scenario requires the default named hosts")
    web, file, dc, bastion = (hosts[name] for name in needed)
    if web["role"] != "web" or file["family"] != "windows" or dc["family"] != "windows":
        raise ValueError("Identity scenario targets are incompatible with their sources")
    step = duration_minutes * 60 / (4 * campaign_count)
    total = duration_minutes * 60

    def at(seconds):
        return stamp(start + timedelta(seconds=seconds))

    policies = [
        {"policy_id": "policy-web-operator", "identity_id": "identity-operator-01",
         "service": "web_login", "asset_id": asset_id(web), "allowed_source": "internal",
         "mfa_required": True, "valid_from": at(0), "valid_until": None},
        {"policy_id": "policy-file-analyst", "identity_id": "identity-analyst-01",
         "service": "windows_network_logon", "asset_id": asset_id(file),
         "required_group": "File Readers", "valid_from": at(0), "valid_until": None},
        {"policy_id": "policy-dc-admin", "identity_id": "identity-admin-01",
         "service": "windows_network_logon", "asset_id": asset_id(dc),
         "required_group": "Domain Admins", "valid_from": at(0), "valid_until": None},
        {"policy_id": "policy-file-operator", "identity_id": "identity-operator-01",
         "service": "windows_network_logon", "asset_id": asset_id(file),
         "required_group": "File Operators", "valid_from": at(0), "valid_until": None},
        {"policy_id": "policy-backup-service", "identity_id": "identity-backup-01",
         "service": "windows_service_logon", "asset_id": asset_id(file),
         "required_group": "Backup Operators", "valid_from": at(0), "valid_until": None},
    ]
    web_events, windows_events, interactions, sessions, changes = [], [], [], [], []

    def web_event(seconds, source_ip, outcome, reason, mfa=None, session_id=None):
        event_id = "webauth-" + stable_id(seed, "web", seconds, source_ip, outcome)
        row = {"time": at(seconds), "event": "login", "request_id": event_id,
               "client_ip": source_ip, "server_name": web["fqdn"],
               "account": "LAB\\operator", "outcome": outcome, "reason": reason}
        if mfa is not None:
            row["mfa_result"] = mfa
        web_events.append(row)
        interactions.append({"event_id": event_id, "source": "web-auth",
                             "at": row["time"], "identity_id": "identity-operator-01",
                             "asset_id": asset_id(web), "source_ip": source_ip,
                             "outcome": outcome, "session_id": session_id})
        if source_ip == ENTITY_IPS["entity-external-scanner-01"]:
            interactions[-1]["source_entity_id"] = "entity-external-scanner-01"
            interactions[-1]["related_operation_id"] = "operation-0000"
        return event_id

    external_ip = ENTITY_IPS["entity-external-scanner-01"]
    attempts = [step * fraction for fraction in (0.25, 0.30, 0.35)]
    for seconds in attempts:
        web_event(seconds, external_ip, "failure", "invalid_password")
    lock_at = attempts[-1]
    unlock_at = step * 0.65
    changes.append({"change_id": "identity-change-" + stable_id(seed, "lockout", at(lock_at)),
                    "kind": "app_lockout", "identity_id": "identity-operator-01",
                    "asset_id": asset_id(web), "effective_at": at(lock_at),
                    "expires_at": at(unlock_at), "before": "active", "after": "locked",
                    "failure_threshold": 3})
    lock_event_id = "webauth-" + stable_id(seed, "locked", at(lock_at))
    web_events.append({"time": at(lock_at), "event": "account_locked",
                       "request_id": lock_event_id, "server_name": web["fqdn"],
                       "account": "LAB\\operator", "failure_count": 3})
    interactions.append({"event_id": lock_event_id, "source": "web-auth", "at": at(lock_at),
                         "identity_id": "identity-operator-01", "asset_id": asset_id(web),
                         "caused_by": interactions[-1]["event_id"]})
    web_event(step * 0.40, external_ip, "failure", "account_locked")
    operator_web_session = "session-" + stable_id(seed, "operator-web")
    web_event(total * 0.50, bastion["ip"], "success", "authenticated",
              mfa="passed", session_id=operator_web_session)
    sessions.append({"session_id": operator_web_session,
                     "identity_id": "identity-operator-01", "asset_id": asset_id(web),
                     "source_asset_id": asset_id(bastion), "started_at": at(total * 0.50)})

    def windows_event(seconds, code, computer, target_account=None, source_ip=None,
                      logon_id=None, actor=None, member=None, group=None, status=None,
                      actor_logon_id=None, logon_type=None):
        record_id = 100000 + len(windows_events) + 1
        row = {"TimeCreated": at(seconds), "Channel": "Security",
               "Provider": "Microsoft-Windows-Security-Auditing", "EventCode": code,
               "Computer": computer["fqdn"], "EventRecordID": record_id}
        if target_account is not None:
            row.update(TargetDomainName="LAB", TargetUserName=target_account)
        if source_ip is not None:
            row.update(IpAddress=source_ip, LogonType=3)
        elif logon_type is not None:
            row["LogonType"] = logon_type
        if logon_id is not None:
            row["TargetLogonId"] = logon_id
        if actor is not None:
            row.update(SubjectUserName=actor, SubjectDomainName="LAB")
        if actor_logon_id is not None:
            row["SubjectLogonId"] = actor_logon_id
        if member is not None:
            row.update(MemberName=member, MemberSid="S-1-5-21-100000001-100000002-100000003-1102",
                       TargetUserName=group, TargetDomainName="LAB",
                       TargetSid="S-1-5-21-100000001-100000002-100000003-1201")
        if status is not None:
            row.update(Status=status, SubStatus="0x0")
        windows_events.append(row)
        return f"windows-{computer['short']}-{record_id}"

    analyst_session = "session-" + stable_id(seed, "analyst-file")
    analyst_logon_id = "0x" + stable_id(seed, "analyst-logon")[:12]
    analyst_at = max(0, step - min(10, step * 0.1))
    eid = windows_event(analyst_at, 4624, file, "analyst", bastion["ip"], analyst_logon_id)
    interactions.append({"event_id": eid, "source": "windows-security", "at": at(analyst_at),
                         "identity_id": "identity-analyst-01", "asset_id": asset_id(file),
                         "source_asset_id": asset_id(bastion), "outcome": "success",
                         "session_id": analyst_session, "policy_id": "policy-file-analyst"})
    sessions.append({"session_id": analyst_session, "identity_id": "identity-analyst-01",
                     "asset_id": asset_id(file), "source_asset_id": asset_id(bastion),
                     "started_at": at(analyst_at), "linked_recon_operation_id": "operation-0001"})

    admin_at = total * 0.55
    admin_session = "session-" + stable_id(seed, "admin-dc")
    admin_logon_id = "0x" + stable_id(seed, "admin-logon")[:12]
    eid = windows_event(admin_at, 4624, dc, "admin", bastion["ip"],
                        admin_logon_id)
    interactions.append({"event_id": eid, "source": "windows-security", "at": at(admin_at),
                         "identity_id": "identity-admin-01", "asset_id": asset_id(dc),
                         "source_asset_id": asset_id(bastion), "outcome": "success",
                         "session_id": admin_session, "policy_id": "policy-dc-admin"})
    sessions.append({"session_id": admin_session, "identity_id": "identity-admin-01",
                     "asset_id": asset_id(dc), "source_asset_id": asset_id(bastion),
                     "started_at": at(admin_at)})
    denied_at = total * 0.58
    eid = windows_event(denied_at, 4625, file, "operator", bastion["ip"],
                        status="0xC000015B")
    interactions.append({"event_id": eid, "source": "windows-security", "at": at(denied_at),
                         "identity_id": "identity-operator-01", "asset_id": asset_id(file),
                         "source_asset_id": asset_id(bastion), "outcome": "failure",
                         "reason": "logon_right_not_granted", "policy_id": "policy-file-operator"})
    grant_at = total * 0.60
    eid = windows_event(grant_at, 4728, dc, actor="admin",
                        member="CN=operator,OU=Users,DC=corp,DC=example,DC=local",
                        group="File Operators", actor_logon_id=admin_logon_id)
    grant = {"change_id": "identity-change-" + stable_id(seed, "group-grant", at(grant_at)),
             "kind": "group_membership", "identity_id": "identity-operator-01",
             "group": "File Operators", "before": "absent", "after": "member",
             "effective_at": at(grant_at), "actor_identity_id": "identity-admin-01",
             "caused_by_session_id": admin_session, "event_id": eid}
    changes.append(grant)
    interactions.append({"event_id": eid, "source": "windows-security", "at": at(grant_at),
                         "identity_id": "identity-operator-01", "asset_id": asset_id(dc),
                         "actor_identity_id": "identity-admin-01", "session_id": admin_session})
    operator_at = total * 0.65
    operator_session = "session-" + stable_id(seed, "operator-file")
    eid = windows_event(operator_at, 4624, file, "operator", bastion["ip"],
                        "0x" + stable_id(seed, "operator-logon")[:12])
    interactions.append({"event_id": eid, "source": "windows-security", "at": at(operator_at),
                         "identity_id": "identity-operator-01", "asset_id": asset_id(file),
                         "source_asset_id": asset_id(bastion), "outcome": "success",
                         "session_id": operator_session, "policy_id": "policy-file-operator",
                         "caused_by": grant["change_id"]})
    sessions.append({"session_id": operator_session, "identity_id": "identity-operator-01",
                     "asset_id": asset_id(file), "source_asset_id": asset_id(bastion),
                     "started_at": at(operator_at)})
    backup_at = total * 0.70
    backup_session = "session-" + stable_id(seed, "backup-service")
    eid = windows_event(backup_at, 4624, file, "svc_backup",
                        logon_id="0x" + stable_id(seed, "backup-logon")[:12], logon_type=5)
    interactions.append({"event_id": eid, "source": "windows-security", "at": at(backup_at),
                         "identity_id": "identity-backup-01", "asset_id": asset_id(file),
                         "outcome": "success", "session_id": backup_session,
                         "policy_id": "policy-backup-service"})
    sessions.append({"session_id": backup_session, "identity_id": "identity-backup-01",
                     "asset_id": asset_id(file), "started_at": at(backup_at)})
    web_events.sort(key=lambda row: (row["time"], row["request_id"]))
    windows_events.sort(key=lambda row: (row["TimeCreated"], row["EventRecordID"]))
    truth = {"schema_version": VERSION, "interactions": interactions,
             "sessions": sessions, "state_changes": changes,
             "notes": ["Web lockout is application-local", "Windows Security records are JSON field projections"]}
    return {"identities": list(iter_identities()), "policies": policies,
            "web_events": web_events, "windows_events": windows_events,
            "truth": truth}
