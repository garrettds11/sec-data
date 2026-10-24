# Linked identity and authentication fixture

The story bundle now exports a small identity sequence against the shared asset catalog. The source records contain observations; `identity-truth.json` and `identity-state.jsonl` contain the policy, sessions, effective state, and links to recon operations. Keep those truth files out of analyst-facing indexes.

| File | Purpose |
| --- | --- |
| `identities.jsonl`, `access-policies.jsonl` | Stable account and policy IDs with validity intervals |
| `web-auth.jsonl` | Project-owned application login and lockout observations |
| `windows-security.jsonl` | Readable Windows Security field projection |
| `windows-security.xml` | One Windows Event XML projection per line |
| `identity-state.jsonl`, `identity-truth.json` | Application lockout, group grant, session IDs, and cross-source links |

The external scanner IP already present in recon attempts the operator account on `prod-web-02`. Three failed web logins trigger an application-local lockout; a fourth attempt is denied during it. After expiry, the operator logs into the web app from the internal bastion with MFA recorded as passed. Separately, the analyst logs onto `prod-file-01` just before the internal recon operation. An operator network logon to that file host is denied, an administrator adds the operator to `File Operators` on `dc-01`, and a later operator logon succeeds. A backup service account provides benign background logon activity with no network source. The validator checks this order and the links to shared identities, assets, policies, sessions, and recon.

The Windows records use documented event IDs [4624](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624), [4625](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625), and [4728](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4728). `0xC000015B` represents a denied logon type. The XML view is a synthetic projection, not a captured Windows event. The web events use a project-owned schema; no vendor add-on is asserted for them. Neither source contains passwords, MFA secrets, or session tokens.

## Splunk mapping status

[Splunk Add-on for Microsoft Windows](https://splunkbase.splunk.com/app/742) is the candidate add-on for `windows-security.xml` with source `XmlWinEventLog:Security` and an XML Windows sourcetype configured for that add-on. Its [Windows input guidance](https://help.splunk.com/en/splunk-cloud-platform/administer/admin-manual/10.6/get-data-into-splunk-cloud-platform/get-windows-data-into-splunk-cloud-platform) uses XML rendering, and [Splunk's security source guide](https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.3/user-and-entity-behavior-analytics/behavior-based-detections-for-ueba-in-splunk-enterprise-security/required-sourcetypes-for-behavior-based-detections) lists 4624, 4625, and account changes as relevant to Authentication and Change analysis.

For local inspection, a pinned TA-Windows **10.0.1** archive was retrieved from [Splunk's Attack Range binary manifest](https://github.com/splunk/security_content/blob/develop/contentctl.yml) into ignored `output/reference/`. SHA-256: `444a0894c6a954f4453cf398e1414a29852de23bb7ea9121dd7c4144903a86c6`. Its `eventtypes.conf` and `tags.conf` define Authentication event types for 4624/4625; `props.conf` includes XML Security field evaluations and 4728 handling. The current Splunkbase listing may offer a newer version, so pin and retest before using it as a production mapping.

**Live CIM inclusion remains unverified.** The XML projection has not been ingested into a running Splunk instance with TA-Windows and CIM installed. In that test, verify `_time`, `EventCode`, `user`, `src`, `dest`, `action`, `tag=authentication`, 4728 Change tagging, and data-model membership. The JSON projection must not be labeled `XmlWinEventLog:Security`; use the XML view for that test. The web app requires its own parsing and CIM mapping, with `Authentication` as the candidate model.
