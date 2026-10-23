# Linked endpoint fixture

The story bundle models Sysmon coverage on `prod-file-01` only. `sensor-coverage.jsonl` records the source and enabled event IDs for the first 23 assets; Linux and other Windows hosts have no Sysmon observations in this fixture. This coverage file and `endpoint-truth.json` are generator context, not analyst events.

| File | Meaning |
| --- | --- |
| `sysmon.jsonl` | Readable source-field projections for Sysmon 1, 3, 5, 11, and 13 |
| `sysmon.xml` | One Windows Event XML projection per line |
| `sensor-coverage.jsonl`, `endpoint-truth.json` | Sensor visibility, session/process/recon links, and answer key |

The analyst's Windows logon on `prod-file-01` precedes a process tree (`wsmprovhost.exe` → `powershell.exe` → synthetic `netscan.exe`). Sysmon process creation, four network connections, a file creation, and termination share process GUIDs and the Windows logon ID. The network rows align with the existing firewall observations, and the process row aligns with the recon process observation. After the operator's authorized group grant and logon, a synthetic configuration helper sets an autorun value. A backup service account then runs a status job, writes a status file, and connects to the approved backup provider as a benign control. Commands and paths are inert synthetic examples; no executables run when the generator runs. No executable hashes, malware signatures, AV detections, or blocked actions are fabricated.

[Microsoft's Sysmon event reference](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events) documents process creation (1), network connection (3), process termination (5), file creation (11), and registry value set (13). Event 3 needs to be [enabled in Sysmon filtering](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-configuration-files), which this scenario's sensor coverage states. The XML is a synthetic field projection, not a captured Windows event.

## Splunk mapping status

[Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709) is the candidate add-on with source `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`. A pinned **5.0.0** archive was retrieved from [Splunk's Attack Range binary manifest](https://github.com/splunk/security_content/blob/develop/contentctl.yml) into ignored `output/reference/`; SHA-256: `3b42abf255fbd794cdfa588c3ad152e63f4b62e5665aad0b2c8dd7a23a3b5818`. Its `eventtypes.conf` selects event 3 for network, 1/5 for process, 11 for file, and 13 for registry; `props.conf` supplies CIM field evaluations. The current Splunkbase listing may offer a newer version.

**Live CIM inclusion remains unverified.** In a running Splunk test with the pinned add-on and CIM, verify `_time`, `ProcessGuid`, parent fields, `user`, network addresses/ports, file path, registry path/value, tags, and the Endpoint, Network Traffic, and Change data models. Do not label `sysmon.jsonl` as XML Windows events; use `sysmon.xml` with appropriate event boundaries and source settings. The fixture does not test Malware CIM because it emits no AV/EDR observation.
