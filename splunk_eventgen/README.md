# Replay sec-data events in Splunk

Splunk Eventgen is an optional replay step for a completed dataset. Your existing `create_dataset.py` workflow and its JSONL outputs work independently. This guide uses [Black Basta v2](black-basta-v2/README.md) and the SA-Eventgen app on a Splunk Enterprise lab instance.

## 1. Select a completed dataset and prepare the CSV

If you need a dataset, follow [Select a scenario and generate data](../README.md#3-select-a-scenario-and-generate-data) and use the Black Basta v2 example. If you already have a Black Basta v2 run, reuse it.

Open PowerShell in the repo root. Set `$outputDir` to the run folder containing `dataset-manifest.json` and `events\`. If you just generated the dataset with the main README, keep the `$outputDir` value returned by that command and leave the example assignment commented out.

~~~powershell
$python = '.\.venv\Scripts\python.exe'
# $outputDir = '.\output\black-basta-v2-run001'  # Set this in a new session.
$samplePath = '.\output\splunk-eventgen\black-basta-v2\black-basta-v2.csv'

if (-not $outputDir -or -not (Test-Path -LiteralPath (Join-Path $outputDir 'dataset-manifest.json') -PathType Leaf)) {
    throw 'Set $outputDir to the Black Basta v2 run folder containing dataset-manifest.json.'
}

& $python .\splunk_eventgen\prepare_sample.py $outputDir $samplePath `
    --scenario-id cisa-aa24-131a-black-basta-composite-v2
if ($LASTEXITCODE -ne 0) { throw 'Eventgen sample preparation failed.' }
~~~

`$outputDir` is the input. `$samplePath` is the new CSV. The script merges the event files into a single chronological stream, preserving each event's source and reporting device. It refuses to overwrite a CSV. Reuse the CSV for repeated runs, or choose a fresh output directory with the same CSV filename to prepare a different run.

## 2. Deploy the replay to Splunk

Install [SA-Eventgen](https://splunkbase.splunk.com/app/1924) and the repo's [TA-sec-data-cim add-on](../splunk/TA-sec-data-cim). Create a lab index named `sec_data_replay` or choose an existing replay index. Run Eventgen on a UTC host so the replay clock agrees with the timestamps' `Z` suffix.

Create `$SPLUNK_HOME/etc/apps/sec_data_black_basta_replay/` on the Splunk instance running SA-Eventgen. The paths below are relative to that companion app folder.

| Source | Destination |
| --- | --- |
| [Black Basta v2 config](black-basta-v2/eventgen.conf) from the repo | `default/eventgen.conf` |
| Generated `black-basta-v2.csv` from step 1 | `samples/black-basta-v2.csv` |
| App metadata shown below | `default/app.conf` and `metadata/default.meta` |

Put the following in `default/app.conf`.

~~~ini
[ui]
label = Sec Data Black Basta Replay
~~~

Put the following in `metadata/default.meta` to make the configuration available to SA-Eventgen.

~~~ini
[]
export = system
~~~

Edit the **deployed** `default/eventgen.conf`. Remove `sampleDir` so Eventgen looks under `samples/`. Keep the stanza, timestamp tokens, `mode = replay`, `sourcetype = secdata:cim:json` and `timeMultiple = 1`. Change these settings for the first run:

~~~ini
outputMode = modinput
index = sec_data_replay
end = 1
~~~

Restart Splunk after deploying the companion app. In Splunk Web, open **Settings → Data inputs → SA-Eventgen** and enable the default modular input if it is disabled. If the input is already enabled, the restart can start the replay. See [Eventgen's app setup](https://splunk.github.io/eventgen/SETUP.html#splunk-app-installation--first-run) for installation and app visibility details.

## 3. Verify one replay and enable recurrence

After the replay finishes, search over its replay window. Eventgen advances the timestamps to the replay period.

~~~spl
index=sec_data_replay sourcetype=secdata:cim:json
| stats count AS events dc(source) AS sources
~~~

The reference sample should return **10,000 events across 17 sources**. For a different run, compare with `event_records` and `source_counts` in the run's `dataset-manifest.json`.

To repeat the same sample, update the deployed stanza and restart Eventgen by restarting Splunk on the lab instance.

~~~ini
end = -1
interval = 3600
~~~

This example waits one hour **after each replay finishes** before starting the next one. Eventgen reuses the same CSV and the same event IDs, with new timestamps on each pass. No external scheduler is needed for this loop. See the [Eventgen configuration reference](https://splunk.github.io/eventgen/REFERENCE.html) for replay timing.

For a standalone preview or the expected telemetry by source, see the [Black Basta v2 replay notes](black-basta-v2/README.md). To add another scenario, start from the [replay config template](eventgen.conf).
