# Documentation guide

Start with the repository [README](../README.md) to generate and ingest a CIM-shaped dataset. The guides below describe the current analyst package, its validation, and the source-format fixtures used to build it.

| Guide | Use it for |
| --- | --- |
| [Dataset](dataset.md) | Output layout, event counts, source inventory, time span, and scaling limits |
| [Story authoring](scenario-authoring.md) | Three story sources, manual editing, review, validation and generation |
| [CISA authoring](cisa-scenario-authoring.md) | Shared human/machine source-based procedure |
| [AI assistance](ai-authoring.md) | Consumer prompts, repository-aware agents and ordinary chat attachment checklist |
| [Black Basta example](examples/aa24-131a-black-basta-notes.md) | Source facts versus a runnable fictional adaptation |
| [Tailored scenarios](scenarios.md) | Versioned JSON contract for LLM-authored story steps and source observations |
| [CIM mapping](cim.md) and [field decisions](cim-fields.md) | Event structure, sourcetype, tags, and field semantics |
| [Splunk validation](splunk-validation.md) | Measured fixture results, example searches, and the limits of the lab test |
| [Scale and history](scale.md) | Large datasets and standalone finding exports |
| [Story bundle](story.md) | Source observations, shared world model, timeline, and answer key |
| [Windows setup](windows-software-requirements.md) and [work instructions](work-instructions-windows-vscode.md) | Local tooling, VS Code, and optional AWS upload |

The [reconnaissance](recon.md), [DNS](dns.md), [ingress](ingress.md), [identity](identity.md), [endpoint](endpoint.md), [data access](data-access.md), and [response](response.md) guides document source-format fixtures and their assumptions. Those files are useful for development and review; the primary Splunk ingest path remains `create_dataset.py` → `events/*.jsonl` with `secdata:cim:json`. The [add-on parsing audit](addon-parsing-audit.md) explains why the source-format fixtures should not be treated as vendor raw events. The [fixture README](../tests/fixtures/README.md) describes the checked-in reference data.

The live CIM checks cover a 291-event planted fixture. They do not establish vendor add-on compatibility or high-volume background behavior. Read each guide's stated validation scope before using a result as evidence.
