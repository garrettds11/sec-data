# Author with AI assistance

AI authors the input; the Python generator runs without an LLM, API key or AI package. Choose one of three story sources: CISA-oriented, AI-generated, or human-generated. All use [general authoring](scenario-authoring.md); CISA inputs additionally use [the advisory procedure](cisa-scenario-authoring.md).

## Repository-aware agent

Open the checkout in an agent that can read files. Start with either prompt below. AGENTS.md directs the agent to inspect the contract/example/context, clarify the exercise, propose steps, wait for review and validate before generation. CLAUDE.md points to those same instructions. Tools do not universally load agent files automatically; explicitly ask the agent to read AGENTS.md if needed.

### AI-generated story prompt

~~~text
create a threat story and generate synthetic data using the capabilities provide by this repo, https://github.com/garrettds11/sec-data
~~~

This selects an AI-generated plausible fictional story unless you supply a different source. The agent should ask for the investigation objective and settings or propose concrete choices, identify assumptions, and obtain approval before generating events. A seed change alone is not a new story.

### CISA-oriented story prompt

~~~text
create a threat story and generate synthetic data using one scenario JSON file based on CISA advisory [ID]. Follow the repo’s current scenario contract. Preserve documented facts, identify fictional additions separately, and propose the ordered story steps before generating data. Explain any details the current generator cannot represent. Details from the CISA publication should be used, including the IOCs, tactics, techniques, software, and weaknesses.
~~~

Replace [ID] with an advisory identifier. The agent must retrieve the full selected revision; an ID or summary/catalog row alone is not its contents. Selected IOCs and behaviors should be represented where supported; explain omissions and alternatives instead of combining every reported attack path.

### Human-generated story with AI translation

~~~text
Use the following human-generated threat story as the source. Read AGENTS.md and the scenario authoring guide. Preserve my intended sequence, clarify gaps, and translate it into one scenario JSON using the current contract. Identify assumptions and unsupported evidence. Propose the ordered steps and run settings for approval before generating data.

[Paste your narrative or ordered observations here.]
~~~

The human supplies the story; using AI to translate or edit it does not change that source classification. You can also manually customize any AI output using the same guide.

## Ordinary AI chat without checkout access

Cloning on your computer does not give a chat access to local files. A URL does not guarantee that the chat can read the repository or its full sources. Attach/paste the following from one checkout revision, then use the selected prompt:

1. AGENTS.md, docs/scenario-authoring.md and docs/scenarios.md.
2. scenarios/file-collection.json as the concrete shape example.
3. The output of validate_scenario.py --describe-contract and --describe-context with your intended seed/host count. Save those outputs under output/ if attachments are needed.
4. For CISA: docs/cisa-scenario-authoring.md and the full advisory/revision, including needed IOC tables. A catalog may help select it but cannot replace it.
5. For human-generated: your narrative and any evidence constraints. For AI-generated: your objective and any preferences, or ask for a proposal.

Tell the chat it has no execution access. It should return a downloadable scenario JSON plus any source/assumption notes and proposed commands. Save the JSON in the checkout and run validation yourself. Give validation errors back to the chat for correction. Do not accept a claim that the data was generated unless an actual output package and manifest exist.

## Review gate and handoff

Before generation, review the sequence, fictional assumptions, observation coverage, unsupported details and settings. Then approve the proposed command, or edit the file manually and run it yourself. The validator checks compatibility, not realism or source accuracy. If generation or Splunk ingest was not performed, the author must say so.

Keep events/ for analysts and truth/ for instructors. Do not attach real credentials or sensitive production data. Historical indicators are offline matching values; no scanning, real malware or connections to those addresses are needed.
