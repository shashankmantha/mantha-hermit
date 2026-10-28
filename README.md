# Mantha Hermit

Mantha Hermit is a local curation tool that sorts community YARA rules into signed rule packs for Mantha Ray.

It collects rules from public sources, checks that each one compiles under YARA-X, scores it against every configured pack, and tests it against known-clean files before it can affect a verdict. Plain-English requests such as "update rule list to include all new rules related to video games" are carried out end to end, with an optional local language model handling borderline decisions. Finished packs are exported as a signed, versioned bundle that Mantha Ray verifies before loading.

> Hermit selects and grades rules; it does not write them. A pack is only as reliable as the community rules it is built from.

## Features

- Plain-English requests to add, remove, or report on rules
- Rules-only request parser when no language model is available
- Optional local language model through Ollama, with validated output
- YARA-X compile checks for every rule and its dependencies
- Explainable per-pack scoring with recorded reasons
- Deterministic severity assignment
- Clean-set testing that demotes or drops noisy rules
- Probation period for new and changed rules
- Approval gates for large changes, removals, and new packs
- Versioned packs with changelogs and rollback
- Per-rule licence tracking and a licence filter for published bundles
- Signed bundles in minisign format with per-pack SHA-256 digests
- Strict reference validator for the bundle contract
- Local web interface in a native window or browser
- Scheduled, unattended updates

## Curation pipeline

Hermit processes each request through seven stages:

1. **Understand**
   - Converts the request into an action, rule selection, topic, and target pack
   - Validates the result against fixed values and rejects anything else
   - Falls back to a rules-only parser when Ollama is unavailable
2. **Fetch**
   - Downloads or updates the sources listed in `config/sources.toml`
   - Records each source's origin and commit
3. **Parse and compile**
   - Parses rules with plyara
   - Compiles each rule with YARA-X together with its private rules, global rules, and imports
   - Defines the `filename`, `filepath`, and `extension` externals used by LOKI and THOR rules
   - Lists rules that fail to compile along with the reason
4. **Score**
   - Determines each rule's file types from its condition, name, and strings
   - Scores the rule against every pack in `config/categories.toml`
   - Places it in one of three bands: included, borderline, or excluded
5. **Judge**
   - Sends borderline rules to the local model twice, with different wording
   - Includes a rule only when both answers agree with sufficient confidence
   - Adds rules the model is unsure about at `info`, where they cannot raise a verdict
6. **Clean-set test**
   - Scans new and changed rules against known-clean files
   - Demotes rules that match to `info`
   - Drops and excludes rules that match repeatedly
7. **Apply**
   - Checks the approval gates
   - Writes a new pack version with a changelog entry
   - Holds large changes as proposals for review

## Safety model

Hermit treats community rules and model output as untrusted input.

Rule selection is constrained by the following controls:

- The language model only answers two narrow questions: what a request means, and whether a borderline rule fits a pack
- Model answers are validated against known actions and pack names; invalid answers are never run
- The model cannot set severity or override a file-type exclusion, a demotion, or a compile failure
- Rule text is passed to the model as data, with instructions to ignore any directions inside it
- New and changed rules start on probation at `info`
- Rules that YARA-X reports as slow are kept at `info`
- Changes that exceed `max(25, 15%)` of a pack, create a new pack, or remove rules require approval

Published bundles are protected by:

- minisign (Ed25519) signatures from a password-protected release key
- A trusted comment that binds the signature to the exact bundle version and archive hash
- Rollback protection: installs refuse a signed bundle older than the one they have
- Per-pack SHA-256 digests compatible with `sha256sum`
- Deterministic archives
- Extraction that rejects links, absolute paths, and path traversal
- A pinned YARA-X version shared with Mantha Ray

The local web interface:

- Listens on `127.0.0.1` only
- Rejects requests whose Host header is not the local machine, preventing DNS rebinding
- Requires a per-session token for every API call
- Enforces a strict Content-Security-Policy with no inline scripts or third-party resources
- Inserts rule names and rule text as text only, never as HTML
- Runs one job at a time so a pack is never written concurrently

## Requirements

Mantha Hermit currently targets Linux.

Required software:

- Git
- Python 3.11.4 or later
- Python virtual-environment support

Optional software:

- [Ollama](https://ollama.com) and an instruct model for borderline judging and free-form requests
- The GitHub CLI (`gh`) for publishing releases
- `minisign` for creating and using the password-protected release key

### Fedora and Nobara

```bash
sudo dnf install git python3 python3-pip
```

### Ubuntu and Debian

```bash
sudo apt update
sudo apt install git python3 python3-venv python3-pip
```

### Arch Linux

```bash
sudo pacman -S --needed git python python-pip
```

### Local model (optional)

Install Ollama, then pull a model:

```bash
ollama pull qwen2.5:7b-instruct
```

Set the model in `config/hermit.toml` under `[ollama] model`. Any instruct model that reliably produces JSON is suitable; 7B to 10B models are sufficient. For thinking models such as qwen3.5, keep `think = false`.

Without a model, Hermit still handles common requests and leaves borderline rules for a later run.

## Installation from source

Clone the repository:

```bash
git clone https://github.com/shashankmantha/mantha-hermit.git
cd mantha-hermit
```

Create a virtual environment and install Hermit:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
```

To run the interface in its own window, install the desktop extra:

```bash
pip install -e '.[desktop]'
```

Confirm the installation:

```bash
hermit status
```

Run the offline demonstration:

```bash
./scripts/demo.sh
```

The demonstration requires no model or network access and completes in a few seconds. It sorts a set of synthetic rules into packs, demotes a rule that matches a clean file, exports and verifies a signed bundle, and confirms that a tampered bundle is rejected.

## Running Mantha Hermit

Launch the interface:

```bash
hermit serve
```

With the desktop extra installed, Hermit opens in its own window. Otherwise it opens in the default browser at `http://127.0.0.1:8765`.

Additional options:

```bash
hermit serve --browser       # open in the browser even when the desktop extra is installed
hermit serve --no-browser    # run the server only
hermit serve --port 8080
hermit desktop-entry         # add Hermit to the desktop application menu
```

To try the interface on the example rules in a temporary workspace:

```bash
./scripts/gui-demo.sh
```

## Making requests

From the interface, enter a request in the composer. From the command line:

```bash
hermit fetch
hermit ask "add new video game rules" --dry-run
hermit ask "add new video game rules"
hermit ask "what changed in games this week?"
```

Useful options:

- `--dry-run` shows the result without changing any pack
- `--plan-only` shows how the request was understood
- `--yes` skips the approval gates
- `--no-input` holds gated changes as proposals instead of prompting
- `--llm-limit N` caps the number of model calls

Review and apply held proposals:

```bash
hermit apply <proposal.json>
```

Inspect why a rule was placed where it was:

```bash
hermit explain <rule-name>
```

## Understanding results

### Rule severity

| Severity | Meaning |
| --- | --- |
| **threat** | Strong evidence of malicious content. Raises the case to **High Concern** in Mantha Ray. |
| **suspicious** | Indicators that warrant inspection. Raises the case to **Needs Review**. |
| **info** | Context only. Shown in the report but does not change the verdict. |

Severity is assigned deterministically from, in order: the rule's `score` metadata, malicious tags, name prefixes (`MAL_`, `APT_`, `SUSP_`, `HKTL_`, `PUA_`, `Tool_`), and the pack default. Explicit `SUSP_`, `HKTL_`, `PUA_`, and `Tool_` prefixes lower a blanket score. Overrides in `config/demotions.toml` are applied last.

### Rule states

| State | Effective severity | Ends |
| --- | --- | --- |
| **Probation** | info | After 14 days, or with `hermit promote --now`. Promoted only if it does not match the clean set. |
| **Uncertain** | info | Remains at info until the rule's text changes. |
| **Demoted** | info | Remains at info. |
| **Active** | Proposed severity | — |

### Request outcomes

| Outcome | Meaning |
| --- | --- |
| **Applied** | The change passed the gates and was written as a new pack version. |
| **Held** | The change exceeded a gate and was saved as a proposal for review. |
| **Dry run** | The change was calculated but not written. |
| **Nothing to do** | No new rules matched the request. |

## Pack output

Each live pack is stored under `packs/<id>/` in the bundle contract layout, with Hermit's own state alongside it:

```text
packs/games/
├── pack.json
├── severities.json
├── pack.yarx
├── rules/
│   └── <namespace>.yar
└── .hermit/
    ├── state.json
    ├── baseline.json
    ├── CHANGELOG.md
    ├── history.jsonl
    └── history/
        └── v0001/
```

### Important files

- `pack.json` — pack metadata and digest
- `severities.json` — effective severity for every rule
- `rules/` — rule text, one file per namespace
- `.hermit/state.json` — every rule with its dependencies, severity, status, decision source, licence, and upstream origin
- `.hermit/baseline.json` — every rule the pack has considered, so declined rules are not judged again
- `.hermit/CHANGELOG.md` — human-readable version history
- `.hermit/history/` — saved versions used for rollback

Each rule's dependencies are stored with it, so a pack can be rebuilt or rolled back after a rule changes or disappears upstream.

## Publishing bundles

Generate the release key once:

```bash
hermit keygen
```

The secret key is password-protected, created with `minisign`, and written outside the repository. The public key is written to `config/minisign.pub`. The release key can push rules to every Mantha Ray install, so always keep it password-protected and publish from a terminal, where `minisign` can ask for the password. For demos and testing, `hermit keygen --no-password` creates a key that needs no password; `publish` warns when it signs with one.

Build, sign, and verify a bundle locally, as a dry run that takes no version number:

```bash
hermit publish --no-push
```

Publish a GitHub release to the repository set in `[bundle] release_repo`:

```bash
hermit publish
```

Publishing:

1. Confirms the installed YARA-X version matches `[bundle] yara_x_version`
2. Builds the bundle and applies the licence filter
3. Writes a deterministic archive and signs it
4. Verifies the archive exactly as Mantha Ray will
5. Records the version only after the release succeeds

Verify any bundle the way Mantha Ray's updater does:

```bash
hermit verify <bundle.tar.gz>
hermit verify <bundle.tar.gz> --installed 2026.10.22.1   # also refuse a rollback
```

Export an unsigned bundle folder for local testing:

```bash
hermit export-bundle --unsigned <folder>
```

The bundle format is specified in [docs/bundle-contract.md](docs/bundle-contract.md), and `hermit/contract.py` is its reference validator.

## Scheduled updates

`hermit auto` adds new rules to every pack without prompting and holds gated changes for approval. It exits with status `3` when a proposal is held.

A systemd user timer for weekly updates is described in [docs/how-it-works.md](docs/how-it-works.md#hands-off-schedule).

## Configuration

| File | Purpose |
| --- | --- |
| `config/hermit.toml` | Paths, model, automation, and bundle settings |
| `config/categories.toml` | Pack definitions, signals, weights, thresholds, and descriptions |
| `config/sources.toml` | Rule sources |
| `config/demotions.toml` | Manual severity overrides |

The model reads each pack's description. Changing a pack's description or signals causes its borderline rules to be judged again.

## Development

Run the tests from the repository root:

```bash
python -m unittest discover -s tests -v
```

Continuous integration runs the tests and the offline demonstration on Python 3.11, 3.12, and 3.13.

The web interface uses plain HTML, CSS, and JavaScript under `hermit/web/` and has no build step.

## Project structure

```text
mantha-hermit/
├── hermit/
│   ├── cli.py          command-line interface
│   ├── ask.py          request handling and pack updates
│   ├── server.py       local web server and JSON API
│   ├── web/            web interface
│   ├── intent.py       rules-only request parser
│   ├── llm.py          Ollama client and borderline judge
│   ├── parse.py        YARA parsing, compile checks, licences
│   ├── features.py     file-type detection
│   ├── classify.py     per-pack scoring and severity
│   ├── families.py     malware-family labels
│   ├── pipeline.py     load, score, and judge
│   ├── livepacks.py    versioned packs, probation, rollback
│   ├── cleantest.py    clean-set scanning
│   ├── contract.py     bundle contract writer and validator
│   ├── bundle.py       export, archive, publish, verify
│   └── signing.py      minisign-compatible signing
├── config/
├── docs/
│   ├── how-it-works.md
│   └── bundle-contract.md
├── examples/
├── scripts/
│   ├── demo.sh
│   └── gui-demo.sh
├── tests/
├── pyproject.toml
└── README.md
```

## Troubleshooting

### `hermit: command not found`

The virtual environment is not active or Hermit is not installed in it:

```bash
. .venv/bin/activate
pip install -e .
```

### The interface opens in the browser instead of a window

The desktop extra is not installed:

```bash
pip install -e '.[desktop]'
```

### Ollama is not reachable

Confirm the service is running and the configured model is available:

```bash
ollama list
hermit status
```

Hermit continues without a model; borderline rules are left for a later run.

### A request is understood incorrectly

Check how it was parsed:

```bash
hermit ask "<request>" --plan-only
```

Naming the pack directly, or adding terms to the pack's `aliases` in `config/categories.toml`, makes requests easier to match.

### Rules fail to compile

Compile failures are listed with their reason in the run report. Rules that use features unsupported by YARA-X are excluded rather than silently dropped.

### Publishing reports a YARA-X version mismatch

The installed YARA-X must match the version Mantha Ray pins. Install the version set in `[bundle] yara_x_version`:

```bash
pip install 'yara-x==1.22.0'
```

### A change was held instead of applied

The change exceeded an approval gate. Review the proposal in the interface or apply it from the command line:

```bash
hermit apply <proposal.json>
```

## Current limitations

- Public rule sets contain very few rules specific to games, so the `games` pack relies largely on hand-written rules.
- Most rules from aggregated sources share the same score, so severity depends heavily on name prefixes.
- Rules without a known licence are excluded from published bundles, which removes a large share of some sources.
- Model judging takes several seconds per borderline rule on consumer hardware; the first run over a large source is slow.
- Clean-set testing is only as broad as the clean files provided in `clean_dirs`.

## Roadmap

Planned work includes:

- A user edition for local changes layered over the official packs
- `local:` packs created by users
- Pack export, import, and community sharing
- Use of upstream rule-quality metadata in severity assignment
- Model agreement evaluation

## Related projects

- **Mantha Ray** — local static malware triage for Linux, using ClamAV, capa, FLOSS, and a YARA-X stage that loads Hermit's packs
- **Mantha Reef** — a VS Code extension that scans workspaces for security issues and uses Mantha Ray to triage files

## Responsible use

Mantha Hermit is intended for defensive security work, education, and authorized research.

Only redistribute rules in accordance with their upstream licences. Hermit records each rule's licence in every bundle, but the publisher remains responsible for compliance.

## License

[MIT](LICENSE) © 2026 Shashank Mantha. The example rules in `examples/rules/` are CC0. Rules packaged from other sources keep their upstream licences.