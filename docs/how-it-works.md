# How Hermit works

Reference for running Hermit as the pack maintainer. The [README](../README.md) has the overview; the [bundle contract](bundle-contract.md) has the format Mantha Ray loads.

## Commands

| Command | What it does |
|---|---|
| `hermit fetch` | Download or update the rule sources in `config/sources.toml` (git repos or zip releases) |
| `hermit ask "<request>"` | Carry out a plain-English request against the live packs (add, remove, report) |
| `hermit auto` | Scheduled run: add new rules to every pack, never prompts, holds big changes for approval |
| `hermit apply <proposal.json>` | Apply a proposal that `ask` or `auto` held |
| `hermit promote [packs] [--now]` | End probation for rules whose time is up (or all of them), clean-set tested first |
| `hermit packs [--history N]` | What the live packs hold |
| `hermit rollback <pack> [--to N]` | Restore an earlier version (saved as a new version) |
| `hermit explain <rule>` | File types, score in every pack and each reason |
| `hermit export-bundle --unsigned DIR` | The live packs as an unsigned bundle folder (contract v1) |
| `hermit keygen [--no-password]` | Create the minisign key pair for signing bundles (password-protected unless `--no-password`) |
| `hermit publish [--no-push]` | Build, sign, verify and (with `release_repo` set) create a GitHub release |
| `hermit verify <bundle.tar.gz> [--installed V]` | What Mantha Ray's updater does: signature, signed version and hash, rollback check, safe unpack, strict validation |
| `hermit validate <dir>` | Strict contract check of a bundle folder or a pack folder |
| `hermit serve [--browser] [--port N]` | The app, in its own window (needs the `desktop` extra) or in your browser |
| `hermit desktop-entry [--remove]` | Add the app to your desktop's app menu |
| `hermit sort`, `hermit find`, `hermit test` | Lower-level tools: write candidate folders for inspection, run a clean-set check |

## `ask`: from a request to an updated pack

1. **Understand.** The model turns the request into a small command. The command has:
   - an action: add, remove or report;
   - which rules: new, all, or since a date;
   - a topic;
   - a target pack.

   The command is validated against fixed values, so an invalid or unexpected answer is rejected, never run. If Ollama is off, a rules-only parser handles the common phrasings using pack names and the `aliases` in `categories.toml`. `--plan-only` shows how a request was understood.
2. **Fetch** the sources (unless `--rules`, `--no-fetch` or `fetch_before_ask = false`).
3. **Promote** rules in the target pack whose probation has ended.
4. **Select.** "New" means new *to that pack*: each pack remembers every rule it has considered, so it never re-judges a rule it already turned down. Rules you removed stay out.
5. **Score and judge.** Rules are scored as below.
   - Borderline rules go to the model twice, with different wording, and both answers must agree confidently.
   - If they disagree, or the model is unsure, the rule goes in at `info` and is marked uncertain.
   - Rules the model never got to (Ollama down, `--llm-limit`) are left for the next run.
6. **Clean-set test.** New and changed rules are scanned against `clean_dirs` (known-clean files, such as game installs you own). A rule that fires there is demoted to `info`. One that fires on `drop_after_clean_hits` or more files is dropped and remembered as excluded.
7. **Gates.** It applies on its own unless the request would:
   - change more than `max(25, 15% of the pack)` rules;
   - create a pack that isn't in `categories.toml`;
   - or remove rules.

   Then it asks, or with `--no-input` (always, in `auto`) saves the proposal for `hermit apply`. `--yes` skips the gates.
8. **Apply** as a new pack version, with a changelog entry.

### Severity while rules are new

| State | Effective severity | Ends |
|---|---|---|
| Probation (every new or changed rule) | info | After `probation_days` (14); `hermit promote --now` ends it early. Promoted to its proposed severity if it doesn't fire on the clean set, otherwise kept at info or dropped |
| Uncertain (model unsure or passes disagreed) | info | Stays info. Re-judged only if the rule's text changes |
| Demoted (fired on a clean file, slow pattern, or `demotions.toml`) | info | Stays info |

## How a rule gets sorted

1. **Parse and compile-check.**
   - Every rule is compiled with YARA-X on its own, with its dependencies (private rules it references, global rules and imports).
   - Rules that don't compile are listed with the reason, never silently dropped.
   - LOKI/THOR-style rules that read `filename`, `filepath` or `extension` compile with those defined as externals.
2. **File types.**
   - Each rule's file types come from its condition's gates: `uint16(0) == 0x5A4D`, the ELF magic, use of `pe.`/`elf.`, or the OLE, PDF, RTF and LNK magics. Failing that, they come from its name, description and strings.
   - Webshell, Office, PDF, RTF, mail, memory-only, Android, macOS and LNK rules are not applicable to any pack by default.
3. **Scoring** against each pack in `config/categories.toml`. Weighted term lists are matched against the name, tags, description, strings and file types. Every point is recorded as a reason, e.g. `+3 family: name: 'lumma*'`.
4. **Bands.** At or above `include_score` the rule is in. Between `review_score` and `include_score` it's borderline. Below that, it's out.
5. **Local model, borderline rules only.**
   - **What it sees:** the rule summary and the pack descriptions. It answers in JSON, which is validated against the real pack names.
   - **What it can't do:** change severity, or override a file-type exclusion, a demotion or a compile failure.
   - **Rule text is untrusted data.** The prompt says so, and the model is told to ignore any instructions inside a rule.
   - **Answers are cached**, so re-runs only ask about rules it hasn't seen.
6. **Severity** is proposed deterministically. It comes from the first of these that applies:
   1. the meta `score` (≥ 75 threat, ≥ 60 suspicious, otherwise info);
   2. `malicious` tags;
   3. name prefixes (`MAL_`/`APT_`, `SUSP_`/`HKTL_`, `PUA_`/`VULN_`/`Tool_`);
   4. the pack default.

   An explicit `SUSP_`, `HKTL_`, `PUA_` or `Tool_` prefix lowers a blanket score. `riskware` is capped at info, so it labels without changing the verdict.
7. **Demotions** in `config/demotions.toml` (`drop` or `info`, with a reason) are applied last.

## The live packs

`packs/<id>/` is a pack folder in [contract v1](bundle-contract.md) layout, plus Hermit's own state:

| Path | What it is |
|---|---|
| `pack.json`, `severities.json`, `rules/*.yar`, `pack.yarx` | The pack, exactly as it ships (before the licence filter) |
| `.hermit/state.json` | Every rule with its text, dependencies, proposed and effective severity, status, who decided and why, upstream, licence and source; plus the excluded rules |
| `.hermit/baseline.json` | Every rule this pack has considered |
| `.hermit/CHANGELOG.md`, `history.jsonl`, `history/vNNNN/` | Every version, for reading and rollback |

Each rule's dependencies (private and global rules) are stored with it, so a pack can be rebuilt or rolled back even after upstream changes or deletes a rule. Packs in the older layout (state in `pack.json`) are migrated automatically the first time they're opened.

## Publishing

```
hermit keygen                 # once: password-protected secret key outside the repo, public key in config/minisign.pub
hermit publish --no-push      # build, sign, verify locally
hermit publish                # ... and create a GitHub release on [bundle] release_repo (needs gh)
```

What `publish` does:

1. Checks that the installed YARA-X matches `[bundle] yara_x_version`, the version Mantha Ray pins.
2. Builds the bundle, applying the licence filter (`require_licence`, `allowed_licences`).
3. Writes a deterministic `tar.gz` and signs it in minisign format, with the trusted comment `mantha-packs <version> sha256:<hash>`.
4. Verifies the result exactly as Mantha Ray will.

Versions always increase, even if the clock goes backwards, because Mantha Ray refuses a bundle older than the one it has installed.
5. Records the version only after any push succeeds, so a failed push can simply be re-run.

`hermit keygen` makes a password-protected key with the `minisign` tool, and `publish` asks for the password when it signs. The release key can push rules to every install, so keep it that way. Publish from a terminal: the app can't ask for the password, so it won't publish with a protected key. `hermit keygen --no-password` makes a key without a password, which needs no `minisign` tool, for demos and testing only; `publish` warns when it signs with one.

## The app (`hermit serve`)

`hermit serve` opens it in its own window, the same way Mantha Ray does: pywebview with Qt, installed with `pip install -e '.[desktop]'`. The window has downloads, file URLs and remote debugging turned off. Closing the window stops the app, but a request that's still running is finished first, so a pack is never left half-written. Without the desktop extra, or with `--browser`, it opens in your browser at `http://127.0.0.1:8765`; `--no-browser` just runs the server. `hermit desktop-entry` adds it to your app menu.

It's a chat-style front end over the same functions as the CLI:
- **Requests** run as background jobs, and the page shows each pipeline step live.
- **Held changes** get an Apply button, and applied ones an Undo button.
- **The pack panel** shows every rule with its text, current and planned severity, who chose it, source, licence and scoring reasons. It also has export, publish, end-probation and undo actions.
- **Chats** are saved in `state/chats.json`, and held proposals in `state/held.json`.

How it's protected:
- **Who can reach it.** The server listens on `127.0.0.1` only. It refuses requests whose Host header isn't this machine, which blocks DNS-rebinding attacks from web pages.
- **Who can call the API.** Every `/api` call needs the token printed into the page when the server starts. A page on another site can't read it.
- **What the page can load.** The Content-Security-Policy allows scripts and styles only from the server itself: no inline script, and no third-party anything.
- **Rule data stays text.** Rule names and text come from the internet, so the frontend inserts them as text, never as HTML.
- **One job at a time.** Only one job runs at a time, so two requests can't write the same pack at once.

`./scripts/gui-demo.sh` starts it on the example rules in a throwaway workspace.

## Hands-off schedule

A systemd user timer, named and described so it explains itself. Mantha Ray's `linux-proton` pack flags unexplained user timers.

```
# ~/.config/systemd/user/hermit-auto.service
[Unit]
Description=hermit: update Mantha Ray rule packs from community YARA rules
[Service]
Type=oneshot
WorkingDirectory=%h/mantha-hermit
ExecStart=%h/mantha-hermit/.venv/bin/hermit auto

# ~/.config/systemd/user/hermit-auto.timer
[Unit]
Description=Weekly hermit update of Mantha Ray rule packs
[Timer]
OnCalendar=Sun 03:00
Persistent=true
[Install]
WantedBy=timers.target
```

Enable it with `systemctl --user enable --now hermit-auto.timer`. `auto` exits with 3 when a proposal is held, so `journalctl --user -u hermit-auto` shows what's waiting.

## Tuning

- **`hermit explain <rule>`** shows why a rule landed where it did.
- **`config/categories.toml`** holds the terms, weights, thresholds, file types, editions and descriptions. The model reads the descriptions. Changing a pack's description or signals re-asks the model about that pack.
- **`--llm-limit N`** caps model calls; the most promising borderline rules go first.
- **`HERMIT_MODEL` and `HERMIT_OLLAMA`** override the model and endpoint for one run.
- **`[ollama] think = false`** turns off thinking for models like qwen3.5, which makes them much faster.

## Candidate folders (`sort`, `find`)

`hermit sort` and `hermit find` write `out/<timestamp>-<label>/` without touching the live packs:
- one folder per pack, with rules, `manifest.json` and `pack.yarx`;
- `review.csv` with the borderline rules;
- `report.md`.

Use them to inspect what a configuration change would do.