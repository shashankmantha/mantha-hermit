# Bundle contract v1

The boundary between Hermit, which builds rule packs, and Mantha Ray, which loads them. Mantha Ray validates every bundle against this contract. Anything that doesn't match is rejected with a clear message, and the data already in use stays in use.

The reference implementation is [`hermit/contract.py`](../hermit/contract.py) (`validate_bundle`, `validate_pack`) and [`hermit/bundle.py`](../hermit/bundle.py) (`verify_bundle`, `safe_extract`). A bundle that `hermit verify` accepts must be accepted by Mantha Ray, and the reverse.

## Layout

```
mantha-packs-<version>.tar.gz           the bundle (deterministic: sorted, fixed owner and time)
mantha-packs-<version>.tar.gz.minisig   detached minisign signature
  manifest.json
  packs/<pack-id>/pack.json
  packs/<pack-id>/severities.json
  packs/<pack-id>/rules/<namespace>.yar  rule text: what Mantha Ray compiles
  packs/<pack-id>/pack.yarx              optional pre-compiled rules (see "Compiled rules")
```

An unsigned folder with the same layout (`hermit export-bundle --unsigned DIR`) is used before signing exists, for local testing.

Nothing else may appear: no extra files, no symlinks, no links or special files in the archive, and no path that leaves the extraction folder.

## `manifest.json`

| Field | Type | Meaning |
|---|---|---|
| `format` | int | `1` |
| `bundle_version` | string | `YYYY.M.D.N`, e.g. `2026.10.25.1`; strictly increases with every publish. Compare as four integers, never as text: `2026.10.22.12` is newer than `2026.10.22.2` |
| `created_at` | string | UTC, `2026-10-25T03:00:00Z` |
| `min_app_version` | string | `X.Y.Z`; the oldest Mantha Ray that can use this bundle. Older installs refuse it politely |
| `yara_x_version` | string | YARA-X version that built any `pack.yarx` |
| `packs` | list | `{id, version, sha256}` per pack folder; see "Pack hash" |
| `sources` | list | `{name, url, revision, licence}` (each value text or null) |
| `changes` | string | short release notes |

`packs` must list exactly the folders under `packs/`. `local:` packs never ship in bundles.

### Pack hash

`sha256` is the SHA-256 of this text: one line `<sha256 of file>  <path relative to the pack folder>\n` per file, sorted by path. It's the same text `sha256sum` prints, so you can check it by hand:

```
cd packs/games && find . -type f | sed 's|^\./||' | LC_ALL=C sort | xargs sha256sum | sha256sum
```

## `pack.json`

| Field | Type | Meaning |
|---|---|---|
| `format` | int | `1` |
| `id` | string | lowercase letters, digits and hyphens, matching the folder name; `local:` is reserved for user packs |
| `version` | int | pack version, ≥ 1 |
| `kind` | string | `detection` or `recognition` |
| `editions` | list | Mantha Ray editions that load the pack, lowercase names; `all` means every edition |
| `description` | string | optional; shown in reports |
| `rules` | list | `{namespace, name, file, source, licence}` for every rule that can produce a match |
| `externals` | list | external variables the rules read, from `filename`, `filepath`, `extension` |

- **Namespaces.** Each rule file is compiled into its own YARA-X namespace, named after the file. So `namespace` equals the file name without `.yar`, and `file` is always `rules/<namespace>.yar`.
- **Rules that aren't listed.** Private and global helper rules that listed rules depend on sit in the same file but aren't listed.
- **`source` and `licence`.** `source` is the rule's upstream repository (or the source name). `licence` is an SPDX id or a licence URL, or null.

## `severities.json`

| Field | Type | Meaning |
|---|---|---|
| `format` | int | `1` |
| `severities` | object | `"namespace:rule"` → `threat`, `suspicious` or `info`: **the severity to apply** |
| `demoted` | object | `"namespace:rule"` → reason, for rules held at `info` because they fired on clean files, the model wasn't sure about them, or YARA-X flagged them as slow |
| `probation` | object | `"namespace:rule"` → `YYYY-MM-DD`, for new rules held at `info` until that date |

- **No calculation needed.** `severities` already accounts for demotion and probation, so Mantha Ray applies it as it is. `demoted` and `probation` only explain why a rule is at `info`.
- **Every key must name a rule in `pack.json`**, and a rule on probation must be `info`.
- **Rules missing from `severities` are treated as `info`.** Mantha Ray reports how many there were.

| Severity | Verdict effect in Mantha Ray |
|---|---|
| `threat` | High Concern |
| `suspicious` | Needs Review |
| `info` | Shown in the report only |

## Scanning

- **Define the externals before compiling.** For every name in `externals`, define the external as an empty string before compiling. When scanning, set `filename` (the file's name), `filepath` (its folder) and `extension` (lower-case suffix with the dot) for each file.
- **Apply limits.** Use a per-file timeout and a cap on matches per file.

## Compiled rules (`pack.yarx`)

- **Use it only from a verified bundle.** Mantha Ray uses `pack.yarx` only when the bundle's signature verified **and** `manifest.yara_x_version` equals its own YARA-X version. Otherwise it compiles `rules/*.yar` itself.
- **Compiling from rule text always works.** It's safe and needs no signature. Hermit validates that every rule file compiles before publishing.
- **Hermit's pinned version.** Hermit refuses to publish when its YARA-X differs from the version pinned in `[bundle] yara_x_version`, unless told to leave `pack.yarx` out.

## Signing

[minisign](https://jedisct1.github.io/minisign/) (Ed25519, prehashed with BLAKE2b-512), as a detached `.minisig` next to the archive.

- **Trusted comment:** exactly `mantha-packs <bundle_version> sha256:<archive sha256>` (64 lowercase hex digits). Verifiers parse it as a whole, never by prefix: `mantha-packs 2026.10.22.1` must not match a comment for `2026.10.22.12`.
- **The release key is password-protected** (`hermit keygen`, which uses `minisign -G`). It can push rules to every install, so it is never stored without a password. `hermit keygen --no-password` makes keys for demos and tests only.
- **The public key** (`minisign.pub`) ships in Mantha Ray's repository. The secret key stays on the owner's machine, outside any repository, with an offline backup.
- **Key rotation.** Ship the new public key in a Mantha Ray code update, then sign with the new key. If a key leaks, publish a code update that removes it.
- **Verifying with the minisign tool:** `minisign -Vm mantha-packs-<version>.tar.gz -p minisign.pub`

## How the updater should verify (in order)

1. **Verify the signature** of the downloaded archive against the bundled public key. If the check fails, stop.
2. **Parse the trusted comment exactly** as `mantha-packs <version> sha256:<hash>`. Reject anything else.
3. **Check the archive's SHA-256** against the signed hash.
4. **Refuse rollbacks.** If the signed version is older than the installed `bundle_version`, stop: see "Rollback protection". If it is the same, there is nothing to update.
5. **Unpack safely** into a fresh folder: plain files and folders only, no path escapes, with size and file-count limits.
6. **Validate** the manifest, pack hashes, `pack.json` and `severities.json` as above, and compile every rule file. The manifest's `bundle_version` must equal the signed version exactly.
7. **Check `min_app_version`** against the running Mantha Ray.
8. **Switch to the new data atomically**, and record the installed `bundle_version`. On any failure, keep the current data and report why.

`hermit verify <bundle.tar.gz> --installed <version>` performs steps 1 to 6 and is the reference implementation.

### Rollback protection

A signature proves who made a bundle, not that it is the latest one. Someone who controls the download (a compromised mirror, a hostile network, a tampered cache) could serve an older bundle that is genuinely signed, for example one from before a threat rule was added, and it would pass every other check.

- **The updater refuses any bundle whose signed `bundle_version` is older than the installed one.** The installed version is stored outside the bundle data, where an update cannot overwrite it before the check.
- **Going back is a local, explicit action only** (for example `mantha-ray packs --rollback`), run by the user on their own machine, never triggered by a download.
- **Hermit never publishes a version older than one it has already published**, even if the clock goes backwards.
- **Freeze attacks** (withholding new bundles so an install keeps using old data) can't be detected from the signature alone. The updater should warn when the installed bundle's `created_at` is more than 30 days old.

## Licences

Published bundles include only rules with a known licence. Hermit's `[bundle] allowed_licences` setting can narrow that to a list. Rules without one stay out of the bundle but can still be used locally.

## Changes to the contract

- **Adding optional fields** is a compatible change within format 1.
- **Anything else** (new required fields, new folders such as `components/` for recognition data) is format 2. Mantha Ray refuses formats it doesn't know.