# Security Review: cincinnati-graph-data

Review of the repository state at commit `a10d1af` (branch
`claude/security-fable-capabilities-k4z0gx`, identical to `master`).

## Scope and method

* Manual review of all executable code: `hack/graph-util.py`, `hack/errata.py`.
* Automated validation of all data files: 17 `channels/*.yaml` and 43
  `blocked-edges/*.yaml` were parsed with `yaml.SafeLoader`, schema-checked,
  and every `blocked-edges` `from` pattern was compiled and screened for
  catastrophic-backtracking shapes (nested quantifiers).
* Secret scan across the working tree (tokens, keys, webhook URLs).

**Result: no secrets found, no malformed or suspicious data files, no unsafe
deserialization, no archive path traversal.** The findings below are
hardening opportunities, ordered by priority.

## Threat model context

This repository's security-critical property is the **integrity of update
recommendations**: merge access effectively steers OpenShift cluster update
paths (e.g. delaying a security release by blocking its edges, or keeping a
vulnerable-but-real release recommended). It cannot inject arbitrary
payloads — channel entries must resolve to existing release images in
`quay.io/openshift-release-dev/ocp-release` (enforced by
`load_channels`/`block_edges` in `hack/graph-util.py`), and release images
are independently signed. Review of data changes (OWNERS gating) is
therefore the primary control.

## Findings

### 1. Blocked-edge `from` regexes are an unvalidated code-like input (medium)

`hack/graph-util.py:217` compiles `blocked-edges/*.yaml` `from` values as
regexes and matches them against every candidate version. A pathological
pattern (e.g. nested quantifiers) merged into the repo would hang every
consumer that processes the graph data — a denial-of-service on graph
tooling via a data-only PR. All 43 current patterns are clean; the gap is
that nothing enforces this at merge time. This fork has no CI
(`.github/` is absent), so no presubmit validates new data files at all.

*Recommendation:* add a presubmit that parses every data file and compiles
every `from` pattern (optionally with a complexity screen or match timeout).

### 2. Downloaded layer blobs are not verified or bounded (medium)

`get_release_metadata` (`hack/graph-util.py:438-443`) downloads layer blobs,
reads them fully into memory, and gunzips them without verifying the bytes
against the requested digest and without any size bound. Content-addressed
URLs provide integrity only if the registry is honest; a compromised or
misbehaving registry response can feed a decompression bomb or arbitrary
oversized blob into memory.

*Recommendation:* hash the downloaded bytes and compare to `layer['digest']`
before use; cap download and decompression sizes.

### 3. Exception handling never catches the intended errors (low)

* `hack/graph-util.py:96,163,199` wrap `yaml.load` in `except ValueError`,
  but PyYAML raises `yaml.YAMLError`, which is not a `ValueError` subclass.
* `hack/graph-util.py:218` wraps `re.compile` in `except ValueError`, but
  invalid patterns raise `re.error`.

Malformed input therefore crashes with a raw traceback instead of the
intended contextual error. Not exploitable, but it hides the provenance of
bad data exactly when it matters.

### 4. Slack webhook accepted as a CLI argument (low)

`hack/errata.py:96` takes the webhook URL — a bearer-style credential — as a
positional argument, exposing it in process listings and shell history.

*Recommendation:* read it from an environment variable or file.

### 5. Robustness nits (low)

* No `urlopen` call in either script sets a timeout — a stalled endpoint
  hangs the tool indefinitely.
* `hack/graph-util.py` retains Python 2 fallbacks; running under EOL
  Python 2 means outdated TLS behavior. Dropping Py2 support removes that
  temptation.
* `hack/errata.py:47` computes `time.sleep((next_time - now).seconds)`; if a
  poll cycle overruns the period, the negative timedelta's `.seconds` wraps
  to a large positive remainder, skewing the schedule.
* `hack/errata.py:85` form-encodes the Slack payload with `urlencode`, which
  stringifies the nested dict as a Python repr rather than JSON — the
  notification path likely never worked against real Slack webhooks.

## Good practices observed

* `yaml.SafeLoader` is used for every YAML load — no unsafe
  deserialization surface.
* Tar handling uses `extractfile()` on two specific member names only —
  no `extractall`, no path-traversal exposure.
* Non-Quay pullspecs are rejected (`repository_uri`,
  `get_release_metadata`), pinning metadata fetches to the expected
  registry over HTTPS.
* The Quay label-mutation path is disabled (`push` returns before syncing)
  and degrades to a dry run when no token is supplied; no credential is
  read from the environment or disk.
* No secrets, keys, or webhook URLs are committed anywhere in the tree.
