# Vulnerabilities and Remediations

Security assessment of `cincinnati-graph-data` and its tooling, with the fix
for each issue. Findings were produced by manual review and a multi-agent
verification pass: every fix was re-checked against the pre-fix code
(commit `a10d1af`), and newly discovered issues were each confirmed by three
independent adversarial reviewers before being listed here.

**Status at a glance**

| ID | Vulnerability | Severity | CWE | Status |
|----|---------------|----------|-----|--------|
| V1 | ReDoS via unvalidated blocked-edge regexes; no presubmit | Medium | CWE-1333 | Fixed (defense-in-depth; see residual) |
| V2 | Registry blobs used without digest/size checks; unsafe tar extraction | Medium | CWE-494 / CWE-409 | Fixed |
| V3 | Exception handlers catch the wrong types | Low | CWE-755 | Fixed |
| V4 | Slack webhook credential passed on the command line | Low | CWE-214 | Fixed |
| V5 | No HTTP timeouts, Python 2 TLS, sleep bug, bad Slack payload | Low | CWE-1088 | Fixed |
| V6 | Path traversal / arbitrary file write via registry `manifest_digest` | **High** | CWE-22 | Fixed |
| V7 | GitHub Actions pinned to mutable tags | Low | CWE-829 | Fixed |
| V8 | Unpinned `pip install PyYAML` in CI | Low | CWE-494 | Fixed |

## Threat model

The security-critical property of this repository is the **integrity of
OpenShift update recommendations**. Merge access can steer or delay cluster
updates (e.g. by blocking the edges to a security release), but cannot inject
arbitrary payloads: channel entries must resolve to release images that already
exist in `quay.io/openshift-release-dev/ocp-release`, and those images are
independently signed. Review of data changes (OWNERS gating) is the primary
control. The `hack/` scripts are operator-run utilities; several findings below
concern what a **compromised or misbehaving registry** can do to the operator
running them — a threat model this repository's own review already adopts.

---

## V6 — Path traversal / arbitrary file write via registry `manifest_digest` (High, CWE-22)

**The most serious issue, discovered during fix verification.**

`load_nodes()` in `hack/graph-util.py` built local cache paths directly from the
registry's tag listing without validating the digest. Both halves of
`manifest_digest` were used as path components with no charset or traversal
check:

```python
# BEFORE (a10d1af), hack/graph-util.py load_nodes()
algo, hash = entry['manifest_digest'].split(':', 1)
...
path = os.path.join(directory, algo, hash)   # attacker-controlled components
with open(path) as f: ...                     # cache READ, parsed as YAML
...
os.makedirs(os.path.join(directory, algo), exist_ok=True)
with open(path, 'w') as f:                     # cache WRITE
    yaml.safe_dump(meta, f, ...)               # attacker-influenced contents
```

**Attack.** A compromised or misbehaving Quay response (the threat model V2
already defends against) returns a tag whose `manifest_digest` is, for example,
`sha256:../../channels/stable-4.5.yaml` or `sha256:/tmp/pwned`. When an operator
runs `hack/graph-util.py push-to-quay`, `os.path.join`/`normpath` resolves the
path outside the `.nodes` cache directory, giving the attacker control of both
the destination path and the file body — an arbitrary file overwrite (verified
empirically to clobber a repo file outside `.nodes`, and to write to `/tmp`).
The write executes on a cache miss before any version validation runs.

**Fix.** The digest is validated against a strict pattern before it is used for
anything; a malformed digest is logged and skipped:

```python
# AFTER, hack/graph-util.py
_DIGEST_REGEXP = re.compile('^[a-z0-9]+:[0-9a-f]+$')
...
digest = entry['manifest_digest']
if not _DIGEST_REGEXP.match(digest):
    _LOGGER.warning('skipping tag {} with malformed manifest_digest {!r}'.format(entry.get('name'), digest))
    continue
algo, hash = digest.split(':', 1)
```

The pattern permits only a lowercase-alphanumeric algorithm and a hexadecimal
value, so neither component can contain a path separator or `..`. Verified: all
traversal payloads above are rejected, and real digests still resolve inside
`.nodes/`.

---

## V1 — ReDoS via unvalidated blocked-edge regexes; no presubmit (Medium, CWE-1333)

`blocked-edges/*.yaml` `from` values are compiled as regexes by `block_edges()`
and matched against candidate versions by every consumer of the graph data.
Before the fix the repository had **no CI at all**, so a data-only PR could merge
a catastrophic-backtracking pattern (e.g. `(a+)+`) that hangs graph tooling —
denial of service via a "just data" change. The compile was also wrapped in
`except ValueError`, which never fires for `re.error` (see V3).

**Fix.** A presubmit, `hack/validate-graph-data.py`, now schema-checks every
data file, compiles every `from` pattern, screens for catastrophic-backtracking
shapes, and time-boxes sample matches. It runs in a least-privilege GitHub
Actions workflow (`.github/workflows/validate.yaml`) on every pull request and
push to `master`.

The catastrophic-backtracking screen was **strengthened after review** showed
the first heuristic (a single regex) was bypassable by patterns such as
`(a|a)*b` and `((a+))+`. The screen now parses the pattern — correctly skipping
escaped characters and `[...]` classes — and flags any group that is itself
quantified and whose body contains an alternation or another quantifier:

```python
def risky_quantified_group(pattern):
    # flags (a+)+, (a|a)*, ((a+))+, (a|ab)*, (a{1,9})+ ...
    # leaves 4\.1\.(18|20) and 4\.(1|2)\.\d+ (unquantified groups) alone
```

Verified: the documented bypasses are now rejected, and every real pattern in
`blocked-edges/` (including `.*`, `4\.1\..*`, `4\.1\.(18|20)`) still passes.

**Residual risk (accepted).** A static ReDoS screen is a heuristic, not a proof;
a sufficiently exotic pattern could still slip past, and the runtime
`block_edges()` match has no timeout. In practice this consumer only matches
against short, semver-validated version strings, and the OWNERS review of data
PRs remains the primary gate. A fully sound guarantee would require a
linear-time regex engine (e.g. RE2) or restricting `from` to a fixed safe
grammar; both are noted as future options.

---

## V2 — Registry blobs used without digest/size checks; unsafe tar extraction (Medium, CWE-494 / CWE-409)

`get_release_metadata()` downloaded config and layer blobs, read them fully into
memory with no size bound, and never checked the bytes against the requested
digest; it then opened them as tar archives and `extractfile()`d members with no
type or size guard.

```python
# BEFORE (a10d1af)
f = urlopen(uri); layer_bytes = f.read(); f.close()   # unbounded, unverified
with tarfile.open(fileobj=io.BytesIO(layer_bytes), mode='r:gz') as tar:
    f = tar.extractfile('release-manifests/release-metadata')  # no guards
```

**Attack.** A compromised registry serves a decompression bomb (memory
exhaustion) or substitutes forged release metadata (accepted as ground truth and
cached), or swaps a member for a symlink.

**Fix.** All downloads go through `get_verified_blob()`, which streams in chunks,
aborts past a size cap, and rejects any payload whose hash does not match the
requested digest. Tar access goes through `extract_metadata_member()`, which
rejects non-regular-file members and members over a 10 MiB cap before
extraction. Both blob call sites and both extraction sites are covered; errors
degrade to a per-node warning. Verified against synthetic good and bad inputs
(digest mismatch, oversize blob, symlink member, oversize member).

**Residual risk (accepted).** Digest verification is anchored to the manifest,
which is itself not re-verified against the tag's signed digest, so a
registry-wide compromise serving a self-consistent forged manifest plus matching
blobs is out of scope for this control. A digest-matching gzip layer within the
size cap can still cost CPU time to scan (memory stays bounded). These are
documented limits, not gaps in the implemented fix.

---

## V3 — Exception handlers catch the wrong types (Low, CWE-755)

`hack/graph-util.py` wrapped `yaml.load` in `except ValueError` (three sites) and
`re.compile` in `except ValueError` (one site). PyYAML raises `yaml.YAMLError`
and invalid regexes raise `re.error` — neither is a `ValueError` — so the
handlers were dead code and malformed input crashed with a raw traceback that
did not identify the offending file.

**Fix.** The handlers now catch `yaml.YAMLError` and `re.error` respectively,
each re-raising a contextual `ValueError` with the file path. `yaml.SafeLoader`
was already in use, so there was never a code-execution path — the impact was
lost error context only. The new validator uses the correct types from the
start.

---

## V4 — Slack webhook credential passed on the command line (Low, CWE-214)

`hack/errata.py` took the Slack webhook URL — a bearer-style credential — as a
positional CLI argument, exposing it in `ps` output and shell history for the
lifetime of the long-running poller.

**Fix.** The positional argument was removed; the webhook is read from the
`SLACK_WEBHOOK_URL` environment variable, and the help text documents that it is
a credential. The old invocation now fails loudly instead of silently leaking.

```python
# AFTER, hack/errata.py
run(cache=cache, webhook=os.environ.get('SLACK_WEBHOOK_URL'))
```

---

## V5 — Missing timeouts, Python 2 TLS, sleep bug, malformed Slack payload (Low, CWE-1088)

A cluster of robustness/security issues in both scripts:

* **No HTTP timeouts** — every `urlopen` could hang forever on a stalled
  endpoint. All calls now pass `timeout=30`.
* **Python 2 fallbacks** — the `urllib2` shim and `python` shebang invited
  execution under EOL Python 2 with outdated/absent TLS verification. Removed;
  the shebang is now `python3` and responses are context-managed.
* **Sleep arithmetic** — `time.sleep((next_time - now).seconds)` wrapped a
  negative timedelta to as much as ~86,399 seconds (nearly a day). Replaced with
  `total_seconds()` and explicit overrun handling.
* **Slack payload** — the notification form-encoded a nested dict (a Python
  `repr`, not JSON), so it never conformed to Slack's webhook contract. Now
  `json.dumps`-encoded.

---

## V7 — GitHub Actions pinned to mutable tags (Low, CWE-829)

The new workflow pinned `actions/checkout@v4` and `actions/setup-python@v5` by
floating tag. A repointed tag (the mechanism of the March 2025
`tj-actions/changed-files` compromise) would run attacker code in the job — able
to subvert the very validation check the workflow provides.

**Fix.** Both actions are pinned to full commit SHAs with a version comment, and
`persist-credentials: false` is set on checkout:

```yaml
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
  with:
    persist-credentials: false
- uses: actions/setup-python@0b93645e9fea7318ecaed2b359559ac225c90a2b # v5.3.0
```

---

## V8 — Unpinned `pip install PyYAML` in CI (Low, CWE-494)

The workflow ran `pip install PyYAML` with no version pin, so each CI run
fetched whatever PyPI served — a supply-chain exposure (a malicious PyYAML
release would execute inside the job via `import yaml`) and a reproducibility
problem.

**Fix.** The install is pinned: `pip install PyYAML==6.0.2`. Hash-pinned
`--require-hashes` via a committed `requirements.txt` is noted as a stronger
future step.

---

## Considered and dismissed

For transparency, four additional candidate findings were investigated and
**rejected** by adversarial review as either duplicates or non-issues:

* **Decompression-bomb residual in the tar scan** — a real but bounded CPU cost
  that is a residual facet of V2 (already documented), not a new memory-
  exhaustion vulnerability; the per-member cap and chunked discard bound memory.
* **Validator ReDoS screen is bypassable** — folded into V1, whose screen has
  since been strengthened and whose residual is documented above.
* **Blocked-edge patterns are start-anchored / use unescaped dots** — no current
  impact (no version in the data is mis-matched), and the only failure direction
  is fail-safe over-blocking. Authentic upstream style, not a defect.
* **A green CI check does not attest data validity on PRs that edit the
  validator** — inherent to all `pull_request` CI and already mitigated by
  OWNERS review; an integrity caveat, not a code defect. Adding a CODEOWNERS
  entry for `hack/` and `.github/` is a reasonable process hardening.

## Good practices confirmed

* `yaml.SafeLoader` is used for every YAML load — no unsafe deserialization.
* Non-Quay pullspecs are rejected, pinning metadata fetches to the expected
  registry over HTTPS.
* The Quay label-mutation path is disabled and degrades to a dry run without a
  token; no credential is read from the environment or disk in that path.
* No secrets, keys, or webhook URLs are committed anywhere in the history.
