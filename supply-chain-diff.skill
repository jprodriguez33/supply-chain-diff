---
name: supply-chain-diff
description: Checks whether a published package (PyPI, npm, etc.) matches its corresponding tagged source on GitHub, to detect supply-chain tampering — code injected at publish time that never appears in the public repo. Use this whenever the user wants to audit a package for supply-chain compromise, check if a package "matches" its GitHub source, verify a package hasn't been tampered with, investigate a suspicious version bump, or vet a dependency before adding it to a project or CI pipeline. Trigger on phrases like "check this package for tampering," "diff this package against GitHub," "is this package legit," "audit this dependency," or "supply chain check," even if the user doesn't use those exact words — e.g. "make sure this npm package is safe to install" or "did anyone mess with this release" should also trigger this skill.
---

# Supply Chain Diff

Detects supply-chain tampering by comparing what's actually published to a
package registry against what's in the corresponding tagged commit on the
package's public source repository (GitHub, GitLab, Bitbucket, Codeberg).
A mismatch — files, dependencies, or
code present in the published artifact but absent from the tagged source —
is a strong signal of compromise, since attackers who hijack a maintainer
account or a CI pipeline typically publish a malicious build without ever
pushing the malicious code to the visible git history.

## When this is worth doing

Best used on packages that are:
- **High-leverage**: widely depended-on, especially pulled into CI/CD
  pipelines (pytest plugins, pre-commit hooks, linters, build tools) —
  these compromises have outsized blast radius since most consumers never
  inspect the package directly.
- **Recently updated**: a suspicious or unexpected version bump is the
  single strongest trigger to check a package right now, since the
  vulnerable window between a malicious publish and detection is where
  real damage happens.
- **Solo/small-maintainer**: fewer eyes on the release process historically
  correlates with higher compromise risk (see: `event-stream`,
  `ua-parser-js`, `colors`/`faker`, `eslint-config-airbnb`, and more
  recently `litellm`/`lightning`-family incidents).

## Workflow

### Step 1: Identify the package and ecosystem

Ask (or infer from context) which registry the package lives on: PyPI, npm,
crates.io, RubyGems, etc. This skill's bundled script currently supports
**PyPI** and **npm** directly; for other registries, adapt Step 2's lookup
manually using the same principles (find the published artifact URL, find
the registry's declared source repo).

### Step 2: Fetch registry metadata and the published artifact(s)

Run the bundled script to get the version, source repo URL, and
download the published artifact(s) in one step:

```bash
python scripts/fetch_package.py <package-name> --ecosystem pypi
# or
python scripts/fetch_package.py <package-name> --ecosystem npm
```

By default this resolves the **latest** version. To audit a specific
release — which is the usual case, since you're often investigating one
particular suspicious version that may not be latest (or may already be
yanked) — pass `--version`:

```bash
python scripts/fetch_package.py <package-name> --ecosystem pypi --version 1.2.3
```

The script prints the resolved version and the auto-detected source URL,
and extracts each artifact into
`./supply-chain-diff-work/<package-name>-<version>/`. It also prints the
exact inner directory to diff and a ready-to-run `diff` command for each
artifact — use those paths rather than guessing, because the extracted
tree is nested one level deeper than the git checkout (see Step 4).

**For PyPI it fetches both the sdist and a wheel** when both exist, into
`published-sdist/` and `published-wheel/`. This matters: `pip install`
runs the **wheel**, not the sdist, and several real attacks inject code
into the wheel (notably auto-executing `.pth` files, which live in the
wheel layout, not the sdist) while leaving the sdist and GitHub clean.
Diff both; treat the wheel as the primary attack surface.

The script recognizes source URLs on GitHub, GitLab, Bitbucket, and
Codeberg, and understands npm's `git+https`, `git+ssh`, `git://`, and
`github:owner/repo` URL forms. If it still can't auto-detect a source URL
(some packages don't declare one cleanly), ask the user for it or search
for it. For registries other than PyPI/npm (crates.io, RubyGems, etc.),
adapt this step manually using the same principles.

### Step 3: Clone the source at the matching tag

```bash
cd supply-chain-diff-work/<package-name>-<version>
git clone <github-url> source
cd source
git tag | grep <version>
```

Tag naming isn't consistent across projects (`v1.2.3`, `1.2.3`,
`release-1.2.3`, etc.) — check the actual tag list rather than assuming.
If no exact tag matches the published version, note this explicitly as a
finding on its own (it makes independent verification harder and is worth
flagging even absent other issues), and fall back to the closest tag or
the version specified in the tagged `CHANGELOG.md`/`setup.py`/`package.json`.

```bash
git checkout <matching-tag>
```

### Step 4: Diff

Compare the two trees. Prioritize, in order:

1. **File presence differences** — anything in the published artifact
   that isn't in the tagged source at all. Use the exact `diff -rq`
   commands the script printed in Step 2 as a starting point (they point
   at the correct inner directory). Note that the extracted artifact sits
   one level deeper than the checkout: an sdist unpacks to
   `published-sdist/<name>-<version>/` and an npm tarball to
   `published/package/`, whereas the git clone is flat at `source/`. So
   compare `published-sdist/<name>-<version>/` against `source/`, not
   `published-sdist/` against `source/` — the latter reports every file as
   differing and buries real findings. Interpret results with judgment —
   see "Expected, benign differences" below. When a wheel was fetched,
   diff `published-wheel/` too; it's the artifact that actually runs.
2. **Build/packaging config** — `setup.py`, `setup.cfg`, `pyproject.toml`
   (Python) or `package.json`, install/postinstall scripts (npm).
   Specifically check for: `cmdclass` overrides, custom build hooks,
   unexpected `entry_points`/`scripts` fields, `postinstall`/`preinstall`
   npm lifecycle scripts.
3. **Auto-executing files**: `.pth` files (Python, these run arbitrary code
   at interpreter startup when present in site-packages), npm lifecycle
   scripts, any file that runs without being explicitly imported/called.
4. **Suspicious code patterns** in any file that *does* differ: network
   calls (`urllib`, `requests`, `socket`, `fetch`, `http`), reads of
   environment variables or credential paths (`os.environ`, `.ssh/`,
   `.aws/`, `.npmrc`), `eval`/`exec`/`Function()`, base64-decoded strings
   that get executed, obfuscated/minified code in a package that's
   otherwise readable source.

> **Stronger (but heavier) check:** the diff here treats the sdist/source
> tree as a stand-in for "what the maintainer built from." The gold
> standard is a reproducible build — rebuild the artifact from the tagged
> commit in a clean environment and compare the *outputs* — which catches
> tampering that a file-tree diff can miss (e.g. a compiled extension that
> differs from its declared source). It's more setup and not always
> achievable, so treat it as an escalation when the heuristic diff is
> inconclusive but suspicion remains, not the default.

### Step 5: Distinguish real findings from expected, benign differences

Most diffs will NOT indicate tampering. Before flagging anything, check
whether it's one of these well-known, benign categories:

- **Test/CI/doc files excluded from the published artifact** — `tests/`,
  `.github/`, `tox.ini`, `CONTRIBUTING.md`, etc. are routinely excluded via
  `MANIFEST.in`, `setup.cfg`'s `exclude`, or `.npmignore`. Present in
  GitHub, absent from the package: expected, not a finding.
- **Build-generated metadata** — `PKG-INFO`, `*.egg-info/`, npm's generated
  `package-lock.json` if absent upstream. Present in the package, absent
  from GitHub: expected, not a finding.
- **Cosmetic formatting differences** in config files from the build
  process (whitespace, auto-generated boilerplate sections like
  `[egg_info] tag_build =`). Verify the *substance* (dependencies, entry
  points, scripts) is unchanged before dismissing, but formatting-only
  diffs are not findings.
- **Legitimate use of "suspicious" patterns that exist identically in both
  trees** — e.g., a language-installer tool legitimately using
  `urllib.request.urlopen` to fetch a toolchain, documented and present in
  both published and GitHub versions. Only flag patterns that are NEW in
  the published artifact relative to GitHub, not patterns that exist
  identically in both.

### Step 6: Report findings

For a clean result, state plainly that no evidence of tampering was found
and summarize what was checked (don't just say "looks fine" — list the
categories checked, per Step 4, so the absence of findings is itself
informative).

For actual findings, report:
- Exact file(s)/line(s) that differ
- The published-only content, quoted or summarized
- Why it's suspicious (which category from Step 4 it falls into)
- Severity/plausibility judgment — a stray debug print is not the same as
  a hidden network call reading `.ssh/id_rsa`

**Do not conclude a package is compromised from a single suspicious-looking
line without checking whether it's benign per Step 5.** False positives
here are costly — they can trigger unnecessary panic or unfounded public
accusations against a maintainer. When uncertain, present the finding with
appropriate hedging ("this is unusual and worth asking the maintainer
about" vs. "this is definitely malicious") rather than asserting
compromise.

If genuine tampering is found, this is a serious finding — treat it with
the same responsible-disclosure care as any other vulnerability: don't
publish details publicly before the maintainer/registry has a chance to
respond, and consider that the maintainer's account itself may be
compromised (meaning outreach to their listed email/GitHub may not be a
safe channel — registry security teams, e.g. PyPI's security contact or
npm's security team, are a better first stop for confirmed compromises).
