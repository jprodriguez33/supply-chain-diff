# supply-chain-diff

A [Claude skill](https://docs.claude.com) that checks whether a published package
(PyPI, npm) matches its corresponding tagged source on a public repository
(GitHub, GitLab, Bitbucket, Codeberg) — to catch supply-chain tampering, where
malicious code is injected at publish time but never pushed to the visible git
history.

## What's here

```
supply-chain-diff/
  SKILL.md                     # the skill: when to use it, workflow, judgment calls
  scripts/
    fetch_package.py           # fetches registry metadata + downloads artifacts
supply-chain-diff.skill        # the same folder, zipped, ready to install as a skill
```

The unpacked `supply-chain-diff/` folder is committed so it's diffable in version
control. `supply-chain-diff.skill` is just that folder zipped, provided as a
convenient install artifact (rebuild it any time with
`cd supply-chain-diff && zip -r ../supply-chain-diff.skill . -x '*__pycache__*'`).

## Usage

The script fetches metadata and the published artifact(s); the actual diffing and
judgment is driven by `SKILL.md`.

```bash
# PyPI — downloads BOTH sdist and wheel (the wheel is what pip actually runs)
python supply-chain-diff/scripts/fetch_package.py <package> --ecosystem pypi

# npm
python supply-chain-diff/scripts/fetch_package.py <package> --ecosystem npm

# audit a specific (e.g. suspicious) version rather than latest
python supply-chain-diff/scripts/fetch_package.py <package> --ecosystem pypi --version 1.2.3
```

It prints the resolved version, the auto-detected source URL, where each artifact
was extracted, and ready-to-run `diff` commands. Only Python 3 standard library is
required.

## Safety

This tool downloads and extracts packages you may **suspect are malicious**. It is
designed to be safe for that:

- It **only downloads and diffs** — it never installs the package or executes its
  code. Do **not** `pip install` / `npm install` the package you're auditing.
- Archive extraction is hardened against path-traversal ("zip-slip") so a hostile
  archive can't write outside the work directory.

Even so, for anything you genuinely suspect is compromised, run the audit inside a
disposable sandbox (container or VM) as defense in depth.


## Example: auditing a known-good package (Flask)

Validating that the tool stays quiet on a package known to be clean. A
trustworthy result means the published artifact's source matches the tagged
git source exactly.

### 1. Fetch the published artifacts

    python supply-chain-diff/scripts/fetch_package.py flask --ecosystem pypi

    Package:    flask
    Version:    3.1.3
    Source URL: https://github.com/pallets/flask
    Artifacts:  sdist + flask-3.1.3-py3-none-any.whl

### 2. Clone the matching source tag

Flask tags releases with the bare version (no `v` prefix). Cloning the tag —
not the default branch — is essential; diffing against `main` would surface
every change made since the release and produce false noise.

    git clone --depth 1 --branch 3.1.3 https://github.com/pallets/flask <work>/source
    # resolves to commit 22d9247, the exact commit tag 3.1.3 points to

### 3. Diff the published package against the tagged source

The wheel flattens the package to `flask/`; the repo uses a `src/` layout, so
the meaningful comparison is package-dir to package-dir:

    # wheel
    diff -rq <work>/published-wheel/flask <work>/source/src/flask -x '__pycache__' -x '*.pyc'
    # sdist
    diff -rq <work>/published-sdist/flask-3.1.3/src/flask <work>/source/src/flask -x '__pycache__' -x '*.pyc'

### Result

Both diffs returned **no output** — every `.py` file in the published wheel
and sdist is identical to the tagged source. No source divergence; nothing
injected at publish time. Clean baseline confirmed.

> Note: a clean result depends on the release tag corresponding to the
> published commit (here, 3.1.3 → 22d9247). Diffing against the root
> directories instead of the aligned package dirs surfaces expected,
> benign differences — build-generated `*.dist-info/` metadata and files
> present in git but excluded from the wheel (tests, docs, packaging
> config). These are noise, not signal, and are why directory alignment
> matters.
