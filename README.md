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

## License

See [LICENSE](LICENSE). (The included template is MIT — replace the placeholder
year/name, or swap for whatever license you prefer.)
