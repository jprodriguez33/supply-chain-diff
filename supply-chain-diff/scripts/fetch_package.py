#!/usr/bin/env python3
"""
Fetch package metadata and download the published artifact(s) for a
supply-chain-diff check.

Usage:
    python fetch_package.py <package-name> --ecosystem pypi
    python fetch_package.py <package-name> --ecosystem npm
    python fetch_package.py <package-name> --ecosystem pypi --version 1.2.3

For PyPI this downloads BOTH the sdist and a wheel when available, because
the wheel is what `pip install` actually runs on the victim's machine and
is where several real attacks (e.g. auto-executing `.pth` files) hide.
"""

import argparse
import os
import re
import shutil
import sys
import tarfile
import urllib.error
import urllib.request
import zipfile
import json
from pathlib import Path

UA = "supply-chain-diff-skill"
TIMEOUT = 60

# Hosts we know how to turn into a browsable/clonable source URL, in
# preference order. GitHub first because it's by far the most common, but
# GitLab/Bitbucket/Codeberg are handled too so they don't show as NOT FOUND.
KNOWN_HOSTS = ("github.com", "gitlab.com", "bitbucket.org", "codeberg.org")


# --------------------------------------------------------------------------
# networking
# --------------------------------------------------------------------------
def fetch_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as e:
        die(f"HTTP {e.code} fetching {url} — package/version may not exist.")
    except urllib.error.URLError as e:
        die(f"Network error fetching {url}: {e.reason}")
    except json.JSONDecodeError:
        die(f"Response from {url} was not valid JSON.")


def download(url, dest):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp, open(dest, "wb") as fh:
            shutil.copyfileobj(resp, fh)
    except (urllib.error.HTTPError, urllib.error.URLError) as e:
        die(f"Failed to download {url}: {e}")


def die(msg):
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


# --------------------------------------------------------------------------
# source-repo URL normalization
# --------------------------------------------------------------------------
def normalize_repo_url(url):
    """Turn the many ways a repo URL can be written into a plain
    https://host/owner/repo, or return None if it isn't a recognizable
    VCS URL. Handles npm's git+https / git+ssh / git:// / scp-like /
    `github:owner/repo` shorthand forms, not just bare https."""
    if not url or not isinstance(url, str):
        return None
    url = url.strip()

    # `github:owner/repo` shorthand (npm)
    m = re.match(r"^(github|gitlab|bitbucket):([^/]+/[^/#]+)$", url)
    if m:
        host = {"github": "github.com", "gitlab": "gitlab.com",
                "bitbucket": "bitbucket.org"}[m.group(1)]
        return f"https://{host}/{_strip_git(m.group(2))}"

    if url.startswith("git+"):
        url = url[4:]

    # scp-like: git@host:owner/repo(.git)
    m = re.match(r"^(?:ssh://)?[^@/]+@([^:/]+)[:/]([^/]+/[^/#?]+?)(?:\.git)?/?$", url)
    if m:
        return f"https://{m.group(1)}/{_strip_git(m.group(2))}"

    # git://, ssh://, http(s)://  host/owner/repo...
    m = re.match(r"^(?:git|ssh|https?)://([^/]+)/([^?#]+)", url)
    if m:
        host = m.group(1).split("@")[-1]  # drop any userinfo
        parts = [p for p in m.group(2).split("/") if p][:2]
        if len(parts) == 2:
            return f"https://{host}/{_strip_git('/'.join(parts))}"
    return None


def _strip_git(path):
    return re.sub(r"\.git$", "", path)


def guess_source_url(candidates):
    normalized = []
    for c in candidates:
        n = normalize_repo_url(c)
        if n and n not in normalized:
            normalized.append(n)
    for host in KNOWN_HOSTS:
        for n in normalized:
            if host in n:
                return n
    return normalized[0] if normalized else None


# --------------------------------------------------------------------------
# safe extraction (this tool processes potentially-malicious archives)
# --------------------------------------------------------------------------
def _within(base, target):
    base = os.path.realpath(base)
    target = os.path.realpath(target)
    return target == base or target.startswith(base + os.sep)


def safe_extract(archive_path, dest):
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    name = archive_path.name.lower()
    if name.endswith((".tar.gz", ".tgz", ".tar")):
        with tarfile.open(archive_path) as tar:
            try:
                tar.extractall(dest, filter="data")  # Python 3.12+
                return
            except TypeError:
                pass  # older Python without the filter arg; fall back below
            except tarfile.TarError as e:
                die(f"Refused to extract {archive_path.name}: {e}")
            for m in tar.getmembers():
                if not _within(dest, dest / m.name):
                    die(f"Unsafe path in archive: {m.name}")
            tar.extractall(dest)
    elif name.endswith((".whl", ".zip")):
        with zipfile.ZipFile(archive_path) as zf:
            for n in zf.namelist():
                if not _within(dest, dest / n):
                    die(f"Unsafe path in archive: {n}")
            zf.extractall(dest)
    else:
        die(f"Don't know how to extract {archive_path.name}")


def inner_dir(root):
    """If an archive extracted to a single top-level directory (sdist /
    npm `package/`), return it so the caller can diff at the right level."""
    entries = list(root.iterdir())
    dirs = [p for p in entries if p.is_dir()]
    if len(entries) == 1 and len(dirs) == 1:
        return dirs[0]
    return root


# --------------------------------------------------------------------------
# ecosystem handlers
# --------------------------------------------------------------------------
def handle_pypi(package_name, version, work_dir):
    if version:
        data = fetch_json(f"https://pypi.org/pypi/{package_name}/{version}/json")
    else:
        data = fetch_json(f"https://pypi.org/pypi/{package_name}/json")
    version = data["info"]["version"]

    candidates = [data["info"].get("home_page", ""),
                  *data["info"].get("project_urls", {}).values()]
    source_url = guess_source_url(candidates)

    sdist = next((f for f in data["urls"] if f["packagetype"] == "sdist"), None)
    wheels = [f for f in data["urls"] if f["packagetype"] == "bdist_wheel"]
    # prefer a universal py3 wheel; else first wheel
    wheel = next((w for w in wheels if w["filename"].endswith("-none-any.whl")),
                 wheels[0] if wheels else None)

    pkg_dir = work_dir / f"{package_name}-{version}"
    pkg_dir.mkdir(parents=True, exist_ok=True)
    extracted = {}

    if sdist:
        extracted["sdist"] = _fetch_and_extract(
            sdist["url"], pkg_dir / sdist["filename"], pkg_dir / "published-sdist")
    else:
        print("NOTE: no sdist published for this version.", file=sys.stderr)

    if wheel:
        if len(wheels) > 1:
            print(f"NOTE: {len(wheels)} wheels available; inspecting "
                  f"{wheel['filename']}. Others may target different platforms.",
                  file=sys.stderr)
        extracted["wheel"] = _fetch_and_extract(
            wheel["url"], pkg_dir / wheel["filename"], pkg_dir / "published-wheel")
    else:
        print("NOTE: no wheel published — but note the wheel is what pip "
              "actually installs and runs, so its absence is itself worth "
              "a glance.", file=sys.stderr)

    return version, source_url, extracted


def handle_npm(package_name, version, work_dir):
    data = fetch_json(f"https://registry.npmjs.org/{package_name}")
    version = version or data["dist-tags"]["latest"]
    if version not in data.get("versions", {}):
        die(f"version {version} not found for {package_name}.")
    version_data = data["versions"][version]

    repo = version_data.get("repository", {})
    repo_url = repo.get("url", "") if isinstance(repo, dict) else repo
    source_url = guess_source_url([repo_url, version_data.get("homepage", "")])

    tarball_url = version_data["dist"]["tarball"]
    pkg_dir = work_dir / f"{package_name}-{version}"
    pkg_dir.mkdir(parents=True, exist_ok=True)

    extracted = {"tarball": _fetch_and_extract(
        tarball_url, pkg_dir / f"{package_name.replace('/', '-')}-{version}.tgz",
        pkg_dir / "published")}
    return version, source_url, extracted


def _fetch_and_extract(url, archive_path, dest):
    print(f"Downloading {url}")
    download(url, archive_path)
    safe_extract(archive_path, dest)
    return inner_dir(dest)


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("package_name")
    parser.add_argument("--ecosystem", choices=["pypi", "npm"], required=True)
    parser.add_argument("--version", help="specific version to audit "
                        "(default: latest). Use this to investigate a "
                        "suspicious release that may not be latest.")
    parser.add_argument("--work-dir", default="./supply-chain-diff-work")
    args = parser.parse_args()

    work_dir = Path(args.work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)

    handler = {"pypi": handle_pypi, "npm": handle_npm}[args.ecosystem]
    version, source_url, extracted = handler(args.package_name, args.version, work_dir)

    print(f"\nPackage:    {args.package_name}")
    print(f"Version:    {version}")
    print(f"Source URL: {source_url or 'NOT FOUND — search / ask the user'}")
    print("Published artifact(s) extracted to:")
    for kind, path in extracted.items():
        print(f"  [{kind}] {path}")

    src = Path(args.work_dir) / f"{args.package_name}-{version}" / "source"
    print(f"\nNext:")
    print(f"  git clone {source_url or '<source-url>'} {src}")
    print(f"  # then diff the extracted inner dir(s) above against {src}/, e.g.:")
    for kind, path in extracted.items():
        print(f"  diff -rq {path}/ {src}/    # {kind}")


if __name__ == "__main__":
    main()
