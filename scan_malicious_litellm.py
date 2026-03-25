#!/usr/bin/env python3
"""
Scan local Python environments for malicious LiteLLM versions.

An environment is considered compromised when litellm is installed at
version 1.82.7 or 1.82.8.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable

MALICIOUS_VERSIONS = {"1.82.7", "1.82.8"}
DEFAULT_TIMEOUT = 15
COMMON_SYSTEM_PYTHONS = (
    "/usr/bin/python3",
    "/usr/local/bin/python3",
    "/opt/homebrew/bin/python3",
    "/opt/homebrew/anaconda3/bin/python",
    "/opt/homebrew/anaconda3/bin/python3",
)
SKIP_DIR_NAMES = {
    ".Trash",
    ".git",
    ".hg",
    ".svn",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".nox",
    "node_modules",
    "__pycache__",
    "Library",
    "Applications",
    "Movies",
    "Music",
    "Pictures",
}
DEFAULT_PROJECT_ROOTS = (
    "Workspace",
    "Projects",
    "Code",
    "src",
    "work",
)
DEFAULT_ENV_ROOTS = (
    ".virtualenvs",
    ".venvs",
    "venv",
    "virtualenvs",
)


@dataclass
class EnvironmentCandidate:
    kind: str
    name: str
    root: Path
    python: Path


@dataclass
class EnvironmentResult:
    kind: str
    name: str
    root: str
    python: str
    litellm_version: str | None
    compromised: bool
    malicious_version_detected: bool
    local_pth_files: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


@dataclass
class SearchRoot:
    path: Path
    max_depth: int | None = None


def run_command(args: list[str], timeout: int = DEFAULT_TIMEOUT) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def real_path(path: Path) -> Path:
    try:
        return path.resolve()
    except OSError:
        return path


def is_executable_file(path: Path) -> bool:
    return path.is_file() and os.access(path, os.X_OK)


def looks_like_python_interpreter(path: Path) -> bool:
    return bool(re.fullmatch(r"python(?:\d+(?:\.\d+)?)?", path.name))


def unique_candidates(candidates: Iterable[EnvironmentCandidate]) -> list[EnvironmentCandidate]:
    deduped: dict[tuple[str, str], EnvironmentCandidate] = {}
    for item in candidates:
        key = (str(real_path(item.python)), str(real_path(item.root)))
        deduped[key] = item
    return sorted(deduped.values(), key=lambda item: (item.kind, item.name, str(item.root)))


def safe_home() -> Path:
    return Path.home().expanduser()


def discover_conda_envs() -> list[EnvironmentCandidate]:
    candidates: list[EnvironmentCandidate] = []
    conda_exe = shutil.which("conda")
    env_roots: set[Path] = set()

    if conda_exe:
        try:
            completed = run_command([conda_exe, "info", "--json"], timeout=20)
            if completed.returncode == 0 and completed.stdout:
                payload = json.loads(completed.stdout)
                for env_path in payload.get("envs", []):
                    env_roots.add(Path(env_path).expanduser())
                for extra in ("default_prefix", "root_prefix"):
                    value = payload.get(extra)
                    if value:
                        env_roots.add(Path(value).expanduser())
        except (subprocess.SubprocessError, json.JSONDecodeError):
            pass

    common_roots = [
        safe_home() / "miniconda3",
        safe_home() / "anaconda3",
        Path("/opt/homebrew/anaconda3"),
        Path("/opt/homebrew/miniconda3"),
    ]
    for root in common_roots:
        if root.exists():
            env_roots.add(root)
            envs_dir = root / "envs"
            if envs_dir.is_dir():
                for child in envs_dir.iterdir():
                    if child.is_dir():
                        env_roots.add(child)

    for root in sorted(env_roots):
        python = root / "bin" / "python"
        if is_executable_file(python):
            candidates.append(
                EnvironmentCandidate(
                    kind="conda",
                    name=root.name,
                    root=root,
                    python=python,
                )
            )
    return candidates


def discover_path_pythons() -> list[EnvironmentCandidate]:
    candidates: list[EnvironmentCandidate] = []
    python_paths: set[Path] = set()

    names = ("python", "python3", "python3.12", "python3.11", "python3.10", "python3.9", "python3.8")
    for name in names:
        found = shutil.which(name)
        if found:
            python_paths.add(Path(found))

    path_dirs = [Path(part) for part in os.environ.get("PATH", "").split(os.pathsep) if part]
    for directory in path_dirs:
        if not directory.is_dir():
            continue
        try:
            for child in directory.iterdir():
                if looks_like_python_interpreter(child) and is_executable_file(child):
                    python_paths.add(child)
        except OSError:
            continue

    for raw in COMMON_SYSTEM_PYTHONS:
        path = Path(raw)
        if looks_like_python_interpreter(path) and is_executable_file(path):
            python_paths.add(path)

    pyenv_root = safe_home() / ".pyenv" / "versions"
    if pyenv_root.is_dir():
        for child in pyenv_root.iterdir():
            python = child / "bin" / "python"
            if looks_like_python_interpreter(python) and is_executable_file(python):
                python_paths.add(python)

    asdf_root = safe_home() / ".asdf" / "installs" / "python"
    if asdf_root.is_dir():
        for child in asdf_root.iterdir():
            python = child / "bin" / "python"
            if looks_like_python_interpreter(python) and is_executable_file(python):
                python_paths.add(python)

    for python in sorted(python_paths):
        root = python.parent.parent
        if not root.exists():
            continue
        candidates.append(
            EnvironmentCandidate(
                kind="system",
                name=python.name,
                root=root,
                python=python,
            )
        )
    return candidates


def iter_search_roots(extra_roots: list[str]) -> list[SearchRoot]:
    home = safe_home()
    roots = [SearchRoot(Path.cwd(), max_depth=6)]

    for name in DEFAULT_PROJECT_ROOTS:
        roots.append(SearchRoot(home / name, max_depth=5))

    for name in DEFAULT_ENV_ROOTS:
        roots.append(SearchRoot(home / name, max_depth=4))

    roots.extend(
        [
            SearchRoot(home / ".local" / "share" / "virtualenvs", max_depth=4),
            SearchRoot(home / ".cache" / "pypoetry" / "virtualenvs", max_depth=4),
            SearchRoot(home / "Library" / "Caches" / "pypoetry" / "virtualenvs", max_depth=4),
        ]
    )

    workon_home = os.environ.get("WORKON_HOME")
    if workon_home:
        roots.append(SearchRoot(Path(workon_home).expanduser(), max_depth=4))

    roots.extend(SearchRoot(Path(item).expanduser(), max_depth=None) for item in extra_roots)

    deduped: list[SearchRoot] = []
    seen: set[str] = set()
    for root in roots:
        resolved = str(real_path(root.path))
        if resolved not in seen and root.path.exists():
            seen.add(resolved)
            deduped.append(root)
    return deduped


def discover_venvs(search_roots: list[SearchRoot]) -> list[EnvironmentCandidate]:
    candidates: list[EnvironmentCandidate] = []
    seen_roots: set[str] = set()

    for root in search_roots:
        for current_root, dirnames, filenames in os.walk(root.path, topdown=True):
            current = Path(current_root)
            try:
                depth = len(current.relative_to(root.path).parts)
            except ValueError:
                depth = 0

            dirnames[:] = [
                name
                for name in dirnames
                if name not in SKIP_DIR_NAMES
                and not (name.startswith(".") and name not in {".venv", ".virtualenvs"})
            ]

            if root.max_depth is not None and depth >= root.max_depth:
                dirnames[:] = []

            if "pyvenv.cfg" not in filenames:
                continue

            env_root = current
            python = env_root / "bin" / "python"
            if not is_executable_file(python):
                continue

            resolved_root = str(real_path(env_root))
            if resolved_root in seen_roots:
                continue
            seen_roots.add(resolved_root)
            candidates.append(
                EnvironmentCandidate(
                    kind="venv",
                    name=env_root.name,
                    root=env_root,
                    python=python,
                )
            )

            # Do not recurse further inside a matched virtual environment.
            dirnames[:] = []

    return candidates


def discover_all_environments(extra_roots: list[str]) -> list[EnvironmentCandidate]:
    candidates: list[EnvironmentCandidate] = []
    candidates.extend(discover_path_pythons())
    candidates.extend(discover_conda_envs())
    candidates.extend(discover_venvs(iter_search_roots(extra_roots)))
    return unique_candidates(candidates)


def get_litellm_version(python: Path) -> tuple[str | None, list[str]]:
    code = """
import json
import importlib.metadata as m

result = {"version": None, "errors": []}
try:
    result["version"] = m.version("litellm")
except m.PackageNotFoundError:
    pass
except Exception as exc:
    result["errors"].append(str(exc))

print(json.dumps(result))
""".strip()

    errors: list[str] = []
    try:
        completed = run_command([str(python), "-c", code])
    except (subprocess.SubprocessError, OSError) as exc:
        return None, [f"version check failed: {exc}"]

    if completed.returncode != 0:
        stderr = completed.stderr.strip()
        errors.append(stderr or f"version check exited with {completed.returncode}")
        return None, errors

    try:
        payload = json.loads(completed.stdout)
        return payload.get("version"), payload.get("errors", [])
    except json.JSONDecodeError:
        return None, ["version check returned invalid JSON"]


def find_local_pth_files(python: Path) -> list[str]:
    code = """
import json
import site
import sysconfig

paths = set()
for getter in (lambda: site.getsitepackages(), lambda: [site.getusersitepackages()]):
    try:
        for item in getter():
            if item:
                paths.add(item)
    except Exception:
        pass

for key in ("purelib", "platlib"):
    value = sysconfig.get_paths().get(key)
    if value:
        paths.add(value)

print(json.dumps(sorted(paths)))
""".strip()

    try:
        completed = run_command([str(python), "-c", code])
        if completed.returncode != 0:
            return []
        directories = json.loads(completed.stdout)
    except (subprocess.SubprocessError, json.JSONDecodeError, OSError):
        return []

    found: list[str] = []
    for item in directories:
        site_dir = Path(item)
        target = site_dir / "litellm_init.pth"
        if target.exists():
            found.append(str(target))
    return sorted(set(found))


def scan_environment(env: EnvironmentCandidate) -> EnvironmentResult:
    version, version_errors = get_litellm_version(env.python)
    errors = list(version_errors)
    local_pth_files = find_local_pth_files(env.python)
    malicious_version_detected = version in MALICIOUS_VERSIONS
    compromised = malicious_version_detected or bool(local_pth_files)

    return EnvironmentResult(
        kind=env.kind,
        name=env.name,
        root=str(env.root),
        python=str(env.python),
        litellm_version=version,
        compromised=compromised,
        malicious_version_detected=malicious_version_detected,
        local_pth_files=local_pth_files,
        errors=errors,
    )


def find_uv_cache_hits() -> list[str]:
    hits: list[str] = []
    cache_roots: list[Path] = []

    uv_cache_dir = os.environ.get("UV_CACHE_DIR")
    if uv_cache_dir:
        cache_roots.append(Path(uv_cache_dir).expanduser())

    cache_roots.extend(
        [
            safe_home() / ".cache" / "uv",
            safe_home() / "Library" / "Caches" / "uv",
        ]
    )

    seen: set[str] = set()
    for uv_cache in cache_roots:
        resolved = str(real_path(uv_cache))
        if resolved in seen or not uv_cache.is_dir():
            continue
        seen.add(resolved)
        for current_root, dirnames, filenames in os.walk(uv_cache):
            dirnames[:] = [name for name in dirnames if name != "__pycache__"]
            if "litellm_init.pth" in filenames:
                hits.append(str(Path(current_root) / "litellm_init.pth"))
    return sorted(set(hits))


def render_text_report(results: list[EnvironmentResult], uv_hits: list[str]) -> str:
    compromised = [item for item in results if item.compromised]
    malicious_version = [item for item in results if item.malicious_version_detected]
    residual_pth = [item for item in results if item.local_pth_files]
    installed = [item for item in results if item.litellm_version]
    clean = [item for item in installed if not item.compromised]
    overall_compromised = bool(compromised or uv_hits)

    lines = [
        f"Environments scanned: {len(results)}",
        f"Environments with litellm installed: {len(installed)}",
        f"Malicious version hits: {len(malicious_version)}",
        f"Environments with leftover litellm_init.pth: {len(residual_pth)}",
        f"uv cache hits for litellm_init.pth: {len(uv_hits)}",
        "",
    ]

    if overall_compromised:
        lines.append("Verdict: compromised")
    else:
        lines.append("Verdict: no 1.82.7 / 1.82.8 detected")
    lines.append("")

    if compromised:
        lines.append("Compromised environments:")
        for item in compromised:
            reasons: list[str] = []
            if item.malicious_version_detected:
                reasons.append(f"malicious version {item.litellm_version}")
            if item.local_pth_files:
                reasons.append("litellm_init.pth present")
            lines.extend(
                [
                    f"- [{item.kind}] {item.name}",
                    f"  reason: {', '.join(reasons)}",
                    f"  python: {item.python}",
                    f"  root: {item.root}",
                    f"  litellm: {item.litellm_version}",
                ]
            )
            if item.local_pth_files:
                lines.append(f"  local pth: {', '.join(item.local_pth_files)}")
            if item.errors:
                lines.append(f"  errors: {' | '.join(item.errors)}")
        lines.append("")

    if clean:
        lines.append("Installed but not on a malicious version:")
        for item in clean:
            lines.append(f"- [{item.kind}] {item.name}: {item.litellm_version} ({item.python})")
        lines.append("")

    if uv_hits:
        lines.append("litellm_init.pth found in uv cache:")
        for hit in uv_hits:
            lines.append(f"- {hit}")
        lines.append("")

    no_package = [item for item in results if not item.litellm_version]
    if no_package:
        lines.append("Environments without litellm installed:")
        for item in no_package:
            lines.append(f"- [{item.kind}] {item.name}: {item.python}")
        lines.append("")

    errored = [item for item in results if item.errors]
    if errored:
        lines.append("Additional errors:")
        for item in errored:
            lines.append(f"- {item.python}: {' | '.join(item.errors)}")

    return "\n".join(lines).strip() + "\n"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Scan Python environments for malicious LiteLLM versions.")
    parser.add_argument(
        "--root",
        action="append",
        default=[],
        help="Extra directories to search for virtual environments.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print machine-readable JSON output.",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    environments = discover_all_environments(args.root)
    results = [scan_environment(env) for env in environments]
    uv_hits = find_uv_cache_hits()

    payload = {
        "malicious_versions": sorted(MALICIOUS_VERSIONS),
        "compromised": any(item.compromised for item in results) or bool(uv_hits),
        "uv_cache_hits": uv_hits,
        "environments": [asdict(item) for item in results],
    }

    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(render_text_report(results, uv_hits), end="")

    return 1 if payload["compromised"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
