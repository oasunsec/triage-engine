"""Prepare benchmark EVTX inputs referenced by a corpus manifest."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Iterable, List


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "config" / "benchmark" / "corpus.json"
DEFAULT_SOURCE_REPO = "https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git"
DEFAULT_CACHE_REPO = ROOT / "repo_cache" / "sbousseaden_EVTX-ATTACK-SAMPLES"


def _resolve_path(value: str, *, manifest_dir: Path) -> Path:
    candidate = Path(value)
    if candidate.is_absolute():
        return candidate.resolve()

    root_candidate = (ROOT / candidate).resolve()
    manifest_candidate = (manifest_dir / candidate).resolve()
    if root_candidate.exists():
        return root_candidate
    if manifest_candidate.exists():
        return manifest_candidate
    return root_candidate


def _run(command: List[str], *, cwd: Path | None = None) -> None:
    result = subprocess.run(command, cwd=str(cwd) if cwd else None, capture_output=True, text=True)
    if result.returncode != 0:
        details = result.stderr.strip() or result.stdout.strip() or "unknown error"
        raise RuntimeError(f"Command failed ({' '.join(command)}): {details}")


def _load_manifest(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"Manifest must be a JSON object: {path}")
    return payload


def _manifest_sample_paths(manifest: dict, *, manifest_dir: Path) -> List[Path]:
    samples = manifest.get("samples")
    if not isinstance(samples, list):
        raise ValueError("Manifest missing samples list.")
    resolved: List[Path] = []
    for sample in samples:
        if not isinstance(sample, dict):
            continue
        path_value = sample.get("path")
        if not isinstance(path_value, str) or not path_value.strip():
            continue
        resolved.append(_resolve_path(path_value, manifest_dir=manifest_dir))
    return resolved


def _missing_paths(paths: Iterable[Path]) -> List[Path]:
    return [path for path in paths if not path.is_file()]


def _ensure_cache_repo(cache_repo: Path, *, source_repo: str) -> None:
    cache_repo.parent.mkdir(parents=True, exist_ok=True)
    if not cache_repo.exists():
        print(f"[prepare-benchmark] cloning source dataset into {cache_repo}")
        _run(
            [
                "git",
                "clone",
                "--filter=blob:none",
                "--no-checkout",
                "--depth",
                "1",
                source_repo,
                str(cache_repo),
            ]
        )
    elif not (cache_repo / ".git").is_dir():
        raise RuntimeError(f"Cache path exists but is not a git repository: {cache_repo}")


def _checkout_required_files(cache_repo: Path, required: List[Path]) -> None:
    relative_files = sorted({str(path.relative_to(cache_repo)).replace("\\", "/") for path in required})
    if not relative_files:
        return
    print(f"[prepare-benchmark] sparse checkout of {len(relative_files)} file(s)")
    _run(["git", "sparse-checkout", "init", "--no-cone"], cwd=cache_repo)
    _run(["git", "sparse-checkout", "set", *relative_files], cwd=cache_repo)
    _run(["git", "checkout"], cwd=cache_repo)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Prepare benchmark EVTX sample inputs referenced by manifest.")
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST), help="Path to benchmark manifest JSON.")
    parser.add_argument(
        "--source-repo",
        default=DEFAULT_SOURCE_REPO,
        help="Git repository URL used to fetch missing sbousseaden EVTX samples.",
    )
    parser.add_argument(
        "--cache-repo",
        default=str(DEFAULT_CACHE_REPO),
        help="Local path for sbousseaden EVTX repository cache.",
    )
    return parser


def main(argv: List[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    manifest_path = Path(args.manifest).resolve()
    cache_repo = Path(args.cache_repo).resolve()
    if not manifest_path.is_file():
        raise SystemExit(f"Manifest not found: {manifest_path}")

    manifest = _load_manifest(manifest_path)
    sample_paths = _manifest_sample_paths(manifest, manifest_dir=manifest_path.parent)
    if not sample_paths:
        print("[prepare-benchmark] no sample paths found; nothing to do")
        return 0

    missing = _missing_paths(sample_paths)
    if not missing:
        print("[prepare-benchmark] all sample files are already present")
        return 0

    managed_missing = [path for path in missing if path.is_relative_to(cache_repo)]
    unmanaged_missing = [path for path in missing if not path.is_relative_to(cache_repo)]
    if unmanaged_missing:
        missing_text = "\n".join(f"- {path}" for path in unmanaged_missing)
        raise SystemExit(
            "Missing sample paths are outside managed cache repo and cannot be auto-fetched:\n" + missing_text
        )

    _ensure_cache_repo(cache_repo, source_repo=args.source_repo)
    _checkout_required_files(cache_repo, managed_missing)

    remaining_missing = _missing_paths(sample_paths)
    if remaining_missing:
        missing_text = "\n".join(f"- {path}" for path in remaining_missing)
        raise SystemExit("Sample preparation incomplete. Missing files:\n" + missing_text)

    print(f"[prepare-benchmark] prepared {len(managed_missing)} missing file(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
