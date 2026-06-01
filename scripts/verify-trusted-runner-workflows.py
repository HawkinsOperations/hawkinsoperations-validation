"""Verify self-hosted runners are not reachable from public PR workflows."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import yaml


CANONICAL_REPOS = (
    ".github",
    "hawkinsoperations-detections",
    "hawkinsoperations-validation",
    "hawkinsoperations-platform",
    "hawkinsoperations-proof",
    "hawkinsoperations-website",
)
PUBLIC_PR_TRIGGERS = {"pull_request", "pull_request_target"}


def workflow_trigger_keys(workflow: dict[str, Any]) -> set[str]:
    on_value = workflow.get("on", workflow.get(True))
    if isinstance(on_value, str):
        return {on_value}
    if isinstance(on_value, list):
        return {str(item) for item in on_value}
    if isinstance(on_value, dict):
        return {str(key) for key in on_value}
    return set()


def runs_on_values(runs_on: Any) -> list[str]:
    if isinstance(runs_on, str):
        return [runs_on]
    if isinstance(runs_on, list):
        return [str(item) for item in runs_on]
    return []


def is_self_hosted(runs_on: Any) -> bool:
    return any(value == "self-hosted" for value in runs_on_values(runs_on))


def load_workflow(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        parsed = yaml.safe_load(handle) or {}
    if not isinstance(parsed, dict):
        return {}
    return parsed


def workflow_files(repo_path: Path) -> list[Path]:
    workflow_dir = repo_path / ".github" / "workflows"
    if not workflow_dir.exists():
        return []
    return sorted(
        path
        for pattern in ("*.yml", "*.yaml")
        for path in workflow_dir.glob(pattern)
        if path.is_file()
    )


def scan_repo(repo_name: str, repo_path: Path) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for workflow_path in workflow_files(repo_path):
        workflow = load_workflow(workflow_path)
        triggers = workflow_trigger_keys(workflow)
        public_triggers = sorted(triggers & PUBLIC_PR_TRIGGERS)
        if not public_triggers:
            continue

        jobs = workflow.get("jobs", {})
        if not isinstance(jobs, dict):
            continue

        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                continue
            runs_on = job.get("runs-on")
            if not is_self_hosted(runs_on):
                continue
            findings.append(
                {
                    "repo": repo_name,
                    "workflow_path": str(workflow_path),
                    "job_name": str(job_name),
                    "trigger": ",".join(public_triggers),
                    "runs_on": json.dumps(runs_on),
                }
            )
    return findings


def scan_canonical_repos(org_root: Path) -> tuple[list[dict[str, str]], list[str]]:
    findings: list[dict[str, str]] = []
    missing: list[str] = []
    for repo_name in CANONICAL_REPOS:
        repo_path = org_root / repo_name
        if not repo_path.exists():
            missing.append(str(repo_path))
            continue
        findings.extend(scan_repo(repo_name, repo_path))
    return findings, missing


def default_org_root() -> Path:
    return Path(__file__).resolve().parents[2]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify public PR workflows do not run on self-hosted runners."
    )
    parser.add_argument(
        "--org-root",
        type=Path,
        default=default_org_root(),
        help="Path containing the six canonical HawkinsOperations repositories.",
    )
    parser.add_argument(
        "--allow-missing",
        action="store_true",
        help="Do not fail if one or more canonical repositories are absent.",
    )
    args = parser.parse_args()

    findings, missing = scan_canonical_repos(args.org_root)
    if missing and not args.allow_missing:
        print("CANONICAL_REPO_SCAN=FAIL")
        for repo_path in missing:
            print(f"missing_repo={repo_path}")
        return 1

    if findings:
        print("PUBLIC_PR_SELF_HOSTED_EXPOSURE=FAIL")
        for finding in findings:
            print(
                "exposure="
                f"repo={finding['repo']};"
                f"workflow={finding['workflow_path']};"
                f"job={finding['job_name']};"
                f"trigger={finding['trigger']};"
                f"runs_on={finding['runs_on']}"
            )
        return 1

    print("PUBLIC_PR_SELF_HOSTED_EXPOSURE=PASS")
    print(f"canonical_repos_scanned={len(CANONICAL_REPOS) - len(missing)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
