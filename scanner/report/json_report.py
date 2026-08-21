import json
from datetime import datetime

from core.models import Finding, Verdict
from loadtest.runner import LoadTestResult
from smoketest.runner import SmokeTestResult


def build_json_report(
    findings: list[Finding], verdict: Verdict, target: str, load_test_result: LoadTestResult = None,
    smoke_test_result: SmokeTestResult = None,
) -> dict:
    return {
        "target": target,
        "generated_at": datetime.now().isoformat(),
        "verdict": verdict.to_dict(),
        "finding_count": len(findings),
        "findings": [f.to_dict() for f in findings],
        "load_test": load_test_result.to_dict() if load_test_result else None,
        "smoke_test": smoke_test_result.to_dict() if smoke_test_result else None,
    }


def write_json_report(
    path: str, findings: list[Finding], verdict: Verdict, target: str, load_test_result: LoadTestResult = None,
    smoke_test_result: SmokeTestResult = None,
) -> None:
    data = build_json_report(
        findings, verdict, target, load_test_result=load_test_result, smoke_test_result=smoke_test_result
    )
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
