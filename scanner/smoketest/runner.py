import time

import requests

DEFAULT_TARGETS = ["/"]


class SmokeCheck:
    def __init__(self, path: str, expected_status: int | None, status_code: int | None, latency_ms: float, error: str = ""):
        self.path = path
        self.expected_status = expected_status
        self.status_code = status_code
        self.latency_ms = latency_ms
        self.error = error

    @property
    def ok(self) -> bool:
        if self.error:
            return False
        if self.expected_status is not None:
            return self.status_code == self.expected_status
        return self.status_code is not None and self.status_code < 500

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "expected_status": self.expected_status,
            "status_code": self.status_code,
            "latency_ms": round(self.latency_ms, 1),
            "error": self.error,
            "ok": self.ok,
        }


class SmokeTestResult:
    def __init__(self, base_url: str, checks: list[SmokeCheck]):
        self.base_url = base_url
        self.checks = checks

    @property
    def passed(self) -> bool:
        return bool(self.checks) and all(c.ok for c in self.checks)

    @property
    def passed_count(self) -> int:
        return sum(1 for c in self.checks if c.ok)

    def to_dict(self) -> dict:
        return {
            "base_url": self.base_url,
            "passed": self.passed,
            "passed_count": self.passed_count,
            "total_count": len(self.checks),
            "checks": [c.to_dict() for c in self.checks],
        }


def parse_smoke_targets(raw_text: str) -> list[tuple[str, int | None]]:
    """Her satir 'path' ya da 'path beklenen_status' formatinda. Bos ise varsayilan: ['/'].

    Beklenen status verilmezse basari kosulu 'yanit geldi ve 5xx degil' olur -- yani her
    path'in tam olarak hangi kodu donmesi gerektigini bilmene gerek yok, sadece cokmedigini
    dogrulamak istiyorsan bos birakabilirsin."""
    targets: list[tuple[str, int | None]] = []
    for line in (raw_text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        path = parts[0]
        if not path.startswith("/"):
            path = "/" + path
        expected = None
        if len(parts) > 1:
            try:
                expected = int(parts[1])
            except ValueError:
                expected = None
        targets.append((path, expected))
    return targets or [(p, None) for p in DEFAULT_TARGETS]


def run_smoke_test(
    base_url: str,
    targets: list[tuple[str, int | None]] = None,
    headers: dict = None,
    timeout: float = 10.0,
    on_progress=None,
) -> SmokeTestResult:
    """Hedefin kritik path'lerine tek tek, sirayla, hafif bir 'ayakta mi' kontrolu yapar --
    tam guvenlik taramasindan (dakikalar) once saniyeler icinde 'bu hedefe hic tarama
    baslatmaya deger mi' sorusuna cevap vermek icindir. Bulgu/verdict sistemine dahil
    edilmez, ayri ve bagimsiz bir gecti/kaldi sonucudur."""
    progress = on_progress or (lambda msg: None)
    targets = targets or [(p, None) for p in DEFAULT_TARGETS]
    base = base_url.rstrip("/")

    progress(f"Smoke test başlıyor: {base} — {len(targets)} path.")
    checks: list[SmokeCheck] = []
    session = requests.Session()
    try:
        for path, expected in targets:
            url = base + path
            start = time.monotonic()
            try:
                resp = session.get(url, headers=headers, timeout=timeout)
                elapsed_ms = (time.monotonic() - start) * 1000
                check = SmokeCheck(path=path, expected_status=expected, status_code=resp.status_code, latency_ms=elapsed_ms)
            except Exception as exc:
                elapsed_ms = (time.monotonic() - start) * 1000
                check = SmokeCheck(path=path, expected_status=expected, status_code=None, latency_ms=elapsed_ms, error=type(exc).__name__)
            checks.append(check)
            progress(f"  {'OK' if check.ok else 'FAIL'}  {path}  ({check.status_code or check.error})")
    finally:
        session.close()

    result = SmokeTestResult(base_url=base_url, checks=checks)
    progress(f"Smoke test bitti: {result.passed_count}/{len(checks)} geçti.")
    return result
