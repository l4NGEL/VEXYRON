import statistics
import threading
import time

import requests

# Kaza ile hedefe asiri yuk vermeyi onlemek icin sert ust sinirlar (defense in depth --
# CLI/webapp de kendi tarafinda sinirlar, ama bu fonksiyon dogrudan cagirilsa bile korur).
MAX_CONCURRENCY = 200
MAX_DURATION_S = 120
MAX_STAGES = 5


def _percentile(sorted_values: list[float], pct: float) -> float:
    if not sorted_values:
        return 0.0
    k = (len(sorted_values) - 1) * (pct / 100)
    f = int(k)
    c = min(f + 1, len(sorted_values) - 1)
    if f == c:
        return sorted_values[f]
    return sorted_values[f] + (sorted_values[c] - sorted_values[f]) * (k - f)


class LoadTestResult:
    def __init__(
        self, target, method, concurrency, duration_s, status_codes, errors, latencies_ms, wall_time_s,
        aborted_reason=None, preflight_status=None, stages_ran=None,
        threshold_p95_ms=None, threshold_error_rate_pct=None,
    ):
        self.target = target
        self.method = method
        self.concurrency = concurrency
        self.duration_s = duration_s
        self.status_codes = status_codes
        self.errors = errors
        self.wall_time_s = wall_time_s
        self.aborted_reason = aborted_reason
        self.preflight_status = preflight_status
        self.stages_ran = stages_ran or []
        self.threshold_p95_ms = threshold_p95_ms
        self.threshold_error_rate_pct = threshold_error_rate_pct

        self.total_requests = sum(status_codes.values()) + sum(errors.values())
        self.successful = sum(c for code, c in status_codes.items() if 200 <= code < 400)
        self.failed = self.total_requests - self.successful
        self.rps = self.total_requests / wall_time_s if wall_time_s > 0 else 0.0

        if latencies_ms:
            sorted_lat = sorted(latencies_ms)
            self.latency_min_ms = sorted_lat[0]
            self.latency_avg_ms = statistics.mean(sorted_lat)
            self.latency_p50_ms = _percentile(sorted_lat, 50)
            self.latency_p95_ms = _percentile(sorted_lat, 95)
            self.latency_p99_ms = _percentile(sorted_lat, 99)
            self.latency_max_ms = sorted_lat[-1]
        else:
            self.latency_min_ms = self.latency_avg_ms = self.latency_p50_ms = 0.0
            self.latency_p95_ms = self.latency_p99_ms = self.latency_max_ms = 0.0

    @property
    def error_rate(self) -> float:
        return (self.failed / self.total_requests) if self.total_requests else 0.0

    @property
    def passed(self) -> bool | None:
        """Esik degeri verilmediyse None (degerlendirilmedi) doner. Aborted testler icin de
        None -- gecti/kaldi hukmu vermek icin gercek trafik gerekir."""
        if self.aborted_reason:
            return None
        if self.threshold_p95_ms is None and self.threshold_error_rate_pct is None:
            return None
        ok = True
        if self.threshold_p95_ms is not None:
            ok = ok and self.latency_p95_ms <= self.threshold_p95_ms
        if self.threshold_error_rate_pct is not None:
            ok = ok and (self.error_rate * 100) <= self.threshold_error_rate_pct
        return ok

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "method": self.method,
            "concurrency": self.concurrency,
            "requested_duration_s": self.duration_s,
            "actual_duration_s": round(self.wall_time_s, 2),
            "total_requests": self.total_requests,
            "successful": self.successful,
            "failed": self.failed,
            "error_rate_pct": round(self.error_rate * 100, 2),
            "requests_per_sec": round(self.rps, 2),
            "status_codes": {str(k): v for k, v in sorted(self.status_codes.items())},
            "errors": self.errors,
            "latency_ms": {
                "min": round(self.latency_min_ms, 1),
                "avg": round(self.latency_avg_ms, 1),
                "p50": round(self.latency_p50_ms, 1),
                "p95": round(self.latency_p95_ms, 1),
                "p99": round(self.latency_p99_ms, 1),
                "max": round(self.latency_max_ms, 1),
            },
            "aborted_reason": self.aborted_reason,
            "preflight_status": self.preflight_status,
            "stages_ran": self.stages_ran,
            "threshold_p95_ms": self.threshold_p95_ms,
            "threshold_error_rate_pct": self.threshold_error_rate_pct,
            "passed": self.passed,
        }


def _run_workers(url, method, concurrency, duration_s, headers, body, status_codes, errors, latencies_ms, lock):
    """Bir stage/asama boyunca `concurrency` kadar thread'i `duration_s` saniye calistirip
    sonuclari (paylasilan) status_codes/errors/latencies_ms icine biriktirir. Coklu stage'ler
    bu fonksiyonu ardarda cagirip aynı accumulator'lari paylasarak birikimli sonuc uretir."""
    stop_at = time.monotonic() + duration_s

    def worker():
        session = requests.Session()
        try:
            while time.monotonic() < stop_at:
                start = time.monotonic()
                try:
                    resp = session.request(method, url, headers=headers, data=body, timeout=10)
                    elapsed_ms = (time.monotonic() - start) * 1000
                    with lock:
                        latencies_ms.append(elapsed_ms)
                        status_codes[resp.status_code] = status_codes.get(resp.status_code, 0) + 1
                except Exception as exc:
                    elapsed_ms = (time.monotonic() - start) * 1000
                    with lock:
                        latencies_ms.append(elapsed_ms)
                        name = type(exc).__name__
                        errors[name] = errors.get(name, 0) + 1
        finally:
            session.close()

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(concurrency)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=duration_s + 30)


def _normalize_stages(stages) -> list[tuple[int, float]]:
    normalized = []
    for item in stages[:MAX_STAGES]:
        if isinstance(item, dict):
            c, d = item.get("concurrency"), item.get("duration_s")
        else:
            c, d = item
        c = max(1, min(int(c), MAX_CONCURRENCY))
        d = max(1.0, min(float(d), MAX_DURATION_S))
        normalized.append((c, d))
    return normalized


def run_load_test(
    url: str,
    method: str = "GET",
    concurrency: int = 10,
    duration_s: float = 15.0,
    stages: list = None,
    headers: dict = None,
    body=None,
    threshold_p95_ms: float = None,
    threshold_error_rate_pct: float = None,
    on_progress=None,
) -> LoadTestResult:
    """Hedefe belirtilen sure boyunca `concurrency` kadar eszamanli worker ile surekli
    istek gonderip response time (p50/p95/p99) ve hata oranini olcer.

    `stages` verilirse (ör. [(10, 10), (50, 20), (10, 10)] -- eszamanli, saniye ciftleri)
    `concurrency`/`duration_s` yok sayilir; asamalar sirayla calisip TEK bir birikimli
    sonuca (k6'daki "stages" ramp-up/sustain/ramp-down mantigina benzer, ama adim adim)
    toplanir. En fazla MAX_STAGES asama calisir, her biri kendi icinde
    MAX_CONCURRENCY/MAX_DURATION_S ile kirpilir.

    threshold_p95_ms / threshold_error_rate_pct verilirse sonucun .passed ozelligi
    gecti/kaldi hukmu doner (verilmezse None -- degerlendirilmemis).

    GUVENLIK: Bu fonksiyon safety.assert_authorized kontrolunden GECMEZ -- cagiran taraf
    (core.orchestrator) bunu load-test'ten ONCE kendisi cagirmis olmalidir, tipki diger
    tarama modullerinde oldugu gibi. Kaza ile asiri yuk vermeyi onlemek icin concurrency
    ve duration MAX_CONCURRENCY/MAX_DURATION_S ile kirpilir; her worker kendi
    requests.Session'ini kullanir (Session nesneleri thread'ler arasi paylasima uygun
    tasarlanmamistir)."""
    progress = on_progress or (lambda msg: None)

    if stages:
        stage_list = _normalize_stages(stages)
    else:
        stage_list = [(max(1, min(int(concurrency), MAX_CONCURRENCY)), max(1.0, min(float(duration_s), MAX_DURATION_S)))]

    peak_concurrency = max(c for c, _ in stage_list)
    total_planned_duration = sum(d for _, d in stage_list)

    # Once tek istekle hedefi dogrula: path 404 donuyorsa tum yuku bindirip "%100 hata"
    # raporlamak yaniltici olur -- bu bir performans basarisizligi degil, yanlis path'tir.
    # Erkenden durup nedenini soyleriz, boylece var olmayan bir endpoint'e bosuna yuk binmez.
    progress(f"Hedef doğrulanıyor: {method} {url}")
    preflight_status = None
    preflight_error = None
    try:
        probe = requests.request(method, url, headers=headers, data=body, timeout=10)
        preflight_status = probe.status_code
    except Exception as exc:
        preflight_error = type(exc).__name__

    aborted_reason = None
    if preflight_status == 404:
        aborted_reason = (
            f"Hedef path 404 dönüyor ({method} {url}) — yük testi başlatılmadı. Path'i kontrol edip "
            "tekrar deneyin; aksi halde tüm istekler 404 olur ve sonuç gerçek bir performans ölçümü "
            "değil, yalnızca 'yanlış path' anlamına gelir."
        )
    elif preflight_error:
        aborted_reason = (
            f"Hedefe ön-kontrol isteği başarısız oldu ({preflight_error}) — yük testi başlatılmadı. "
            "URL'i ve hedefin ayakta olduğunu kontrol edin."
        )

    if aborted_reason:
        progress(f"Yük testi durduruldu: {aborted_reason}")
        return LoadTestResult(
            target=url,
            method=method,
            concurrency=peak_concurrency,
            duration_s=total_planned_duration,
            status_codes={},
            errors={},
            latencies_ms=[],
            wall_time_s=0.0,
            aborted_reason=aborted_reason,
            preflight_status=preflight_status,
            threshold_p95_ms=threshold_p95_ms,
            threshold_error_rate_pct=threshold_error_rate_pct,
        )

    if len(stage_list) > 1:
        plan = " → ".join(f"{c}w/{d:.0f}s" for c, d in stage_list)
        progress(f"Yük testi başlıyor (aşamalı): {method} {url} — {plan}.")
    else:
        c0, d0 = stage_list[0]
        progress(f"Yük testi başlıyor: {method} {url} — {c0} eşzamanlı worker, {d0:.0f} saniye.")

    status_codes: dict[int, int] = {}
    errors: dict[str, int] = {}
    latencies_ms: list[float] = []
    lock = threading.Lock()

    wall_start = time.monotonic()
    for i, (stage_concurrency, stage_duration) in enumerate(stage_list, start=1):
        if len(stage_list) > 1:
            progress(f"  Aşama {i}/{len(stage_list)}: {stage_concurrency} worker, {stage_duration:.0f} saniye.")
        _run_workers(url, method, stage_concurrency, stage_duration, headers, body, status_codes, errors, latencies_ms, lock)
    wall_time_s = time.monotonic() - wall_start

    result = LoadTestResult(
        target=url,
        method=method,
        concurrency=peak_concurrency,
        duration_s=total_planned_duration,
        status_codes=status_codes,
        errors=errors,
        latencies_ms=latencies_ms,
        wall_time_s=wall_time_s,
        preflight_status=preflight_status,
        stages_ran=[{"concurrency": c, "duration_s": d} for c, d in stage_list],
        threshold_p95_ms=threshold_p95_ms,
        threshold_error_rate_pct=threshold_error_rate_pct,
    )
    progress(
        f"Yük testi bitti: {result.total_requests} istek, {result.rps:.1f} istek/sn, "
        f"%{result.error_rate * 100:.1f} hata oranı, p95={result.latency_p95_ms:.0f}ms."
        + (f" — Eşik: {'GEÇTİ' if result.passed else 'KALDI'}." if result.passed is not None else "")
    )
    return result
