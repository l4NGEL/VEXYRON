import html
from datetime import datetime

from core.models import Finding, Verdict
from loadtest.runner import LoadTestResult
from smoketest.runner import SmokeTestResult

SEVERITY_COLORS = {
    "Critical": "#7f1d1d",
    "High": "#dc2626",
    "Medium": "#d97706",
    "Low": "#2563eb",
    "Info": "#6b7280",
}

VERDICT_COLORS = {
    "NOT_READY": ("#7f1d1d", "#fee2e2"),
    "READY_WITH_WARNINGS": ("#92400e", "#fef3c7"),
    "READY": ("#065f46", "#d1fae5"),
}

VERDICT_LABELS_TR = {
    "NOT_READY": "❌ PRODUCTION'A HAZIR DEĞİL",
    "READY_WITH_WARNINGS": "⚠️ UYARILARLA HAZIR",
    "READY": "✅ PRODUCTION'A HAZIR",
}


def _esc(value) -> str:
    return html.escape(str(value))


def _finding_card(f: Finding) -> str:
    color = SEVERITY_COLORS.get(f.severity.value, "#999")
    muted = "" if f.is_open else ' style="opacity:0.7"'
    disposition_html = ""
    if not f.is_open:
        disposition_html = (
            f'<p class="disposition"><strong>Durum:</strong> {_esc(f.disposition.value)} — {_esc(f.disposition_reason)}</p>'
        )
    return f"""
        <div class="finding" style="border-left-color:{color}"{muted}>
          <div class="finding-header">
            <span class="badge" style="background:{color}">{_esc(f.severity.value)}</span>
            <span class="category">{_esc(f.category.value)}</span>
            <span class="title">{_esc(f.title)}</span>
            <span class="finding-id">#{_esc(f.id)}</span>
          </div>
          <div class="location">{_esc(f.location)}</div>
          <p><strong>Açıklama:</strong> {_esc(f.description)}</p>
          <p><strong>Kanıt:</strong> <code>{_esc(f.evidence)}</code></p>
          <p><strong>Çözüm:</strong> {_esc(f.remediation)}</p>
          {disposition_html}
        </div>
"""


def _load_test_section(result: LoadTestResult) -> str:
    if result.aborted_reason:
        return f"""
    <div class="loadtest-box">
      <h2 class="section-title" style="margin-top:0">Yük Testi — Başlatılmadı</h2>
      <p style="color:#92400e;background:#fef3c7;border-radius:8px;padding:0.75rem 1rem;font-weight:600">{_esc(result.aborted_reason)}</p>
    </div>
"""

    error_color = "#dc2626" if result.error_rate > 0.05 else ("#d97706" if result.error_rate > 0 else "#059669")
    codes_html = "".join(
        f'<span class="count-pill">{_esc(code)}: {count}</span>' for code, count in sorted(result.status_codes.items())
    )
    errors_html = ""
    if result.errors:
        errs = "".join(f'<span class="count-pill" style="border-color:#dc2626">{_esc(name)}: {count}</span>' for name, count in sorted(result.errors.items()))
        errors_html = f'<p><strong>Bağlantı hataları:</strong></p><div>{errs}</div>'

    stage_html = ""
    if len(result.stages_ran) > 1:
        stages = " → ".join(f"{s['concurrency']}w/{s['duration_s']:.0f}s" for s in result.stages_ran)
        stage_html = f'<p class="meta"><strong>Aşamalar:</strong> {_esc(stages)}</p>'

    threshold_html = ""
    if result.passed is not None:
        badge_color = "#059669" if result.passed else "#dc2626"
        badge_bg = "#d1fae5" if result.passed else "#fee2e2"
        parts = []
        if result.threshold_p95_ms is not None:
            parts.append(f"p95 ≤ {result.threshold_p95_ms:.0f}ms")
        if result.threshold_error_rate_pct is not None:
            parts.append(f"hata ≤ %{result.threshold_error_rate_pct:.1f}")
        threshold_html = (
            f'<p><span class="badge" style="background:{badge_color}">{"GEÇTİ" if result.passed else "KALDI"}</span> '
            f'<span style="background:{badge_bg};color:{badge_color};border-radius:6px;padding:0.1rem 0.5rem;font-size:0.85rem">Eşik: {_esc(", ".join(parts))}</span></p>'
        )

    return f"""
    <div class="loadtest-box">
      <h2 class="section-title" style="margin-top:0">Yük Testi Sonucu</h2>
      <p class="meta">Hedef: <code>{_esc(result.method)} {_esc(result.target)}</code></p>
      {stage_html}
      <div class="stat-grid">
        <div class="stat"><div class="stat-value">{result.concurrency}</div><div class="stat-label">eşzamanlı worker</div></div>
        <div class="stat"><div class="stat-value">{result.wall_time_s:.1f}s</div><div class="stat-label">süre</div></div>
        <div class="stat"><div class="stat-value">{result.total_requests}</div><div class="stat-label">toplam istek</div></div>
        <div class="stat"><div class="stat-value">{result.rps:.1f}</div><div class="stat-label">istek/sn</div></div>
        <div class="stat"><div class="stat-value" style="color:{error_color}">%{result.error_rate * 100:.1f}</div><div class="stat-label">hata oranı</div></div>
      </div>
      <p><strong>Gecikme (ms):</strong> min {result.latency_min_ms:.0f} · ort {result.latency_avg_ms:.0f} · p50 {result.latency_p50_ms:.0f} · p95 {result.latency_p95_ms:.0f} · p99 {result.latency_p99_ms:.0f} · max {result.latency_max_ms:.0f}</p>
      <p><strong>Durum kodları:</strong></p>
      <div>{codes_html}</div>
      {errors_html}
      {threshold_html}
    </div>
"""


def _smoke_test_section(result: SmokeTestResult) -> str:
    badge_color = "#059669" if result.passed else "#dc2626"
    badge_bg = "#d1fae5" if result.passed else "#fee2e2"
    rows = ""
    for c in result.checks:
        ok_color = "#059669" if c.ok else "#dc2626"
        detail = _esc(c.error) if c.error else str(c.status_code)
        expected = f" (beklenen {c.expected_status})" if c.expected_status is not None else ""
        rows += (
            f'<p><span class="badge" style="background:{ok_color}">{"OK" if c.ok else "FAIL"}</span> '
            f'<code>{_esc(c.path)}</code> → {detail}{expected} '
            f'<span style="color:#6b7280;font-size:0.85rem">({c.latency_ms:.0f}ms)</span></p>'
        )
    return f"""
    <div class="loadtest-box">
      <h2 class="section-title" style="margin-top:0">Smoke Test
        <span style="background:{badge_bg};color:{badge_color};border-radius:6px;padding:0.15rem 0.6rem;font-size:0.8rem;margin-left:0.5rem">
          {result.passed_count}/{len(result.checks)} geçti
        </span>
      </h2>
      <p class="meta">Hedef: <code>{_esc(result.base_url)}</code></p>
      {rows}
    </div>
"""


def render_html_report(
    findings: list[Finding], verdict: Verdict, target: str, load_test_result: LoadTestResult = None,
    smoke_test_result: SmokeTestResult = None,
) -> str:
    fg, bg = VERDICT_COLORS.get(verdict.status, ("#111111", "#eeeeee"))
    label = VERDICT_LABELS_TR.get(verdict.status, verdict.label)
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    counts_html = "".join(
        f'<span class="count-pill" style="border-color:{SEVERITY_COLORS.get(sev, "#999")}">'
        f"{sev}: {verdict.counts.get(sev, 0)}</span>"
        for sev in ("Critical", "High", "Medium", "Low", "Info")
    )
    if verdict.accepted_count:
        counts_html += (
            f'<span class="count-pill count-pill-muted">'
            f"İncelenmiş/Kabul Edilmiş: {verdict.accepted_count} (verdict'e dahil değil)</span>"
        )

    smoke_test_html = _smoke_test_section(smoke_test_result) if smoke_test_result else ""
    load_test_html = _load_test_section(load_test_result) if load_test_result else ""

    open_findings = [f for f in findings if f.is_open]
    reviewed_findings = [f for f in findings if not f.is_open]

    if not findings:
        body_html = '<p class="no-findings">Hiçbir bulgu yok.</p>'
    else:
        body_html = ""
        if open_findings:
            body_html += '<h2 class="section-title">Açık Bulgular</h2>'
            body_html += "".join(_finding_card(f) for f in open_findings)
        else:
            body_html += '<p class="no-findings">Açık bulgu yok.</p>'
        if reviewed_findings:
            body_html += f'<h2 class="section-title">İncelenmiş / Kabul Edilmiş ({len(reviewed_findings)})</h2>'
            body_html += "".join(_finding_card(f) for f in reviewed_findings)

    return f"""<!doctype html>
<html lang="tr">
<head>
<meta charset="utf-8">
<title>VEXYRON Raporu — {_esc(target)}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, Arial, sans-serif; background:#f4f5f7; color:#1a1a1a; margin:0; }}
  .container {{ max-width: 900px; margin: 2rem auto; padding: 0 1.5rem; }}
  header h1 {{ margin-bottom: 0.25rem; }}
  header .meta {{ color:#6b7280; font-size:0.9rem; margin-bottom:1.5rem; }}
  .verdict-banner {{ background:{bg}; color:{fg}; border-radius:10px; padding:1.25rem 1.5rem; margin-bottom:1.5rem; }}
  .verdict-banner h2 {{ margin:0 0 0.6rem 0; font-size:1.4rem; }}
  .count-pill {{ display:inline-block; border:1.5px solid #999; border-radius:999px; padding:0.15rem 0.75rem; margin-right:0.5rem; margin-bottom: 0.4rem; font-size:0.85rem; background:#fff; color:#111; }}
  .count-pill-muted {{ border-style: dashed; color:#4b5563; }}
  .section-title {{ font-size: 1.1rem; color:#374151; margin: 1.5rem 0 0.75rem; }}
  .finding {{ background:#fff; border:1px solid #e5e7eb; border-left:5px solid #999; border-radius:8px; padding:1rem 1.25rem; margin-bottom:1rem; }}
  .finding-header {{ display:flex; align-items:center; gap:0.6rem; margin-bottom:0.4rem; flex-wrap:wrap; }}
  .badge {{ color:#fff; font-size:0.75rem; font-weight:700; padding:0.2rem 0.6rem; border-radius:6px; }}
  .category {{ color:#6b7280; font-size:0.8rem; border:1px solid #d1d5db; border-radius:6px; padding:0.1rem 0.5rem; }}
  .title {{ font-weight:700; font-size:1.05rem; }}
  .finding-id {{ margin-left:auto; color:#9ca3af; font-size:0.75rem; font-family: ui-monospace, Consolas, monospace; }}
  .location {{ font-family: ui-monospace, Consolas, monospace; font-size:0.85rem; color:#374151; margin-bottom:0.5rem; word-break:break-all; }}
  code {{ background:#f3f4f6; padding:0.1rem 0.35rem; border-radius:4px; word-break:break-all; }}
  .disposition {{ color:#4b5563; font-style: italic; }}
  .no-findings {{ color:#059669; font-weight:600; }}
  .loadtest-box {{ background:#fff; border:1px solid #e5e7eb; border-radius:10px; padding:1.25rem 1.5rem; margin-bottom:1.5rem; }}
  .stat-grid {{ display:flex; flex-wrap:wrap; gap:1.5rem; margin:0.75rem 0 1rem; }}
  .stat-value {{ font-size:1.4rem; font-weight:700; }}
  .stat-label {{ font-size:0.75rem; color:#6b7280; }}
</style>
</head>
<body>
  <div class="container">
    <header>
      <h1>VEXYRON Raporu</h1>
      <p style="margin:0 0 0.35rem;color:#6b7280;font-size:0.8rem;font-weight:700;letter-spacing:0.03em">SECURITY VALIDATION PLATFORM</p>
      <div class="meta">Hedef: {_esc(target)} &middot; Oluşturulma: {_esc(generated_at)}</div>
    </header>
    <div class="verdict-banner">
      <h2>{_esc(label)}</h2>
      <div>{counts_html}</div>
    </div>
    {smoke_test_html}
    {load_test_html}
    <section>
      {body_html}
    </section>
  </div>
</body>
</html>
"""
