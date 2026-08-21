from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.models import Finding, Verdict
from loadtest.runner import LoadTestResult
from smoketest.runner import SmokeTestResult

SEVERITY_STYLE = {
    "Critical": "bold white on red",
    "High": "bold red",
    "Medium": "bold yellow",
    "Low": "cyan",
    "Info": "dim",
}

VERDICT_STYLE = {
    "NOT_READY": "bold white on red",
    "READY_WITH_WARNINGS": "bold black on yellow",
    "READY": "bold white on green",
}

VERDICT_ICON = {
    "NOT_READY": "❌",
    "READY_WITH_WARNINGS": "⚠",
    "READY": "✅",
}


def _findings_table(findings: list[Finding]) -> Table:
    table = Table(show_lines=False)
    table.add_column("ID", no_wrap=True, style="dim")
    table.add_column("Severity", no_wrap=True)
    table.add_column("Kategori", no_wrap=True)
    table.add_column("Başlık")
    table.add_column("Konum", overflow="fold")

    for f in findings:
        style = SEVERITY_STYLE.get(f.severity.value, "")
        table.add_row(f.id, f"[{style}]{f.severity.value}[/{style}]", f.category.value, f.title, f.location)
    return table


def _findings_detail(findings: list[Finding], start_index: int = 1) -> None:
    console = Console()
    for i, f in enumerate(findings, start_index):
        style = SEVERITY_STYLE.get(f.severity.value, "")
        console.print(
            f"[{style}]{i}. [{f.severity.value}] {f.title}[/{style}]  ({f.category.value})  {f.location}  [dim]#{f.id}[/dim]"
        )
        console.print(f"   Açıklama: {f.description}")
        console.print(f"   Kanıt: {f.evidence}")
        console.print(f"   Çözüm: {f.remediation}")
        if not f.is_open:
            console.print(f"   [dim]Durum: {f.disposition.value} -- {f.disposition_reason}[/dim]")
        console.print()


def _print_load_test(console: Console, result: LoadTestResult) -> None:
    if result.aborted_reason:
        console.print(Panel(f"[bold yellow]{result.aborted_reason}[/bold yellow]", title="YÜK TESTİ — BAŞLATILMADI", expand=False))
        console.print()
        return

    error_style = "bold red" if result.error_rate > 0.05 else ("yellow" if result.error_rate > 0 else "green")
    stage_line = None
    if len(result.stages_ran) > 1:
        stage_line = "Aşamalar: " + " → ".join(f"{s['concurrency']}w/{s['duration_s']:.0f}s" for s in result.stages_ran)
    lines = [
        f"Hedef: {result.method} {result.target}",
        stage_line or f"Eşzamanlı worker: {result.concurrency}  |  Süre: {result.wall_time_s:.1f}s",
        f"Toplam istek: {result.total_requests}  |  İstek/sn: {result.rps:.1f}",
        f"[{error_style}]Hata oranı: %{result.error_rate * 100:.1f}[/{error_style}]  ({result.failed} başarısız / {result.total_requests})",
        "",
        f"Gecikme (ms) — min {result.latency_min_ms:.0f} · ort {result.latency_avg_ms:.0f} · "
        f"p50 {result.latency_p50_ms:.0f} · p95 {result.latency_p95_ms:.0f} · p99 {result.latency_p99_ms:.0f} · max {result.latency_max_ms:.0f}",
    ]
    if result.status_codes:
        codes = "  ".join(f"{code}: {count}" for code, count in sorted(result.status_codes.items()))
        lines.append(f"Durum kodları — {codes}")
    if result.errors:
        errs = "  ".join(f"{name}: {count}" for name, count in sorted(result.errors.items()))
        lines.append(f"[bold red]Bağlantı hataları — {errs}[/bold red]")
    if result.passed is not None:
        threshold_style = "bold white on green" if result.passed else "bold white on red"
        parts = []
        if result.threshold_p95_ms is not None:
            parts.append(f"p95 ≤ {result.threshold_p95_ms:.0f}ms")
        if result.threshold_error_rate_pct is not None:
            parts.append(f"hata ≤ %{result.threshold_error_rate_pct:.1f}")
        lines.append(f"[{threshold_style}] {'GEÇTİ' if result.passed else 'KALDI'} [/{threshold_style}]  Eşik: {', '.join(parts)}")

    console.print(Panel("\n".join(lines), title="YÜK TESTİ SONUCU", expand=False))
    console.print()


def _print_smoke_test(console: Console, result: SmokeTestResult) -> None:
    lines = []
    for c in result.checks:
        style = "bold green" if c.ok else "bold red"
        outcome = "OK" if c.ok else "FAIL"
        detail = c.error or str(c.status_code)
        expected = f" (beklenen {c.expected_status})" if c.expected_status is not None else ""
        lines.append(f"[{style}]{outcome}[/{style}]  {c.path}  →  {detail}{expected}  ({c.latency_ms:.0f}ms)")

    style = "bold white on green" if result.passed else "bold white on red"
    console.print(
        Panel(
            "\n".join(lines),
            title=f"SMOKE TEST — [{style}]{result.passed_count}/{len(result.checks)} GEÇTİ[/{style}]",
            subtitle=result.base_url,
            expand=False,
        )
    )
    console.print()


def print_report(
    findings: list[Finding], verdict: Verdict, target: str, load_test_result: LoadTestResult = None,
    smoke_test_result: SmokeTestResult = None,
) -> None:
    console = Console()

    console.print("[bold]VEXYRON[/bold] [dim]— Security Validation Platform[/dim]")

    if smoke_test_result:
        _print_smoke_test(console, smoke_test_result)

    icon = VERDICT_ICON.get(verdict.status, "")
    style = VERDICT_STYLE.get(verdict.status, "bold")
    counts_line = "   ".join(
        f"{sev}: {verdict.counts.get(sev, 0)}" for sev in ("Critical", "High", "Medium", "Low", "Info")
    )
    if verdict.accepted_count:
        counts_line += f"   [dim]| İncelenmiş/Kabul Edilmiş: {verdict.accepted_count} (verdict'e dahil değil)[/dim]"

    console.print()
    console.print(
        Panel(
            f"[{style}] {icon}  {verdict.label}  [/{style}]\n\n{counts_line}",
            title="PRODUCTION READINESS",
            subtitle=target,
            expand=False,
        )
    )
    console.print()

    if load_test_result:
        _print_load_test(console, load_test_result)

    if not findings:
        console.print("[bold green]Hiçbir bulgu yok.[/bold green]")
        return

    open_findings = [f for f in findings if f.is_open]
    reviewed_findings = [f for f in findings if not f.is_open]

    if open_findings:
        console.print("[bold]Açık Bulgular[/bold]")
        console.print(_findings_table(open_findings))
        console.print()
        _findings_detail(open_findings)
    else:
        console.print("[bold green]Açık bulgu yok.[/bold green]\n")

    if reviewed_findings:
        console.print(f"[bold]İncelenmiş / Kabul Edilmiş ({len(reviewed_findings)})[/bold]")
        console.print(_findings_table(reviewed_findings))
        console.print()
        _findings_detail(reviewed_findings, start_index=len(open_findings) + 1)
