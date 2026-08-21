from urllib.parse import urlparse

from core.auth import perform_login
from checks.access_control import check_broken_access_control
from checks.api_security import run_api_checks
from checks.auth_weakness import check_auth_weakness
from checks.command_injection import check_command_injection
from checks.csrf import check_csrf
from checks.database import check_database
from checks.idor import check_idor
from checks.recon import check_recon
from checks.security_headers import check_cookie_flags, check_security_headers
from checks.sensitive_files import check_sensitive_files
from checks.sqli import check_sqli
from checks.xss import check_xss
from core.crawler import crawl
from core.http_client import HttpClient
from core.models import Finding, Verdict, compute_verdict, sort_findings
from core.suppressions import apply_suppressions, load_suppressions
from loadtest.runner import LoadTestResult, run_load_test
from mobile.apk_scan import run_mobile_checks
from network.port_scan import scan_ports
from safety import assert_authorized
from smoketest.runner import SmokeTestResult, parse_smoke_targets, run_smoke_test


def run_full_scan(
    url: str,
    scan_network: bool = False,
    scan_database: bool = False,
    host: str = None,
    api_base: str = None,
    no_api: bool = False,
    openapi: str = None,
    apk_path: str = None,
    login_path: str = None,
    username: str = None,
    password: str = None,
    second_username: str = None,
    second_password: str = None,
    login_json: bool = False,
    login_username_field: str = "username",
    login_extra_fields: dict = None,
    i_authorize_this_scan: bool = False,
    max_pages: int = 30,
    delay: float = 0.0,
    accepted_findings_path: str = None,
    smoke_test: bool = False,
    smoke_targets: str = None,
    load_test: bool = False,
    load_test_path: str = None,
    load_test_concurrency: int = 10,
    load_test_duration: float = 15.0,
    load_test_stages: str = None,
    load_test_threshold_p95_ms: float = None,
    load_test_threshold_error_pct: float = None,
    load_test_method: str = "GET",
    on_progress=None,
) -> tuple[list[Finding], Verdict, LoadTestResult | None, SmokeTestResult | None]:
    """CLI (scanner_cli.py) ve webapp'in ortak kullandigi tek tarama orkestrasyonu --
    web + mobil backend/API + ag + mobil APK kontrollerinin tamamini calistirip
    (findings, verdict, load_test_result) dondurur (load_test=False ise ucuncu deger
    None'dir). Yetkisiz hedeflerde safety.UnauthorizedTargetError yukseltir; cagiran
    taraf bunu yakalayip kullaniciya uygun sekilde gostermelidir.

    accepted_findings_path verilirse, o dosyadaki (finding_id -> disposition+reason)
    eslesmelerine gore ilgili bulgular 'Kabul Edilmiş Risk'/'False Positive' olarak
    isaretlenir ve verdict hesabina dahil edilmez (ama raporda gorunmeye devam eder).

    login_json=True ise login body'si JSON olarak gonderilir (varsayilan form-encoded).
    login_username_field, kullanici adi/email alaninin adini belirler (ör. 'email').
    login_extra_fields, login body'sine eklenecek sabit ek alanlardir (ör.
    {'login_type': 'staff'}). Login yanitinda bir JWT/bearer token bulunursa
    (core.auth) otomatik olarak Authorization header'ina eklenir.

    load_test=True ise, GUVENLIK TARAMASINDAN SONRA, ayni yetki kontrolune tabi
    hedefe (login yapildiysa ayni oturum/bearer token ile) belirtilen sure boyunca
    yuk testi calistirilir -- varsayilan olarak KAPALIDIR, bilinçli opt-in gerekir.
    load_test_stages verilirse (metin, her satirda 'eszamanli,sure') asamali/ramp
    yuk testi calisir; load_test_threshold_p95_ms / load_test_threshold_error_pct
    verilirse sonuca gecti/kaldi hukmu eklenir.

    smoke_test=True ise, AGIR TARAMADAN ONCE, hedefin birkac kritik path'ine hizli
    (saniyeler suren) bir 'ayakta mi' kontrolu yapilir. Bulgu/verdict'e dahil edilmez,
    ayri ve bagimsiz bir sonuc olarak doner -- taramanin geri kalanini durdurmaz.
    """
    progress = on_progress or (lambda msg: None)
    web_host = urlparse(url).hostname

    assert_authorized(web_host, i_authorize_this_scan)
    if scan_network:
        assert_authorized(host or web_host, i_authorize_this_scan)
    if scan_database:
        assert_authorized(host or web_host, i_authorize_this_scan)

    smoke_result = None
    if smoke_test:
        progress("Smoke test: hedefin ayakta olup olmadığı kontrol ediliyor...")
        smoke_result = run_smoke_test(url, targets=parse_smoke_targets(smoke_targets), on_progress=progress)

    client = HttpClient(delay=delay)
    login_set_cookie = ""

    if login_path and username and password:
        login_url = url.rstrip("/") + login_path
        progress(f"Giriş yapılıyor: {login_url}")
        try:
            login_resp = perform_login(
                client,
                login_url,
                username,
                password,
                as_json=login_json,
                username_field=login_username_field,
                extra_fields=login_extra_fields,
            )
            if "Authorization" in client.session.headers:
                progress("Yanıtta bir bearer token bulundu, sonraki isteklere Authorization header'ı olarak eklendi.")
            # Set-Cookie genelde login'in kendi 302 yanitinda gelir; requests redirect'i
            # otomatik takip ettiginden bu header nihai yanitta degil, resp.history'de olabilir.
            for candidate in (*login_resp.history, login_resp):
                if "Set-Cookie" in candidate.headers:
                    login_set_cookie = candidate.headers["Set-Cookie"]
                    break
        except Exception as exc:
            progress(f"[UYARI] Login denemesi başarısız oldu: {exc}")

    progress(f"{url} taranıyor (web crawl)...")
    pages = crawl(client, url, max_pages=max_pages)
    progress(f"{len(pages)} sayfa keşfedildi.")

    findings: list[Finding] = []
    progress("Keşif (DNS / dizin / parmak izi)...")
    findings += check_recon(client, url, pages)
    findings += check_sqli(client, pages)
    findings += check_xss(client, pages)
    findings += check_csrf(pages)
    findings += check_security_headers(pages)
    findings += check_cookie_flags(login_set_cookie, location=url.rstrip("/") + (login_path or "/login"))
    findings += check_sensitive_files(client, url)
    findings += check_idor(client, pages)
    findings += check_command_injection(client, pages)

    if login_path:
        login_url = url.rstrip("/") + login_path
        findings += check_auth_weakness(
            client,
            login_url,
            username_field=login_username_field,
            as_json=login_json,
            extra_fields=login_extra_fields,
        )

    resolved_api_base = api_base or (url.rstrip("/") + "/api")
    if not no_api:
        progress(f"Mobil backend/API taranıyor: {resolved_api_base}")
        findings += run_api_checks(client, resolved_api_base, openapi_path=openapi)

    if login_path and second_username and second_password:
        progress(f"Broken access control testi: düşük yetkili hesap ({second_username}) deneniyor...")
        low_priv_client = HttpClient(delay=delay)
        login_url = url.rstrip("/") + login_path
        try:
            perform_login(
                low_priv_client,
                login_url,
                second_username,
                second_password,
                as_json=login_json,
                username_field=login_username_field,
                extra_fields=login_extra_fields,
            )
            admin_candidate_urls = {url.rstrip("/") + "/admin", resolved_api_base.rstrip("/") + "/admin/users"}
            for page in pages:
                admin_candidate_urls.update(link for link in page.links if "admin" in link.lower())
            findings += check_broken_access_control(low_priv_client, sorted(admin_candidate_urls))
        except Exception as exc:
            progress(f"[UYARI] İkinci kullanıcı girişi başarısız: {exc}")

    if scan_network:
        net_host = host or web_host
        progress(f"Ağ/port taraması: {net_host}")
        findings += scan_ports(net_host)

    if scan_database:
        db_host = host or web_host
        progress(f"Veritabanı servis taraması: {db_host}")
        findings += check_database(db_host, client=client, web_url=url)

    if apk_path:
        progress(f"Mobil APK statik analizi: {apk_path}")
        findings += run_mobile_checks(apk_path)

    if accepted_findings_path:
        suppressions = load_suppressions(accepted_findings_path)
        if suppressions:
            progress(f"{len(suppressions)} bulgu, {accepted_findings_path} dosyasına göre incelenmiş/kabul edilmiş olarak işaretlendi.")
        findings = apply_suppressions(findings, suppressions)

    findings = sort_findings(findings)
    verdict = compute_verdict(findings)

    load_test_result = None
    if load_test:
        target = url.rstrip("/") + (load_test_path or "")
        stages = _parse_load_stages(load_test_stages)
        # Ayni oturum/bearer token'i yuk testine de tasi -- boylece authenticated
        # bir endpoint'in yuk altindaki davranisi da olculebilir.
        load_test_result = run_load_test(
            target,
            method=load_test_method,
            concurrency=load_test_concurrency,
            duration_s=load_test_duration,
            stages=stages,
            headers=dict(client.session.headers),
            threshold_p95_ms=load_test_threshold_p95_ms,
            threshold_error_rate_pct=load_test_threshold_error_pct,
            on_progress=progress,
        )

    return findings, verdict, load_test_result, smoke_result


def _parse_load_stages(raw_text: str):
    """Her satir 'eszamanli,sure' (ör. '10,10'). Bos/None ise None doner (tek-asama modu)."""
    if not raw_text or not raw_text.strip():
        return None
    stages = []
    for line in raw_text.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = [p.strip() for p in line.replace("\t", ",").split(",") if p.strip()]
        if len(parts) < 2:
            continue
        try:
            stages.append((int(float(parts[0])), float(parts[1])))
        except ValueError:
            continue
    return stages or None
