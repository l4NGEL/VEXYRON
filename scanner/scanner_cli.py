import argparse
import json as _json
import os
import sys
from datetime import datetime

from core.orchestrator import run_full_scan
from report.console_report import print_report
from report.html_report import render_html_report
from report.json_report import write_json_report
from report.pdf_report import write_pdf_report
from safety import UnauthorizedTargetError

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_REPORTS_DIR = os.path.join(SCRIPT_DIR, "..", "reports")


def parse_args():
    parser = argparse.ArgumentParser(description="VEXYRON -- Security Validation Platform: kendi uygulamani tarayan guvenlik araci.")
    parser.add_argument("--url", required=True, help="Taranacak hedef web uygulamasi (ör. http://127.0.0.1:5000)")
    parser.add_argument("--scan-network", action="store_true", help="Ag/port taramasini da calistir")
    parser.add_argument("--scan-database", action="store_true", help="Veritabani servis / dump maruziyet taramasini da calistir")
    parser.add_argument("--host", help="Ag ve veritabani taramasi icin hedef host (varsayilan: --url'den cikarilir)")
    parser.add_argument("--api-base", help="JSON API taramasi icin baz URL (varsayilan: --url + /api)")
    parser.add_argument("--no-api", action="store_true", help="Mobil backend/API taramasini atla")
    parser.add_argument("--openapi", help="API kesfi icin bir OpenAPI/Swagger JSON spec dosyasi")
    parser.add_argument("--apk-path", help="Mobil statik analiz icin decode edilmis APK klasoru veya .apk dosyasi")
    parser.add_argument("--login-path", help="Web login formu path'i (ör. /login) -- verilirse tarama oncesi giris yapilir")
    parser.add_argument("--username", help="Login icin kullanici adi")
    parser.add_argument("--password", help="Login icin sifre")
    parser.add_argument(
        "--second-username",
        help="Broken access control testi icin DUSUK yetkili (admin olmayan) ikinci bir hesabin kullanici adi",
    )
    parser.add_argument("--second-password", help="Ikinci (dusuk yetkili) hesabin sifresi")
    parser.add_argument(
        "--login-json",
        action="store_true",
        help="Login body'sini form-encoded yerine JSON olarak gonder (JWT/JSON API'ler icin)",
    )
    parser.add_argument(
        "--login-username-field",
        default="username",
        help="Login body'sindeki kullanici adi/email alaninin adi (varsayilan: username, ör. 'email')",
    )
    parser.add_argument(
        "--login-extra",
        help="Login body'sine eklenecek sabit ek alanlar, JSON string olarak (ör. '{\"login_type\":\"staff\"}')",
    )
    parser.add_argument("--output", default=None, help="Rapor cikti klasoru (varsayilan: reports/<timestamp>)")
    parser.add_argument(
        "--i-authorize-this-scan",
        action="store_true",
        help="localhost/private IP disindaki hedefler icin zorunlu onay bayragi -- sadece izniniz olan sistemlerde kullanin",
    )
    parser.add_argument("--max-pages", type=int, default=30, help="Crawler'in en fazla gezecegi sayfa sayisi")
    parser.add_argument("--delay", type=float, default=0.0, help="Istekler arasi gecikme (saniye), hedefe nazik olmak icin")
    parser.add_argument(
        "--accepted-findings",
        help="Incelenip 'kabul edilmis risk' / 'false positive' olarak isaretlenmis bulgularin oldugu JSON dosyasi -- bu bulgular raporda gorunmeye devam eder ama verdict'e dahil edilmez",
    )
    parser.add_argument(
        "--load-test",
        action="store_true",
        help="Guvenlik taramasindan SONRA, ayni hedefe yuk/stres testi de calistir (varsayilan kapali -- bilincli opt-in)",
    )
    parser.add_argument(
        "--load-test-path",
        help="Yuk testi icin --url'e eklenecek path (ör. /search) -- varsayilan: --url'in kendisi",
    )
    parser.add_argument("--load-test-method", default="GET", help="Yuk testi icin HTTP metodu (varsayilan GET)")
    parser.add_argument(
        "--load-test-users", type=int, default=10, help="Yuk testinde eszamanli 'kullanici' (thread) sayisi (varsayilan 10, ust sinir 200)"
    )
    parser.add_argument(
        "--load-test-duration", type=float, default=15.0, help="Yuk testinin sureceği saniye (varsayilan 15, ust sinir 120)"
    )
    parser.add_argument(
        "--load-test-stage",
        action="append",
        metavar="ESZAMANLI,SURE",
        help="Asamali/ramp yuk testi icin bir asama, 'eszamanli,sure' (ör. '10,10') -- birden fazla kez verilebilir "
        "(en fazla 5), verilirse --load-test-users/--load-test-duration yok sayilir",
    )
    parser.add_argument("--load-test-threshold-p95-ms", type=float, help="Yuk testi icin gecti/kaldi p95 gecikme esigi (ms)")
    parser.add_argument("--load-test-threshold-error-pct", type=float, help="Yuk testi icin gecti/kaldi hata orani esigi (%%)")
    parser.add_argument(
        "--smoke-test",
        action="store_true",
        help="Agir taramadan ONCE hedefin kritik path'lerine hizli bir 'ayakta mi' kontrolu yap",
    )
    parser.add_argument(
        "--smoke-target",
        action="append",
        metavar="PATH[,BEKLENEN_STATUS]",
        help="Smoke test icin bir path, ör. '/login' veya '/health,200' -- birden fazla kez verilebilir "
        "(verilmezse varsayilan: '/')",
    )
    return parser.parse_args()


def _timestamp() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except AttributeError:
        pass

    args = parse_args()

    login_extra_fields = None
    if args.login_extra:
        try:
            login_extra_fields = _json.loads(args.login_extra)
        except _json.JSONDecodeError as exc:
            print(f"[HATA] --login-extra gecerli bir JSON degil: {exc}", file=sys.stderr)
            sys.exit(2)

    smoke_targets_text = "\n".join(t.replace(",", " ") for t in args.smoke_target) if args.smoke_target else None
    load_test_stages_text = "\n".join(args.load_test_stage) if args.load_test_stage else None

    try:
        findings, verdict, load_test_result, smoke_result = run_full_scan(
            url=args.url,
            scan_network=args.scan_network,
            scan_database=args.scan_database,
            host=args.host,
            api_base=args.api_base,
            no_api=args.no_api,
            openapi=args.openapi,
            apk_path=args.apk_path,
            login_path=args.login_path,
            username=args.username,
            password=args.password,
            second_username=args.second_username,
            second_password=args.second_password,
            login_json=args.login_json,
            login_username_field=args.login_username_field,
            login_extra_fields=login_extra_fields,
            i_authorize_this_scan=args.i_authorize_this_scan,
            max_pages=args.max_pages,
            delay=args.delay,
            accepted_findings_path=args.accepted_findings,
            smoke_test=args.smoke_test,
            smoke_targets=smoke_targets_text,
            load_test=args.load_test,
            load_test_path=args.load_test_path,
            load_test_concurrency=args.load_test_users,
            load_test_duration=args.load_test_duration,
            load_test_stages=load_test_stages_text,
            load_test_threshold_p95_ms=args.load_test_threshold_p95_ms,
            load_test_threshold_error_pct=args.load_test_threshold_error_pct,
            load_test_method=args.load_test_method,
            on_progress=lambda msg: print(f"[*] {msg}"),
        )
    except UnauthorizedTargetError as exc:
        print(
            f"[GÜVENLİK ENGELİ] {exc}\n"
            "İzniniz olduğundan eminseniz --i-authorize-this-scan bayrağını geçerek bilerek devam edebilirsiniz.",
            file=sys.stderr,
        )
        sys.exit(2)

    print_report(findings, verdict, target=args.url, load_test_result=load_test_result, smoke_test_result=smoke_result)

    output_dir = args.output or os.path.join(DEFAULT_REPORTS_DIR, _timestamp())
    os.makedirs(output_dir, exist_ok=True)
    html_path = os.path.join(output_dir, "report.html")
    json_path = os.path.join(output_dir, "report.json")
    pdf_path = os.path.join(output_dir, "report.pdf")

    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(render_html_report(findings, verdict, target=args.url, load_test_result=load_test_result, smoke_test_result=smoke_result))
    write_json_report(json_path, findings, verdict, target=args.url, load_test_result=load_test_result, smoke_test_result=smoke_result)
    write_pdf_report(pdf_path, findings, verdict, target=args.url, load_test_result=load_test_result, smoke_test_result=smoke_result)

    print(f"\n[*] HTML rapor: {html_path}")
    print(f"[*] JSON rapor: {json_path}")
    print(f"[*] PDF rapor: {pdf_path}")

    # Verdict NOT_READY ise process non-zero exit code doner -- boylece bu arac dogrudan
    # bir CI/CD pipeline'inda "production'a deploy etmeden once calistir, kirmizi ise dur" gate'i olarak kullanilabilir.
    sys.exit(1 if verdict.status == "NOT_READY" else 0)


if __name__ == "__main__":
    main()
