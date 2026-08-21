import json
import os
import re
import shutil
import socket
import sys
import tempfile
import zipfile
from datetime import datetime
from types import SimpleNamespace

WEBAPP_DIR = os.path.dirname(os.path.abspath(__file__))
SCANNER_DIR = os.path.abspath(os.path.join(WEBAPP_DIR, "..", "scanner"))
if SCANNER_DIR not in sys.path:
    sys.path.insert(0, SCANNER_DIR)

from flask import Flask, abort, redirect, render_template, request, send_from_directory, url_for  # noqa: E402
from werkzeug.exceptions import RequestEntityTooLarge  # noqa: E402
from werkzeug.utils import secure_filename  # noqa: E402

from core.models import Category, Disposition, Finding, Severity  # noqa: E402
from core.orchestrator import run_full_scan  # noqa: E402
from loadtest.runner import MAX_CONCURRENCY, MAX_DURATION_S  # noqa: E402
from report.html_report import render_html_report  # noqa: E402
from report.json_report import write_json_report  # noqa: E402
from report.pdf_report import write_pdf_report  # noqa: E402
from safety import UnauthorizedTargetError  # noqa: E402
from vulndb import METHODOLOGY_MAP, VULN_DB  # noqa: E402

PROJECT_ROOT = os.path.abspath(os.path.join(WEBAPP_DIR, ".."))
CONFIG_PATH = os.path.join(PROJECT_ROOT, "lab_config.json")
DEFAULT_REPORTS_DIR = os.path.join(PROJECT_ROOT, "reports")
DEFAULT_PORT = 5059
CHROME_BLOCKED_PORTS = {5060, 5061}
UPLOADS_DIR = os.path.join(WEBAPP_DIR, "uploads")
STYLE_CSS_PATH = os.path.join(WEBAPP_DIR, "static", "style.css")
APP_JS_PATH = os.path.join(WEBAPP_DIR, "static", "app.js")
_SAFE_FOLDER = re.compile(r"^[A-Za-z0-9._-]+$")

MAX_UPLOAD_BYTES = 64 * 1024 * 1024
MAX_ZIP_UNCOMPRESSED = 200 * 1024 * 1024
MAX_ZIP_FILES = 4000
ALLOWED_TREE_EXT = {".xml", ".smali", ".txt", ".json", ".properties", ".yml", ".yaml"}


def _default_reports_dir() -> str:
    return os.path.abspath(DEFAULT_REPORTS_DIR)


def load_lab_config() -> dict:
    cfg = {"webapp_port": DEFAULT_PORT, "reports_dir": ""}
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            if "webapp_port" in data:
                cfg["webapp_port"] = data["webapp_port"]
            if "reports_dir" in data:
                cfg["reports_dir"] = data["reports_dir"] or ""
    except (OSError, json.JSONDecodeError):
        pass
    return cfg


def _portable_reports_value(path: str) -> str:
    """Store a project-relative path so another PC gets its own folder."""
    abs_path = os.path.abspath(os.path.expanduser(path or ""))
    default = _default_reports_dir()
    if abs_path == default:
        return ""
    try:
        rel = os.path.relpath(abs_path, PROJECT_ROOT)
    except ValueError:
        return abs_path
    if rel == "reports" or rel == os.path.join(".", "reports"):
        return ""
    if rel.startswith("..") or os.path.isabs(rel):
        return abs_path
    return rel.replace("\\", "/")


def _resolve_reports_dir(custom: str) -> str:
    custom = (custom or "").strip()
    if not custom:
        return _default_reports_dir()
    if os.path.isabs(custom):
        return os.path.abspath(os.path.expanduser(custom))
    return os.path.abspath(os.path.join(PROJECT_ROOT, custom))


def save_lab_config(cfg: dict) -> None:
    os.makedirs(PROJECT_ROOT, exist_ok=True)
    reports = (cfg.get("reports_dir") or "").strip()
    if reports:
        reports = _portable_reports_value(reports)
    with open(CONFIG_PATH, "w", encoding="utf-8") as fh:
        json.dump(
            {
                "webapp_port": int(cfg.get("webapp_port") or DEFAULT_PORT),
                "reports_dir": reports,
            },
            fh,
            indent=2,
        )


def get_reports_dir() -> str:
    custom = (load_lab_config().get("reports_dir") or "").strip()
    path = _resolve_reports_dir(custom)
    try:
        os.makedirs(path, exist_ok=True)
        probe = os.path.join(path, ".pentest-lab-write")
        with open(probe, "w", encoding="utf-8") as fh:
            fh.write("")
        os.remove(probe)
        return path
    except OSError:
        fallback = _default_reports_dir()
        os.makedirs(fallback, exist_ok=True)
        return fallback


def get_configured_port() -> int:
    env = os.environ.get("PENTEST_LAB_WEBAPP_PORT")
    if env:
        try:
            return int(env)
        except ValueError:
            pass
    try:
        return int(load_lab_config().get("webapp_port") or DEFAULT_PORT)
    except (TypeError, ValueError):
        return DEFAULT_PORT


def _scan_count(reports_dir: str) -> int:
    if not os.path.isdir(reports_dir):
        return 0
    return sum(
        1
        for name in os.listdir(reports_dir)
        if os.path.isfile(os.path.join(reports_dir, name, "report.json"))
    )


app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES
app.config["TEMPLATES_AUTO_RELOAD"] = True


class UploadError(Exception):
    pass


@app.context_processor
def _inject_style_version():
    stamps = []
    for path in (STYLE_CSS_PATH, APP_JS_PATH):
        try:
            stamps.append(int(os.path.getmtime(path)))
        except OSError:
            pass
    return {"style_version": max(stamps) if stamps else 0}


def _timestamp() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def _checked(form, name: str) -> bool:
    return form.get(name) == "on"


def _optional(form, name: str):
    value = (form.get(name) or "").strip()
    return value or None


def _enum_or(enum_cls, raw, fallback):
    try:
        return enum_cls(raw)
    except ValueError:
        return fallback


def _finding_from_dict(item: dict) -> Finding:
    return Finding(
        title=item.get("title") or "",
        severity=_enum_or(Severity, item.get("severity"), Severity.INFO),
        category=_enum_or(Category, item.get("category"), Category.WEB),
        location=item.get("location") or "",
        description=item.get("description") or "",
        evidence=item.get("evidence") or "",
        remediation=item.get("remediation") or "",
        id=item.get("id") or "",
        disposition=_enum_or(Disposition, item.get("disposition") or "Açık", Disposition.OPEN),
        disposition_reason=item.get("disposition_reason") or "",
    )


def _load_test_for_view(result):
    """Canlı LoadTestResult veya kaydedilmiş JSON dict'i şablonun beklediği alana çevirir."""
    if result is None:
        return None
    if hasattr(result, "rps"):
        return result
    lat = result.get("latency_ms") or {}
    error_rate = result.get("error_rate")
    if error_rate is None:
        error_rate = (result.get("error_rate_pct") or 0) / 100.0
    codes = result.get("status_codes") or {}
    try:
        codes = {int(k) if str(k).isdigit() else k: v for k, v in codes.items()}
    except (TypeError, ValueError):
        pass
    return SimpleNamespace(
        method=result.get("method"),
        target=result.get("target"),
        concurrency=result.get("concurrency") or 0,
        wall_time_s=result.get("actual_duration_s") or result.get("wall_time_s") or 0,
        total_requests=result.get("total_requests") or 0,
        rps=result.get("requests_per_sec") or result.get("rps") or 0,
        error_rate=error_rate or 0,
        latency_min_ms=lat.get("min") or 0,
        latency_avg_ms=lat.get("avg") or 0,
        latency_p50_ms=lat.get("p50") or 0,
        latency_p95_ms=lat.get("p95") or 0,
        latency_p99_ms=lat.get("p99") or 0,
        latency_max_ms=lat.get("max") or 0,
        status_codes=codes,
        errors=result.get("errors") or {},
        aborted_reason=result.get("aborted_reason"),
        preflight_status=result.get("preflight_status"),
        stages_ran=result.get("stages_ran") or [],
        threshold_p95_ms=result.get("threshold_p95_ms"),
        threshold_error_rate_pct=result.get("threshold_error_rate_pct"),
        passed=result.get("passed"),
    )


def _smoke_test_for_view(result):
    """Canlı SmokeTestResult veya kaydedilmiş JSON dict'i şablonun beklediği alana çevirir."""
    if result is None:
        return None
    if hasattr(result, "checks") and not isinstance(result, dict):
        return result
    checks = [
        SimpleNamespace(
            path=c.get("path"),
            expected_status=c.get("expected_status"),
            status_code=c.get("status_code"),
            latency_ms=c.get("latency_ms") or 0,
            error=c.get("error") or "",
            ok=c.get("ok"),
        )
        for c in result.get("checks") or []
    ]
    return SimpleNamespace(
        base_url=result.get("base_url"),
        checks=checks,
        passed=result.get("passed"),
        passed_count=result.get("passed_count") or 0,
    )


def _read_report(folder: str):
    if not _SAFE_FOLDER.match(folder):
        abort(404)
    json_path = os.path.join(get_reports_dir(), folder, "report.json")
    if not os.path.isfile(json_path):
        abort(404)
    try:
        with open(json_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        abort(404)
    findings = [_finding_from_dict(item) for item in data.get("findings") or [] if isinstance(item, dict)]
    verdict = data.get("verdict") or {}
    return data, findings, verdict, _load_test_for_view(data.get("load_test")), _smoke_test_for_view(data.get("smoke_test"))


def _uploads_root() -> str:
    os.makedirs(UPLOADS_DIR, exist_ok=True)
    return UPLOADS_DIR


def _safe_relpath(rel: str):
    rel = (rel or "").replace("\\", "/").strip()
    if not rel or rel.startswith("/") or ":" in rel:
        return None
    parts = []
    for part in rel.split("/"):
        if part in ("", ".", ".."):
            return None
        parts.append(part)
    return os.path.join(*parts) if parts else None


def _apk_root_from_extracted(dest: str) -> str:
    if os.path.isfile(os.path.join(dest, "AndroidManifest.xml")):
        return dest
    try:
        entries = [e for e in os.listdir(dest) if not e.startswith(".")]
    except OSError:
        return dest
    if len(entries) == 1:
        inner = os.path.join(dest, entries[0])
        if os.path.isdir(inner) and os.path.isfile(os.path.join(inner, "AndroidManifest.xml")):
            return inner
    return dest


def _safe_extract_zip(zip_path: str, dest: str) -> None:
    try:
        zf = zipfile.ZipFile(zip_path)
    except zipfile.BadZipFile as exc:
        raise UploadError("ZIP/APK arşivi okunamadı.") from exc
    with zf:
        infos = zf.infolist()
        if len(infos) > MAX_ZIP_FILES:
            raise UploadError("ZIP çok fazla dosya içeriyor.")
        dest_abs = os.path.abspath(dest)
        total = 0
        for info in infos:
            name = info.filename.replace("\\", "/")
            if name.startswith("/") or name.startswith("\\") or ":" in name.split("/")[0]:
                raise UploadError("ZIP içinde geçersiz yol var.")
            rel = _safe_relpath(name)
            if info.is_dir() or name.endswith("/"):
                continue
            if rel is None:
                raise UploadError("ZIP içinde geçersiz yol var.")
            total += info.file_size
            if total > MAX_ZIP_UNCOMPRESSED:
                raise UploadError("ZIP açılınca çok büyük (üst sınır 200 MB).")
            target = os.path.abspath(os.path.join(dest, rel))
            if not (target == dest_abs or target.startswith(dest_abs + os.sep)):
                raise UploadError("ZIP içinde geçersiz yol var.")
        zf.extractall(dest)


def _resolve_apk_file(saved_path: str) -> str:
    ext = os.path.splitext(saved_path)[1].lower()
    if ext == ".apk":
        return saved_path
    if ext != ".zip":
        return saved_path
    extracted = saved_path + "_extracted"
    os.makedirs(extracted, exist_ok=True)
    _safe_extract_zip(saved_path, extracted)
    root = _apk_root_from_extracted(extracted)
    if os.path.isfile(os.path.join(root, "AndroidManifest.xml")):
        return root
    return saved_path


def _write_tree(files, rels, dest: str) -> None:
    if len(files) > MAX_ZIP_FILES:
        raise UploadError("Klasör çok fazla dosya içeriyor.")
    if rels and len(rels) != len(files):
        raise UploadError("Yüklenen klasör yolları dosyalarla eşleşmedi.")
    dest_abs = os.path.abspath(dest)
    for index, fs in enumerate(files):
        rel_raw = rels[index] if rels else (fs.filename or "")
        rel = _safe_relpath(rel_raw)
        if rel is None:
            continue
        ext = os.path.splitext(rel)[1].lower()
        if ext and ext not in ALLOWED_TREE_EXT:
            continue
        if not ext:
            continue
        target = os.path.abspath(os.path.join(dest, rel))
        if not (target == dest_abs or target.startswith(dest_abs + os.sep)):
            raise UploadError("Klasör içinde geçersiz yol var.")
        os.makedirs(os.path.dirname(target), exist_ok=True)
        fs.save(target)


def _ingest_uploads(req, cleanup: list):
    """Yüklenen APK/JSON dosyalarını geçici klasöre yazar. Dönüş: apk_path, accepted_path."""
    apk_path = None
    accepted_path = None

    apk_file = req.files.get("apk_file")
    folder_files = [fs for fs in req.files.getlist("apk_folder") if fs and fs.filename]
    accepted_file = req.files.get("accepted_file")

    if apk_file and apk_file.filename:
        staging = tempfile.mkdtemp(prefix="pl-apk-", dir=_uploads_root())
        cleanup.append(staging)
        name = secure_filename(apk_file.filename) or "upload.bin"
        ext = os.path.splitext(name)[1].lower()
        if ext not in (".apk", ".zip"):
            raise UploadError("APK yüklemesi .apk veya decode klasörünün .zip'i olmalı.")
        saved = os.path.join(staging, name)
        apk_file.save(saved)
        apk_path = _resolve_apk_file(saved)
    elif folder_files:
        staging = tempfile.mkdtemp(prefix="pl-apkdir-", dir=_uploads_root())
        cleanup.append(staging)
        _write_tree(folder_files, req.form.getlist("apk_folder_rel"), staging)
        apk_path = _apk_root_from_extracted(staging)
        if not os.path.isfile(os.path.join(apk_path, "AndroidManifest.xml")):
            raise UploadError("Seçilen klasörde AndroidManifest.xml yok — decode edilmiş APK klasörü olmalı.")

    if accepted_file and accepted_file.filename:
        name = secure_filename(accepted_file.filename) or "accepted_findings.json"
        if os.path.splitext(name)[1].lower() != ".json":
            raise UploadError("Kabul edilmiş bulgular dosyası .json olmalı.")
        staging = tempfile.mkdtemp(prefix="pl-acc-", dir=_uploads_root())
        cleanup.append(staging)
        saved = os.path.join(staging, "accepted_findings.json")
        accepted_file.save(saved)
        try:
            with open(saved, "r", encoding="utf-8") as fh:
                payload = json.load(fh)
        except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise UploadError("Kabul edilmiş bulgular dosyası geçerli bir JSON değil.") from exc
        if not isinstance(payload, list):
            raise UploadError("Kabul edilmiş bulgular JSON'u bir dizi (liste) olmalı.")
        accepted_path = saved

    return apk_path, accepted_path


@app.errorhandler(RequestEntityTooLarge)
def _too_large(_exc):
    return (
        render_template(
            "index.html",
            error="Yüklenen dosya çok büyük — üst sınır 64 MB.",
            expand_advanced=True,
        ),
        413,
    )


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    form = request.form
    url = (form.get("url") or "").strip()
    if not url:
        return render_template("index.html", error="Bir hedef URL girmelisin.", form=form)

    login_extra_raw = _optional(form, "login_extra")
    login_extra_fields = None
    if login_extra_raw:
        try:
            login_extra_fields = json.loads(login_extra_raw)
        except json.JSONDecodeError:
            return render_template(
                "index.html", error="Login extra fields geçerli bir JSON değil.", form=form, expand_advanced=True
            )

    load_test_users = _optional(form, "load_test_users")
    load_test_duration = _optional(form, "load_test_duration")
    load_test_threshold_p95 = _optional(form, "load_test_threshold_p95_ms")
    load_test_threshold_error = _optional(form, "load_test_threshold_error_pct")
    cleanup = []

    try:
        uploaded_apk, uploaded_accepted = _ingest_uploads(request, cleanup)
        apk_path = uploaded_apk
        if not apk_path and _checked(form, "scan_apk"):
            apk_path = _optional(form, "apk_path")
        accepted_findings_path = uploaded_accepted or _optional(form, "accepted_findings")

        findings, verdict, load_test_result, smoke_result = run_full_scan(
            url=url,
            scan_network=_checked(form, "scan_network"),
            scan_database=_checked(form, "scan_database"),
            host=_optional(form, "host"),
            no_api=_checked(form, "no_api"),
            apk_path=apk_path,
            login_path=_optional(form, "login_path"),
            username=_optional(form, "username"),
            password=_optional(form, "password"),
            second_username=_optional(form, "second_username"),
            second_password=_optional(form, "second_password"),
            login_json=_checked(form, "login_json"),
            login_username_field=_optional(form, "login_username_field") or "username",
            login_extra_fields=login_extra_fields,
            i_authorize_this_scan=_checked(form, "i_authorize"),
            accepted_findings_path=accepted_findings_path,
            smoke_test=_checked(form, "smoke_test"),
            smoke_targets=_optional(form, "smoke_targets"),
            load_test=_checked(form, "load_test"),
            load_test_path=_optional(form, "load_test_path"),
            load_test_method=_optional(form, "load_test_method") or "GET",
            load_test_concurrency=int(load_test_users) if load_test_users else 10,
            load_test_duration=float(load_test_duration) if load_test_duration else 15.0,
            load_test_stages=_optional(form, "load_test_stages"),
            load_test_threshold_p95_ms=float(load_test_threshold_p95) if load_test_threshold_p95 else None,
            load_test_threshold_error_pct=float(load_test_threshold_error) if load_test_threshold_error else None,
        )
    except UploadError as exc:
        return render_template("index.html", error=str(exc), form=form, expand_advanced=True)
    except UnauthorizedTargetError as exc:
        error = f"{exc} İzniniz olduğundan eminseniz aşağıdaki “Gelişmiş seçenekler” içindeki onay kutusunu işaretleyip tekrar deneyin."
        return render_template("index.html", error=error, form=form, expand_advanced=True)
    except Exception as exc:
        return render_template(
            "index.html", error=f"Tarama sırasında beklenmeyen bir hata oluştu: {exc}", form=form
        )
    finally:
        for folder in cleanup:
            shutil.rmtree(folder, ignore_errors=True)

    report_id = _timestamp()
    output_dir = os.path.join(get_reports_dir(), report_id)
    os.makedirs(output_dir, exist_ok=True)
    with open(os.path.join(output_dir, "report.html"), "w", encoding="utf-8") as fh:
        fh.write(render_html_report(
            findings, verdict, target=url, load_test_result=load_test_result, smoke_test_result=smoke_result
        ))
    write_json_report(
        os.path.join(output_dir, "report.json"), findings, verdict, target=url,
        load_test_result=load_test_result, smoke_test_result=smoke_result,
    )
    write_pdf_report(
        os.path.join(output_dir, "report.pdf"), findings, verdict, target=url,
        load_test_result=load_test_result, smoke_test_result=smoke_result,
    )

    return render_template(
        "results.html",
        findings=findings,
        verdict=verdict,
        target=url,
        report_id=report_id,
        load_test_result=load_test_result,
        smoke_test_result=smoke_result,
    )


def _list_scans():
    scans = []
    reports_dir = get_reports_dir()
    if not os.path.isdir(reports_dir):
        return scans
    for name in sorted(os.listdir(reports_dir), reverse=True):
        json_path = os.path.join(reports_dir, name, "report.json")
        if not os.path.isfile(json_path):
            continue
        try:
            with open(json_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            continue
        verdict = data.get("verdict", {})
        scans.append(
            {
                "folder": name,
                "target": data.get("target", "?"),
                "generated_at": data.get("generated_at", ""),
                "verdict_status": verdict.get("status", "READY"),
                "verdict_label": verdict.get("label", ""),
                "finding_count": data.get("finding_count", 0),
                "counts": verdict.get("counts") or {},
            }
        )
    return scans


@app.route("/reports/<path:subpath>")
def download_report(subpath):
    return send_from_directory(get_reports_dir(), subpath)


@app.route("/history")
def history():
    return render_template("history.html", scans=_list_scans())


@app.route("/history/<folder>")
def history_view(folder):
    data, findings, verdict, load_test_result, smoke_result = _read_report(folder)
    return render_template(
        "results.html",
        findings=findings,
        verdict=verdict,
        target=data.get("target", "?"),
        report_id=folder,
        load_test_result=load_test_result,
        smoke_test_result=smoke_result,
        from_history=True,
    )


@app.route("/vulndb")
def vulndb():
    return render_template("vulndb.html", categories=VULN_DB, methodology=METHODOLOGY_MAP)


def _settings_context(saved=False, error=None, restart_needed=False):
    reports_dir = get_reports_dir()
    cfg = load_lab_config()
    return dict(
        max_concurrency=MAX_CONCURRENCY,
        max_duration=MAX_DURATION_S,
        reports_dir=reports_dir,
        default_reports_dir=_default_reports_dir(),
        configured_port=int(cfg.get("webapp_port") or DEFAULT_PORT),
        process_port=get_configured_port(),
        env_port_locked=bool(os.environ.get("PENTEST_LAB_WEBAPP_PORT")),
        max_upload_mb=MAX_UPLOAD_BYTES // (1024 * 1024),
        default_port=DEFAULT_PORT,
        scan_count=_scan_count(reports_dir),
        machine_name=socket.gethostname(),
        config_path=CONFIG_PATH,
        methodology=METHODOLOGY_MAP,
        saved=saved,
        error=error,
        restart_needed=restart_needed,
        custom_reports=bool((cfg.get("reports_dir") or "").strip()),
    )


@app.route("/settings", methods=["GET", "POST"])
def settings_page():
    if request.method != "POST":
        return render_template("settings.html", **_settings_context())

    error = None
    restart_needed = False
    cfg = load_lab_config()
    port_raw = (request.form.get("webapp_port") or "").strip()
    reports_raw = (request.form.get("reports_dir") or "").strip()
    reset_reports = request.form.get("reset_reports") == "on"

    try:
        port = int(port_raw)
        if port < 1024 or port > 65535:
            raise ValueError("port")
        if port in CHROME_BLOCKED_PORTS:
            error = f"{port} Chrome tarafından kilitli (ERR_UNSAFE_PORT). 5059 veya 8080 dene."
        else:
            old = get_configured_port()
            cfg["webapp_port"] = port
            restart_needed = port != request.environ.get("SERVER_PORT") and str(port) != (request.host.split(":")[-1] if ":" in request.host else "")
            if old != port:
                restart_needed = True
    except ValueError:
        error = "Port 1024–65535 arasında bir sayı olmalı."

    if error:
        return render_template("settings.html", **_settings_context(error=error))

    if reset_reports:
        cfg["reports_dir"] = ""
    elif reports_raw:
        path = os.path.abspath(os.path.expanduser(reports_raw))
        try:
            os.makedirs(path, exist_ok=True)
        except OSError as exc:
            return render_template("settings.html", **_settings_context(error=f"Rapor klasörü oluşturulamadı: {exc}"))
        cfg["reports_dir"] = path
    else:
        cfg["reports_dir"] = ""

    save_lab_config(cfg)
    return render_template("settings.html", **_settings_context(saved=True, restart_needed=restart_needed))


if __name__ == "__main__":
    port = get_configured_port()
    app.run(host="127.0.0.1", port=port, debug=False)
