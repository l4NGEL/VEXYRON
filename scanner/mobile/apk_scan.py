import os
import re
import xml.etree.ElementTree as ET

from core.models import Category, Finding, Severity

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

SECRET_PATTERNS = (
    ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("Stripe Live Key", re.compile(r"sk_live_[0-9a-zA-Z]{16,}")),
    (
        "Generic secret/token assignment",
        re.compile(r"(?:token|secret|api[_-]?key)[\"']?\s*[:=]\s*[\"'][A-Za-z0-9_\-]{16,}[\"']", re.IGNORECASE),
    ),
    (
        "Hardcoded const-string secret (smali)",
        re.compile(r'const-string\s+v\d+,\s*"(?:tok|sk|key|secret)[A-Za-z0-9_\-]{8,}"', re.IGNORECASE),
    ),
    ("Private Key Header", re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----")),
)

TEXT_FILE_EXTENSIONS = (".xml", ".smali", ".txt", ".json", ".properties")


def _attr(element: ET.Element, name: str):
    return element.get(f"{ANDROID_NS}{name}")


def _has_launcher_intent_filter(activity_el: ET.Element) -> bool:
    for intent_filter in activity_el.findall("intent-filter"):
        for category in intent_filter.findall("category"):
            if _attr(category, "name") == "android.intent.category.LAUNCHER":
                return True
    return False


def _analyze_manifest_root(root: ET.Element, manifest_loc: str) -> list[Finding]:
    findings = []
    app_el = root.find("application")
    if app_el is None:
        return findings

    if _attr(app_el, "debuggable") == "true":
        findings.append(
            Finding(
                title='android:debuggable="true"',
                severity=Severity.HIGH,
                category=Category.MOBILE,
                location=manifest_loc,
                description="Uygulama debug edilebilir olarak paketlenmis; bir saldirgan cihaza baglanip runtime'i inceleyebilir/degistirebilir.",
                evidence='<application ... android:debuggable="true">',
                remediation="Release build'lerde debuggable=false oldugunu (Gradle varsayilani) dogrulayin; CI/CD'de release imzasi kontrolu ekleyin.",
            )
        )

    if _attr(app_el, "allowBackup") == "true":
        findings.append(
            Finding(
                title='android:allowBackup="true"',
                severity=Severity.MEDIUM,
                category=Category.MOBILE,
                location=manifest_loc,
                description="Uygulama verisi 'adb backup' ile fiziksel/USB erisimi olan biri tarafindan disari alinabilir.",
                evidence='<application ... android:allowBackup="true">',
                remediation="allowBackup=false yapin veya android:fullBackupContent ile hassas veriyi yedeklemeden haric tutun.",
            )
        )

    if _attr(app_el, "usesCleartextTraffic") == "true":
        findings.append(
            Finding(
                title="Cleartext Traffic İzinli",
                severity=Severity.HIGH,
                category=Category.MOBILE,
                location=manifest_loc,
                description="Uygulama sifresiz (duz HTTP) trafige izin veriyor; ag seviyesinde bir saldirgan (ör. acik Wi-Fi) trafigi okuyabilir/degistirebilir.",
                evidence='<application ... android:usesCleartextTraffic="true">',
                remediation="usesCleartextTraffic=false yapip tum trafigi HTTPS uzerinden yapin; istisna gerekiyorsa Network Security Config ile daraltin.",
            )
        )

    for tag in ("activity", "service", "receiver", "provider"):
        for el in app_el.findall(tag):
            if tag == "activity" and _has_launcher_intent_filter(el):
                continue  # MAIN/LAUNCHER activity'nin exported olmasi normaldir, bu bir acik degil.
            if _attr(el, "exported") == "true" and not _attr(el, "permission"):
                name = _attr(el, "name") or "?"
                findings.append(
                    Finding(
                        title=f"Korumasız Exported {tag.capitalize()}",
                        severity=Severity.MEDIUM,
                        category=Category.MOBILE,
                        location=f"{manifest_loc} :: {name}",
                        description=f"'{name}' bileseni exported=true ancak herhangi bir permission tanimlanmamis; cihazdaki diger uygulamalar bu bileseni cagirabilir.",
                        evidence=f'<{tag} android:name="{name}" android:exported="true"> (permission yok)',
                        remediation="Bilesenin gercekten disari acik olmasi gerekip gerekmedigine karar verin; degilse exported=false yapin, gerekliyse ozel bir permission ile koruyun.",
                    )
                )
    return findings


def check_manifest(decoded_dir: str) -> list[Finding]:
    manifest_path = os.path.join(decoded_dir, "AndroidManifest.xml")
    if not os.path.exists(manifest_path):
        return []
    try:
        root = ET.parse(manifest_path).getroot()
    except ET.ParseError:
        return []
    return _analyze_manifest_root(root, manifest_path)


def check_secrets(decoded_dir: str) -> list[Finding]:
    findings = []
    seen = set()
    for dirpath, _dirnames, filenames in os.walk(decoded_dir):
        for filename in filenames:
            if not filename.lower().endswith(TEXT_FILE_EXTENSIONS):
                continue
            full_path = os.path.join(dirpath, filename)
            try:
                with open(full_path, "r", encoding="utf-8", errors="ignore") as fh:
                    content = fh.read()
            except OSError:
                continue

            for label, pattern in SECRET_PATTERNS:
                match = pattern.search(content)
                if not match:
                    continue
                key = (label, full_path)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    Finding(
                        title=f"Hardcoded Secret: {label}",
                        severity=Severity.CRITICAL,
                        category=Category.MOBILE,
                        location=full_path,
                        description="Kaynak/decompiled dosyada duz metin bir secret/API anahtari bulundu; APK'yi indiren herkes bunu okuyup kullanabilir.",
                        evidence=f"Eslesen desen: {label} -> {match.group(0)[:60]}",
                        remediation="Secret'lari istemci tarafinda tutmayin; sunucu-taraflı bir proxy/token exchange kullanin veya calisma zamaninda Android Keystore'dan alin.",
                    )
                )
    return findings


def scan_decoded_apk(decoded_dir: str) -> list[Finding]:
    """`apktool d app.apk` ciktisiyla ayni yapidaki (plain-text AndroidManifest.xml +
    res/ + smali/) bir klasoru tarar. Gercek bir apktool ciktisina karsi da calisir."""
    return check_manifest(decoded_dir) + check_secrets(decoded_dir)


def scan_raw_apk(apk_path: str) -> list[Finding]:
    """androguard kuruluysa ham .apk uzerinde en temel manifest kontrollerini calistirir.
    androguard kurulu degilse veya beklenmeyen bir hatayla karsilasilirsa, kullaniciyi
    apktool ile decode etmeye yonlendiren bilgilendirici bir Finding doner (sert bagimlilik yok)."""
    try:
        from androguard.core.apk import APK
    except ImportError:
        return [
            Finding(
                title="APK Statik Analizi Atlandı",
                severity=Severity.INFO,
                category=Category.MOBILE,
                location=apk_path,
                description="Ham .apk dosyasini analiz etmek icin opsiyonel 'androguard' kutuphanesi kurulu degil.",
                evidence="import androguard.core.apk basarisiz oldu.",
                remediation="`pip install androguard` calistirin, ya da `apktool d app.apk` ile decode edip klasoru --apk-path olarak verin (ek bagimlilik gerektirmez).",
            )
        ]

    try:
        apk = APK(apk_path)
        findings = []

        if str(apk.get_attribute_value("application", "debuggable")).lower() == "true":
            findings.append(
                Finding(
                    title='android:debuggable="true"',
                    severity=Severity.HIGH,
                    category=Category.MOBILE,
                    location=apk_path,
                    description="Uygulama debug edilebilir olarak paketlenmis.",
                    evidence="AndroidManifest.xml (androguard) debuggable=true",
                    remediation="Release build'lerde debuggable=false oldugunu dogrulayin.",
                )
            )
        if str(apk.get_attribute_value("application", "allowBackup")).lower() == "true":
            findings.append(
                Finding(
                    title='android:allowBackup="true"',
                    severity=Severity.MEDIUM,
                    category=Category.MOBILE,
                    location=apk_path,
                    description="Uygulama verisi 'adb backup' ile disari alinabilir.",
                    evidence="AndroidManifest.xml (androguard) allowBackup=true",
                    remediation="allowBackup=false yapin veya fullBackupContent ile daraltin.",
                )
            )
        if str(apk.get_attribute_value("application", "usesCleartextTraffic")).lower() == "true":
            findings.append(
                Finding(
                    title="Cleartext Traffic İzinli",
                    severity=Severity.HIGH,
                    category=Category.MOBILE,
                    location=apk_path,
                    description="Uygulama sifresiz HTTP trafigine izin veriyor.",
                    evidence="AndroidManifest.xml (androguard) usesCleartextTraffic=true",
                    remediation="usesCleartextTraffic=false yapip HTTPS zorunlu kilin.",
                )
            )

        if not findings:
            findings.append(
                Finding(
                    title="APK Statik Analiz Tamamlandı",
                    severity=Severity.INFO,
                    category=Category.MOBILE,
                    location=apk_path,
                    description="androguard ile temel manifest kontrolleri calistirildi, belirgin bir sorun bulunamadi (sadece debuggable/allowBackup/cleartext kontrol edildi -- kapsamli bir denetim yerine gecmez).",
                    evidence="",
                    remediation="Daha kapsamli analiz icin `apktool d` ile decode edip klasor modunu (--apk-path <klasor>) kullanmayi veya manuel bir kod incelemesi yapmayi degerlendirin.",
                )
            )
        return findings
    except Exception as exc:
        return [
            Finding(
                title="APK Statik Analizi Hata Verdi",
                severity=Severity.INFO,
                category=Category.MOBILE,
                location=apk_path,
                description="androguard ile analiz sirasinda beklenmeyen bir hata olustu.",
                evidence=str(exc),
                remediation="APK dosyasinin gecerli oldugunu dogrulayin veya `apktool d` ile decode edip klasor modunu kullanin.",
            )
        ]


def run_mobile_checks(apk_path: str) -> list[Finding]:
    if os.path.isdir(apk_path):
        return scan_decoded_apk(apk_path)
    return scan_raw_apk(apk_path)
