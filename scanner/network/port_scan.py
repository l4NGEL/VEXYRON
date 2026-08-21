import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.models import Category, Finding, Severity

# port -> (servis adi, severity, aciklama, coz  um)
#
# Severity burada servisin KENDI dogasina gore verilir, port numarasinin "acik olmasi"na
# degil: bir veritabani/yonetim protokolunun genel internete acik olmasi neredeyse her zaman
# yanlis yapilandirmadir (HIGH); SSH/HTTP/HTTPS gibi bilincli olarak acik tutulan servisler
# sertlestirme sorunudur, varlik sorunu degil (LOW/INFO). Port taramasi "baglanti kuruldu"
# kanitidir, sömürü kaniti degildir -- bu yuzden hicbir port bulgusu CRITICAL verilmez; CRITICAL
# bu scanner'da yalnizca aktif olarak kanitlanmis aciklar (ör. SQLi bypass) icin kullanilir.
COMMON_PORTS = {
    21: (
        "FTP", Severity.HIGH,
        "FTP genellikle şifresiz kimlik doğrulama ve düz metin veri transferi kullanır; parola ve veri ağ üzerinde açık gönderilir.",
        "FTP'yi kapatıp SFTP/FTPS'e geçin; genel internetten erişim gerekmiyorsa bu portu tamamen kapatın.",
    ),
    22: (
        "SSH", Severity.LOW,
        "SSH açık olması tek başına bir açık değildir; standart bir uzak yönetim protokolüdür. Asıl riski kimlik doğrulama ve sertleştirme ayarları belirler.",
        "Parola ile girişi kapatıp yalnızca anahtar tabanlı kimlik doğrulama kullanın; fail2ban/oran sınırlama ekleyin; mümkünse yönetim erişimini belirli IP aralıklarına veya VPN'e kısıtlayın.",
    ),
    23: (
        "Telnet", Severity.HIGH,
        "Telnet parolalar dahil tüm trafiği düz metin gönderir; ağ trafiğini dinleyen biri kimlik bilgilerini doğrudan görür.",
        "Telnet'i tamamen kapatıp SSH'a geçin.",
    ),
    25: (
        "SMTP", Severity.MEDIUM,
        "Yanlış yapılandırılmış bir mail sunucusu açık relay olarak kötüye kullanılabilir. Bu sunucunun bilinçli olarak mail sunucusu olarak çalıştığını doğrulayın.",
        "Bilinçli bir mail sunucusu değilse portu kapatın; öyleyse open-relay testi yapın ve SPF/DKIM/DMARC yapılandırın.",
    ),
    53: (
        "DNS", Severity.INFO,
        "Beklenen bir servistir (genel DNS sunucusu); asıl risk yanlış yapılandırmadan (ör. herkese açık zone transfer) gelir.",
        "AXFR zone transfer'in yalnızca yetkili secondary sunuculara açık olduğunu doğrulayın.",
    ),
    80: (
        "HTTP", Severity.INFO,
        "Standart, genellikle bilinçli olarak açık tutulan web trafiğidir; asıl risk hassas verinin şifresiz taşınmasıdır.",
        "Tüm trafiği HTTPS'e yönlendirin; hiçbir hassas verinin düz HTTP üzerinden taşınmadığından emin olun.",
    ),
    110: (
        "POP3", Severity.MEDIUM,
        "Genellikle şifresiz kimlik doğrulama kullanır; parola ağ üzerinde açık gönderilebilir.",
        "POP3S (995, SSL/TLS) kullanın veya bu portu kapatın.",
    ),
    135: (
        "MSRPC", Severity.HIGH,
        "Windows RPC uç noktasıdır; tarihsel olarak sık istismar edilmiş geniş bir saldırı yüzeyi taşır.",
        "Bu portu genel internete kapatın; yalnızca iç ağdan erişime izin verin.",
    ),
    139: (
        "NetBIOS", Severity.HIGH,
        "Eski SMB/NetBIOS servisidir; bilinen uzaktan kod çalıştırma açıklarının hedefi olmuştur.",
        "Bu portu genel internete kapatın; gerekmiyorsa NetBIOS/SMBv1'i tamamen devre dışı bırakın.",
    ),
    143: (
        "IMAP", Severity.MEDIUM,
        "Genellikle şifresiz kimlik doğrulama kullanır; parola ağ üzerinde açık gönderilebilir.",
        "IMAPS (993, SSL/TLS) kullanın veya bu portu kapatın.",
    ),
    443: (
        "HTTPS", Severity.INFO,
        "Standart, beklenen güvenli web trafiğidir.",
        "Bilgi amaçlıdır; sertifikanın geçerli olduğundan ve güncel bir TLS sürümü kullanıldığından emin olun.",
    ),
    445: (
        "SMB", Severity.HIGH,
        "SMB, EternalBlue gibi kritik uzaktan kod çalıştırma açıklarının (WannaCry, NotPetya) hedefi olmuştur.",
        "Bu portu genel internete açık bırakmayın; yalnızca iç ağdan erişime izin verin.",
    ),
    1433: (
        "MSSQL", Severity.HIGH,
        "Veritabanı servisidir; internete açık olması doğrudan yetkisiz veri erişimi, brute-force ve sızıntı riski taşır.",
        "Bu portu genel internete kapatıp yalnızca güvenilir uygulama sunucusu / VPN IP aralıklarına kısıtlayın.",
    ),
    3306: (
        "MySQL", Severity.HIGH,
        "Veritabanı servisidir; internete açık olması doğrudan yetkisiz veri erişimi, brute-force ve sızıntı riski taşır.",
        "Bu portu genel internete kapatıp yalnızca güvenilir uygulama sunucusu / VPN IP aralıklarına kısıtlayın.",
    ),
    3389: (
        "RDP", Severity.HIGH,
        "İnternetten erişilebilir RDP; brute-force ve bilinen exploit'lerin (ör. BlueKeep) sık hedefidir.",
        "Bu portu genel internete kapatıp erişimi VPN arkasına alın; açık kalması gerekiyorsa Ağ Düzeyi Kimlik Doğrulaması (NLA) ve hesap kilitleme politikasını zorunlu kılın.",
    ),
    5432: (
        "PostgreSQL", Severity.HIGH,
        "Veritabanı servisidir; internete açık olması doğrudan yetkisiz veri erişimi, brute-force ve sızıntı riski taşır.",
        "Bu portu genel internete kapatıp yalnızca güvenilir uygulama sunucusu / VPN IP aralıklarına kısıtlayın.",
    ),
    5900: (
        "VNC", Severity.HIGH,
        "VNC genellikle zayıf/varsayılan parolayla korunur; başarılı erişim doğrudan ekran/masaüstü kontrolü sağlar.",
        "Bu portu genel internete kapatıp erişimi VPN arkasına alın; güçlü parola ve mümkünse ek bir kimlik doğrulama katmanı kullanın.",
    ),
    6379: (
        "Redis", Severity.HIGH,
        "Redis varsayılan olarak kimlik doğrulaması gerektirmez; internete açık olması doğrudan tam veri erişimi/silme riski taşır.",
        "Bu portu genel internete kapatın, requirepass ile kimlik doğrulamayı zorunlu kılın ve mümkünse yalnızca localhost/iç ağa bind edin.",
    ),
    8080: (
        "HTTP-alt", Severity.MEDIUM,
        "Sıkça admin panel, dev/staging ortamı veya iç araç barındırır; ana web portundan (80/443) ayrı olması çoğunlukla bilinçsizce açık bırakıldığının işaretidir.",
        "Bu portta ne çalıştığını doğrulayın; genel kullanıcıya yönelik değilse genel internete kapatın veya kimlik doğrulaması ekleyin.",
    ),
    27017: (
        "MongoDB", Severity.HIGH,
        "MongoDB varsayılan kurulumlarda kimlik doğrulaması kapalı olabilir; internete açık olması doğrudan veri sızıntısı/silme riski taşır.",
        "Bu portu genel internete kapatın, kimlik doğrulamayı (--auth) zorunlu kılın ve yalnızca localhost/iç ağa bind edin.",
    ),
}

UNKNOWN_SERVICE = (
    "Bilinmeyen", Severity.INFO,
    "Tanımlı olmayan bir servis bu portta yanıt verdi; well-known port listesinde karşılığı yok.",
    "Bu portta hangi servisin çalıştığını doğrulayın; gerekli değilse kapatmayı değerlendirin.",
)


def _probe_port(host: str, port: int, timeout: float) -> tuple[int, bool, str]:
    banner = ""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            try:
                sock.settimeout(timeout)
                data = sock.recv(128)
                banner = data.decode(errors="ignore").strip()
            except (socket.timeout, OSError):
                pass
            return port, True, banner
    except (socket.timeout, ConnectionRefusedError, OSError):
        return port, False, ""


def scan_ports(host: str, ports: dict = None, timeout: float = 0.75, max_workers: int = 20) -> list[Finding]:
    ports = ports or COMMON_PORTS
    findings = []
    open_ports = []

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = [pool.submit(_probe_port, host, port, timeout) for port in ports]
        for future in as_completed(futures):
            port, is_open, banner = future.result()
            if is_open:
                open_ports.append((port, banner))

    for port, banner in sorted(open_ports):
        service, severity, description, remediation = ports.get(port, UNKNOWN_SERVICE)

        if banner:
            confidence = f"banner ile doğrulandı: {banner[:120]!r}"
        else:
            confidence = "yalnızca TCP bağlantısı doğrulandı; servis adı well-known port numarasına göre varsayılmıştır, banner alınamadı"
        evidence = f"TCP connect başarılı, port {port} açık. {confidence}."

        findings.append(
            Finding(
                title=f"Açık Port: {port} ({service})",
                severity=severity,
                category=Category.NETWORK,
                location=f"{host}:{port}",
                description=description,
                evidence=evidence,
                remediation=remediation,
            )
        )
    return findings
