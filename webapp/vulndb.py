"""Scanner'in gercekten kontrol ettigi acik turlerinin referansi -- her satir
scanner/checks|mobile|network altindaki gercek bir module karsilik gelir,
uydurma/pazarlama amacli bir liste degildir."""

METHODOLOGY_MAP = [
    {
        "phase": "Reconnaissance",
        "status": "on",
        "lab": "DNS, WHOIS (public host), robots.txt, dizin wordlist, teknoloji parmak izi, crawl",
        "note": "Pasif OSINT (LinkedIn, Shodan, sosyal medya) yok.",
    },
    {
        "phase": "Scanning / zafiyet analizi",
        "status": "on",
        "lab": "Web, API, ağ port, veritabanı maruziyeti, APK statik",
        "note": "Her tarama crawl + recon ile başlar.",
    },
    {
        "phase": "Grey box (hesaplı)",
        "status": "on",
        "lab": "Login, JWT/cookie, ikinci hesapla broken access control",
        "note": "Ana formda kullanıcı/şifre ve ikinci hesap alanları.",
    },
    {
        "phase": "Reporting",
        "status": "on",
        "lab": "HTML/JSON rapor, severity, çözüm, accepted findings",
        "note": "Verdict yalnızca açık bulgulara göre.",
    },
    {
        "phase": "Weaponization / Delivery",
        "status": "off",
        "lab": "Yok",
        "note": "Exploit paketi, phishing, zararlı dosya üretilmez.",
    },
    {
        "phase": "Exploitation (shell / C2)",
        "status": "off",
        "lab": "Yok — açık kanıtlanır, sistem ele geçirilmez",
        "note": "SQLi/XSS imza ve yansıma; reverse shell yok.",
    },
    {
        "phase": "Post-exploitation / kalıcılık",
        "status": "off",
        "lab": "Yok",
        "note": "Yetki yükseltme, yanal hareket, backdoor yok.",
    },
    {
        "phase": "Covering tracks",
        "status": "off",
        "lab": "Yok",
        "note": "Log silme / iz gizleme eklenmez.",
    },
]

VULN_DB = [
    {
        "name": "Keşif (Recon)",
        "entries": [
            {
                "name": "DNS keşfi",
                "severity": "Info",
                "desc": "Hedef hostname için A/AAAA ve varsa PTR kaydı çözer.",
                "fix": "İç sunucuları genel DNS'te yayınlamayın.",
                "module": "checks/recon.py",
            },
            {
                "name": "WHOIS özeti",
                "severity": "Info",
                "desc": "Public host için IANA/registrar kaydından kısa özet. Localhost ve private IP atlanır.",
                "fix": "WHOIS gizliliği kurum politikasına göre; asıl risk açık servislerdir.",
                "module": "checks/recon.py",
            },
            {
                "name": "Dizin / uç keşfi",
                "severity": "Info",
                "desc": "Kısa recon wordlist (admin, swagger, graphql, .git/HEAD…). Soft-404 elenir.",
                "fix": "Gereksiz admin/docs uçlarını kapatın veya kimlik doğrulaması ekleyin.",
                "module": "checks/recon.py",
            },
            {
                "name": "Teknoloji parmak izi",
                "severity": "Info",
                "desc": "Server, X-Powered-By ve HTML ipuçlarından yığın özeti.",
                "fix": "Banner'ları azaltın; bileşenleri güncel tutun.",
                "module": "checks/recon.py",
            },
        ],
    },
    {
    "name": "Web",
        "entries": [
            {
                "name": "SQL Injection",
                "severity": "Critical",
                "desc": "Form/parametrelere hata-tabanlı ve yorum-satırı payload'ları enjekte edip yanıtta DB hata imzası arar.",
                "fix": "Parametreli sorgular (prepared statements) kullanın; kullanıcı girdisini asla SQL string'ine doğrudan gömmeyin.",
                "module": "checks/sqli.py",
            },
            {
                "name": "Cross-Site Scripting (XSS)",
                "severity": "High",
                "desc": "Benzersiz bir <script> marker'ı enjekte edip yanıtta (reflected) veya sonraki bir GET'te (stored) escape edilmeden bulunup bulunmadığını kontrol eder.",
                "fix": "Kullanıcı girdisini render etmeden önce HTML-escape edin; template motorunun otomatik escaping'ini gereksiz yere kapatmayın.",
                "module": "checks/xss.py",
            },
            {
                "name": "Eksik CSRF Koruması",
                "severity": "Medium",
                "desc": "Keşfedilen her POST formunda csrf/token adında bir input olup olmadığını kontrol eder; action'daki fiile göre (update/delete vb.) önem derecesi ayarlanır.",
                "fix": "Her state-changing form'a sunucu tarafında doğrulanan, tahmin edilemez bir CSRF token ekleyin.",
                "module": "checks/csrf.py",
            },
            {
                "name": "IDOR (Insecure Direct Object Reference)",
                "severity": "High",
                "desc": "Keşfedilen /kaynak/<sayısal-id> şeklindeki URL'lerde komşu id'leri deneyip farklı/geçerli içerik dönüp dönmediğine bakar.",
                "fix": "Sunucu tarafında, isteği yapan oturumun ilgili kaynağın gerçek sahibi olduğunu her istekte doğrulayın.",
                "module": "checks/idor.py",
            },
            {
                "name": "Broken Access Control",
                "severity": "Critical",
                "desc": "Düşük yetkili ikinci bir hesapla admin'e özel URL'lere erişilip erişilemediğini dener (SPA catch-all yanlış pozitiflerini eleyen bir referans karşılaştırmasıyla).",
                "fix": "Sunucu tarafında her istekte kullanıcının rolünü/yetkisini doğrulayın; sadece oturum açmış olmayı yeterli görmeyin.",
                "module": "checks/access_control.py",
            },
            {
                "name": "OS Command Injection",
                "severity": "Critical",
                "desc": "host/ip benzeri form alanlarına shell meta-karakterli payload'lar gönderir; marker'ın TEK BAŞINA (payload'ın tamamı olmadan) göründüğü durumları gerçek çalıştırma kanıtı sayar.",
                "fix": "Kullanıcı girdisini shell'e asla doğrudan geçirmeyin; subprocess'i shell=False ve argüman listesiyle kullanın.",
                "module": "checks/command_injection.py",
            },
            {
                "name": "Hassas Dosya/Path Erişilebilir",
                "severity": "Medium",
                "desc": ".env, .git/config, backup dosyaları gibi yaygın path'leri dener; SPA/catch-all uygulamalarda yanlış pozitifi önlemek için önce bir soft-404 referansı alır.",
                "fix": "Bu dosyaları web root dışına taşıyın veya web sunucusu/uygulama seviyesinde erişimi engelleyin.",
                "module": "checks/sensitive_files.py",
            },
            {
                "name": "Eksik Güvenlik Header'ları / Zayıf Cookie Flag'leri",
                "severity": "Medium",
                "desc": "CSP, X-Frame-Options, X-Content-Type-Options, HSTS varlığını ve session cookie'nin HttpOnly/Secure flag'lerini kontrol eder.",
                "fix": "Bir güvenlik-header middleware'i (ör. Flask-Talisman) ekleyin; SESSION_COOKIE_HTTPONLY/SECURE=True yapın.",
                "module": "checks/security_headers.py",
            },
            {
                "name": "Zayıf/Varsayılan Kimlik Bilgisi ve Rate Limiting",
                "severity": "Critical",
                "desc": "Yaygın varsayılan kimlik bilgilerini ve SQLi-bypass payload'larını dener; 8 ardışık başarısız denemenin engellenip engellenmediğine bakar.",
                "fix": "Varsayılan/zayıf şifreleri yasaklayın; başarısız denemeler için rate limiting/hesap kilitleme ekleyin.",
                "module": "checks/auth_weakness.py",
            },
        ],
    },
    {
        "icon": "📱",
        "name": "Mobil Backend API (JSON/JWT)",
        "entries": [
            {
                "name": "SQL Injection ile Auth Bypass (JSON API)",
                "severity": "Critical",
                "desc": "JSON login body'sine SQLi payload'ları gönderip gerçek bir şifre olmadan başarılı giriş yanıtı (token/user_id) arar.",
                "fix": "Parametreli sorgular kullanın; şifre karşılaştırmasını SQL içinde değil uygulama katmanında yapın.",
                "module": "checks/api_security.py",
            },
            {
                "name": "BOLA / Excessive Data Exposure (API)",
                "severity": "High",
                "desc": "Yaygın REST path wordlist'i + sayısal id brute-force ile endpoint keşfeder; komşu id'leri karşılaştırır ve yanıtta password/secret gibi alan adları arar.",
                "fix": "Object-level authorization uygulayın; API yanıt şemasını DTO/serializer ile sınırlayın.",
                "module": "checks/api_security.py",
            },
        ],
    },
    {
        "icon": "📦",
        "name": "Mobil APK Statik Analiz",
        "entries": [
            {
                "name": "Manifest Yanlış Yapılandırmaları",
                "severity": "High",
                "desc": "debuggable, allowBackup, usesCleartextTraffic bayraklarını ve korumasız exported component'leri kontrol eder (LAUNCHER activity doğru şekilde hariç tutulur).",
                "fix": "Release build'lerde debuggable=false, gereksiz allowBackup=false, usesCleartextTraffic=false yapın; exported component'leri permission ile koruyun.",
                "module": "mobile/apk_scan.py",
            },
            {
                "name": "Hardcoded Secret",
                "severity": "Critical",
                "desc": "Kaynak/decompiled (smali) dosyalarda AWS/Google/Stripe key desenlerini ve genel token/secret atamalarını regex ile arar.",
                "fix": "Secret'ları istemci tarafında tutmayın; sunucu-taraflı bir proxy/token exchange kullanın.",
                "module": "mobile/apk_scan.py",
            },
        ],
    },
    {
        "icon": "🔌",
        "name": "Ağ",
        "entries": [
            {
                "name": "Açık Port",
                "severity": "Medium",
                "desc": "Yaygın ~20 portu thread'li TCP connect scan ile dener, banner grab yapar; telnet/SMB/RDP/veritabanı gibi riskli portları yüksek önemle işaretler.",
                "fix": "Servisin dışarıya açık olması gerekip gerekmediğini değerlendirin; gerekmiyorsa kapatın veya firewall ile kısıtlayın.",
                "module": "network/port_scan.py",
            },
        ],
    },
    {
        "name": "Veritabanı",
        "entries": [
            {
                "name": "Dışarı açık DB servisi",
                "severity": "High",
                "desc": "MySQL, PostgreSQL, MSSQL, Oracle, MongoDB portlarına TCP bağlanır; banner varsa sürüm ipucunu kayda geçirir. Şifre denemesi yapmaz.",
                "fix": "Veritabanını yalnızca uygulama sunucusunun ulaşacağı iç ağa alın; dış portu kapatın.",
                "module": "checks/database.py",
            },
            {
                "name": "Kimlik doğrulamasız Redis / Memcached / Elasticsearch",
                "severity": "Critical",
                "desc": "Redis PING, Memcached STATS ve Elasticsearch HTTP kök yanıtının AUTH olmadan gelip gelmediğine bakar.",
                "fix": "requirepass/ACL, SASL veya xpack.security açın; servisi localhost’a bağlayın.",
                "module": "checks/database.py",
            },
            {
                "name": "HTTP ile indirilebilir SQLite / SQL dump",
                "severity": "Critical",
                "desc": "Yaygın /app.db, /db.sqlite3, /dump.sql path’lerini dener; SQLite magik başlığı veya SQL dump içeriği varsa bulgu üretir.",
                "fix": "Veritabanı dosyalarını web root dışına taşıyın; .db/.sqlite/.sql uzantılarını statik sunucuda yasaklayın.",
                "module": "checks/database.py",
            },
        ],
    },
]
