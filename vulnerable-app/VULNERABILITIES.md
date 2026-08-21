# VULNERABILITIES.md — Cevap Anahtarı

Bu dosya, `vulnerable-app` içine **kasıtlı olarak** yerleştirilmiş 22 güvenlik açığının tam listesidir. `../scanner` aracı, aşağıdaki tam komutla çalıştırıldığında **22/22'sini de** yakalamıştır (bkz. her satırdaki kanıt):

```
python scanner_cli.py --url http://127.0.0.1:5000 --scan-network --host 127.0.0.1 \
  --apk-path ../vulnerable-app/mobile-decoded-apk \
  --login-path /login --username admin --password admin123 \
  --second-username ayse --second-password ayse2024 \
  --output ../reports/demo
```

Sonuç: **37 bulgu** (Critical: 12, High: 14, Medium: 9, Low: 1, Info: 1) → verdict **NOT READY FOR PRODUCTION**, process exit code **1**.

Tüm veriler (kullanıcı, şifre, secret, token) demo amaçlıdır — gerçek bir sistemden alınmamıştır.

**Demo hesaplar:** `admin` / `admin123` (rol: admin), `ayse` / `ayse2024` (rol: user, düşük yetkili test hesabı), `mehmet` / `mehmet2024`

## Web (HTML) açıkları

| # | Açık | Nerede | Kod referansı | Scanner tespit etti mi? |
|---|------|--------|----------------|:---:|
| 1 | SQL Injection | `GET /search?q=` | `app.py:search()` | ✅ `SQL Injection @ GET /search` |
| 2 | SQL Injection (auth bypass) | `POST /login` | `app.py:login()` | ✅ `SQL Injection ile Auth Bypass @ /login` |
| 3 | Stored XSS | `POST /guestbook` | `templates/guestbook.html` | ✅ `XSS @ POST /guestbook` |
| 4 | Reflected XSS | `GET /search?q=` | `templates/search.html` | ✅ `XSS @ GET /search` |
| 5 | CSRF | `POST /profile/update` | `app.py:profile_update()` | ✅ `Eksik CSRF Koruması @ /profile/update` |
| 6 | IDOR | `GET /profile/<id>` | `app.py:profile()` | ✅ `IDOR @ /profile/<id>` |
| 7 | Broken access control | `GET /admin` | `app.py:admin()` | ✅ `Broken Access Control @ /admin` (ayse ile kanıtlandı) |
| 8 | Zayıf auth / rate-limit yok | `POST /login` | `app.py:login()` | ✅ `Rate Limiting Yok` + `Zayıf/Varsayılan Kimlik Bilgisi @ /login` |
| 9 | Command Injection | `POST /tools/ping` | `app.py:tools_ping()` | ✅ `OS Command Injection @ /tools/ping` |
| 10 | Sensitive data exposure | `GET /static/config_backup.txt` | `static/config_backup.txt` | ✅ `Hassas Dosya/Path Erişilebilir @ config_backup.txt` |
| 11 | Eksik güvenlik header'ları + zayıf cookie flag'leri | tüm response'lar | `app.py` (app.config) | ✅ `Eksik Güvenlik Header'ları` + `Cookie HttpOnly Bayrağı Eksik` + `Cookie Secure Bayrağı Eksik` |
| 12 | Directory listing | `GET /uploads/` | `app.py:uploads_listing()` | ✅ `Hassas Dosya/Path Erişilebilir @ /uploads/` |

## Mobil Backend API (JSON) açıkları

| # | Açık | Nerede | Kod referansı | Scanner tespit etti mi? |
|---|------|--------|----------------|:---:|
| 13 | SQL Injection (JSON) | `POST /api/login` | `app.py:api_login()` | ✅ `SQL Injection ile Auth Bypass (JSON API)` + `SQL Injection (JSON API)` |
| 14 | BOLA / IDOR (API) | `GET /api/profile/<id>` | `app.py:api_profile()` | ✅ `BOLA / IDOR (JSON API)` |
| 15 | Excessive data exposure | `GET /api/profile/<id>` | `app.py:api_profile()` | ✅ `Excessive Data Exposure (API) @ /api/profile/1` |
| 16 | Broken access control (API) | `GET /api/admin/users` | `app.py:api_admin_users()` | ✅ `Broken Access Control @ /api/admin/users` (ayse ile kanıtlandı) |
| 17 | Zayıf auth (API) | `POST /api/login` | `app.py:api_login()` | ✅ `Rate Limiting Yok (API)` |

## Mobil APK Statik Analiz açıkları

`mobile-decoded-apk/` klasörü, `apktool d app.apk` çıktısını taklit eden bir demo yapısıdır (gerçek bir `.apk` derlemek Android SDK/gradle gerektirir, bu ortamda yok). `scanner/mobile/apk_scan.py` gerçek bir apktool çıktısına karşı da aynı şekilde çalışır (opsiyonel olarak `androguard` kuruluysa ham `.apk` dosyasını da kabul eder).

| # | Açık | Nerede | Scanner tespit etti mi? |
|---|------|--------|:---:|
| 18 | `debuggable="true"` | `mobile-decoded-apk/AndroidManifest.xml` | ✅ |
| 19 | `allowBackup="true"` | `mobile-decoded-apk/AndroidManifest.xml` | ✅ |
| 20 | Cleartext traffic izinli | `mobile-decoded-apk/AndroidManifest.xml` | ✅ |
| 21 | Aşırı geniş exported component | `mobile-decoded-apk/AndroidManifest.xml` | ✅ (`DeepLinkActivity` + `DataProvider` ayrı ayrı; `MainActivity` LAUNCHER olduğu için doğru şekilde hariç tutuldu) |
| 22 | Hardcoded secret | `res/values/strings.xml`, `smali/.../ApiClient.smali` | ✅ (AWS key + Stripe key + smali token, 3 ayrı bulgu) |

## Kontrol Grubu — Bilerek GÜVENLİ (bunlar açık DEĞİL)

Scanner'ın sadece "her admin-benzeri path'i kör kör işaretlemediğini", gerçekten doğru
korunan bir endpoint'i **ayırt edebildiğini** kanıtlamak için bilerek eklendi. `/admin`
ile birebir aynı veriyi gösterir, tek fark: `role == 'admin'` kontrolü gerçekten var.

| Nerede | Kod referansı | Beklenen davranış | Scanner doğru mu davrandı? |
|---|---|---|:---:|
| `GET /admin-secure` | `app.py:admin_secure()` | `ayse` (role=user) ile 403; `admin` ile 200 | ✅ Bulgu ÜRETMEMELİ |
| `GET /api/admin-secure/users` | `app.py:api_admin_secure_users()` | `ayse` ile 403; `admin` ile 200 | ✅ Bulgu ÜRETMEMELİ (scanner bu path'i otomatik keşfetmez, sadece kod/manuel curl için) |

**Nasıl doğrularsın:** `ayse`/`ayse2024` ile giriş yap, `/admin` ve `/admin-secure`'a sırayla git.
Birincisi seni içeri alır (açık), ikincisi 403 döner (güvenli). Sonra scanner'ı çalıştır —
raporda `/admin` için "Broken Access Control" bulgusu olmalı, `/admin-secure` için **hiçbir
bulgu olmamalı**. Varsa, bu scanner'ın yanlış pozitif ürettiğinin kanıtıdır.

## Bonus bulgular (VULNERABILITIES.md'de numaralandırılmamış ama scanner tarafından da yakalanan)

- **Açık portlar** (`--scan-network` ile): bu makinede gerçekten açık olan 445 (SMB), 5432 (PostgreSQL), 135 (MSRPC) portları — hedef makineye özgü, `vulnerable-app`'in kendisiyle ilgili değil.
- **Zayıf/Varsayılan Kimlik Bilgisi**: `admin/admin123` yaygın zayıf şifre listesinde de bulunduğundan, SQLi-bypass'tan bağımsız ayrı bir bulgu olarak da raporlandı.

---

**Sonuç: 22/22 kasıtlı açık scanner tarafından otomatik olarak tespit edildi.**
