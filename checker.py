#!/usr/bin/env python3
"""
VLESS+Reality Camouflage Site Checker
Проверяет сайты на пригодность для использования в качестве камуфляжа VLESS+Reality.
"""

import sys
import ssl
import socket
import math
import ipaddress
from urllib.parse import urlparse

import certifi
import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

console = Console()


# ──────────────────────────────────────────────
# Утилиты
# ──────────────────────────────────────────────

def normalize_domain(raw: str) -> str:
    """Убирает схему и слэши, оставляет чистый hostname."""
    raw = raw.strip().rstrip("/")
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urlparse(raw)
    return parsed.netloc or parsed.path


def haversine_km(lat1, lon1, lat2, lon2) -> float:
    """Расстояние между двумя точками на Земле (км)."""
    R = 6371.0
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi    = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def resolve_ip(domain: str) -> str | None:
    """DNS-резолв домена в IP."""
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None


def strip_www(host: str) -> str:
    return host.lower().removeprefix("www.")


def compare_hosts(origin: str, final: str) -> tuple[bool, bool]:
    """
    Возвращает (exact_match, www_only_diff).
    exact_match   — hostname совпадает точно.
    www_only_diff — отличие только в наличии/отсутствии www.
    """
    o = origin.lower().split(":")[0]
    f = final.lower().split(":")[0]
    exact    = (o == f)
    www_diff = (not exact) and (strip_www(o) == strip_www(f))
    return exact, www_diff


def make_ssl_context() -> ssl.SSLContext:
    """
    SSLContext с сертификатами certifi.
    Решает CERTIFICATE_VERIFY_FAILED в PyInstaller-сборке на Windows.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    ctx.load_verify_locations(cafile=certifi.where())
    return ctx


# ──────────────────────────────────────────────
# Проверки
# ──────────────────────────────────────────────

def check_geoip(ip: str) -> dict:
    """Критерий 1: Сервер вне РФ."""
    result = {
        "ok": False, "country": "?", "country_code": "?",
        "city": "?", "lat": None, "lon": None, "org": "?", "error": None,
    }
    try:
        with httpx.Client(timeout=10, verify=certifi.where()) as client:
            r = client.get(
                f"http://ip-api.com/json/{ip}"
                f"?fields=status,country,countryCode,city,lat,lon,org"
            )
            data = r.json()
        if data.get("status") == "success":
            result.update({
                "ok":           data["countryCode"] != "RU",
                "country":      data.get("country", "?"),
                "country_code": data.get("countryCode", "?"),
                "city":         data.get("city", "?"),
                "lat":          data.get("lat"),
                "lon":          data.get("lon"),
                "org":          data.get("org", "?"),
            })
        else:
            result["error"] = "ip-api вернул ошибку"
    except Exception as e:
        result["error"] = str(e)
    return result


def check_tls_and_http2(domain: str) -> dict:
    """
    Критерий 2: TLS 1.3 + HTTP/2.
    Критерий 5: шифрование после Server Hello (гарантировано TLS 1.3 / RFC 8446).
    """
    result = {
        "tls_version": None, "tls13": False,
        "http2": False, "alpn": None,
        "encrypted_handshake": False, "error": None,
    }
    try:
        ctx = make_ssl_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                result["tls_version"]         = ssock.version()
                result["alpn"]                = ssock.selected_alpn_protocol()
                result["tls13"]               = ssock.version() == "TLSv1.3"
                result["http2"]               = ssock.selected_alpn_protocol() == "h2"
                result["encrypted_handshake"] = result["tls13"]
    except Exception as e:
        result["error"] = _clean_error(str(e))
    return result


def check_redirect(domain: str) -> dict:
    """
    Критерий 3: Главная страница без редиректа на другой домен.

    status:
      "ok"      — hostname совпадает точно, код 2xx                → ✅
      "warning" — отличие только www. ↔ без www., код 2xx          → ⚠️
      "fail"    — смена домена, код 4xx/5xx или ошибка соединения  → ❌

    Если HTTP/2 даёт StreamReset — автоматически повторяем через HTTP/1.1.
    """
    result = {
        "status": "fail", "status_code": None,
        "final_url": None, "www_redirect": False, "error": None,
    }

    def _try_request(use_http2: bool):
        with httpx.Client(
            http2=use_http2,
            timeout=15,
            follow_redirects=True,
            verify=certifi.where(),
        ) as client:
            return client.get(f"https://{domain}/")

    try:
        try:
            r = _try_request(use_http2=True)
        except Exception as e:
            err_str = str(e)
            # StreamReset / CANCEL / PROTOCOL_ERROR → пробуем HTTP/1.1
            if any(k in err_str for k in ("StreamReset", "stream_id", "error_code", "PROTOCOL_ERROR")):
                r = _try_request(use_http2=False)
            else:
                raise

        result["status_code"] = r.status_code
        result["final_url"]   = str(r.url)

        final_host      = urlparse(str(r.url)).netloc
        exact, www_diff = compare_hosts(domain, final_host)

        if exact and r.status_code < 400:
            result["status"] = "ok"
        elif www_diff and r.status_code < 400:
            result["status"]       = "warning"
            result["www_redirect"] = True
        else:
            result["status"] = "fail"

    except Exception as e:
        result["error"] = _clean_error(str(e))
    return result


# ──────────────────────────────────────────────────────────────────
# OCSP Stapling — production реализация
#
# Метод A: сырой TLS handshake с расширением status_request (RFC 6066).
#   Отправляем ClientHello вручную, читаем ответ побайтово, ищем
#   handshake-сообщение CertificateStatus (тип 22 = 0x16).
#   Именно так работают openssl s_client -status, sslyze, testssl.sh.
#
# Метод B: OCSP responder (RFC 6960) — fallback через cryptography.
#   Если сервер не отдал staple в TLS — делаем HTTP POST к OCSP-серверу
#   напрямую. Подтверждает что сертификат валиден, но stapling не активен.
# ──────────────────────────────────────────────────────────────────

def _build_tls12_client_hello(hostname: str) -> bytes:
    """
    Строит минимальный TLS 1.2 ClientHello с расширением status_request.
    Сервер обязан ответить CertificateStatus если поддерживает stapling.
    Используем TLS 1.2 а не 1.3: в TLS 1.3 Certificate зашифрован,
    поэтому staple читается иначе — через EncryptedExtensions, что
    требует полного handshake. TLS 1.2 проще парсить на уровне сырых байт.
    """
    import os
    import struct

    # Random (32 bytes)
    client_random = os.urandom(32)

    # Session ID — пустой
    session_id = b"\x00"

    # Cipher suites: несколько распространённых + SCSV
    cipher_suites = bytes([
        0x00, 0x1c,              # длина: 14 байт
        0xc0, 0x2b,              # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        0xc0, 0x2f,              # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        0xc0, 0x2c,              # TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        0xc0, 0x30,              # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        0x00, 0x9c,              # TLS_RSA_WITH_AES_128_GCM_SHA256
        0x00, 0xff,              # TLS_EMPTY_RENEGOTIATION_INFO_SCSV
    ])

    # Compression methods: null only
    compression = b"\x01\x00"

    # ── Расширения ──

    # server_name (SNI)
    sni_name    = hostname.encode("ascii")
    sni_ext     = (
        b"\x00\x00"                                    # type: server_name
        + struct.pack(">H", len(sni_name) + 5)         # ext length
        + struct.pack(">H", len(sni_name) + 3)         # list length
        + b"\x00"                                      # name type: host_name
        + struct.pack(">H", len(sni_name))             # name length
        + sni_name
    )

    # status_request (OCSP) — RFC 6066 §8
    # Просим сервер прикрепить OCSP staple к Certificate
    status_request_ext = bytes([
        0x00, 0x12,              # type: status_request (18)
        0x00, 0x05,              # length: 5
        0x01,                    # status type: ocsp (1)
        0x00, 0x00,              # responder ID list: empty
        0x00, 0x00,              # request extensions: empty
    ])

    # supported_groups (elliptic_curves)
    supported_groups_ext = bytes([
        0x00, 0x0a,              # type: supported_groups
        0x00, 0x08,              # length: 8
        0x00, 0x06,              # list length: 6
        0x00, 0x1d,              # x25519
        0x00, 0x17,              # secp256r1
        0x00, 0x18,              # secp384r1
    ])

    # ec_point_formats
    ec_point_ext = bytes([
        0x00, 0x0b,              # type: ec_point_formats
        0x00, 0x02,              # length: 2
        0x01,                    # list length: 1
        0x00,                    # uncompressed
    ])

    # signature_algorithms
    sig_algs_ext = bytes([
        0x00, 0x0d,              # type: signature_algorithms
        0x00, 0x0c,              # length: 12
        0x00, 0x0a,              # list length: 10
        0x04, 0x01,              # rsa_pkcs1_sha256
        0x04, 0x03,              # ecdsa_secp256r1_sha256
        0x05, 0x01,              # rsa_pkcs1_sha384
        0x06, 0x01,              # rsa_pkcs1_sha512
        0x02, 0x01,              # rsa_pkcs1_sha1
    ])

    extensions = sni_ext + status_request_ext + supported_groups_ext + ec_point_ext + sig_algs_ext

    # ── Собираем ClientHello ──
    hello_body = (
        b"\x03\x03"              # client_version: TLS 1.2
        + client_random
        + session_id
        + cipher_suites
        + compression
        + struct.pack(">H", len(extensions))
        + extensions
    )

    # Handshake header: type=1 (ClientHello) + 3-byte length
    handshake = (
        b"\x01"
        + struct.pack(">I", len(hello_body))[1:]       # 3 bytes
        + hello_body
    )

    # TLS Record: content_type=22 (handshake), version=TLS 1.0, length
    record = (
        b"\x16\x03\x01"
        + struct.pack(">H", len(handshake))
        + handshake
    )
    return record


def _tls_has_ocsp_staple(domain: str, timeout: int = 10) -> bool | None:
    """
    Отправляет raw ClientHello с status_request и проверяет наличие
    CertificateStatus в ответе сервера.

    Возвращает:
      True  — сервер прислал OCSP staple в handshake
      False — сервер не прислал staple (stapling не настроен)
      None  — ошибка соединения / таймаут
    """
    import struct

    try:
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(_build_tls12_client_hello(domain))

            # Читаем ответ — нас интересуют TLS records
            # CertificateStatus — handshake type 22 (0x16)
            # Обычно приходит в одном из первых records после ServerHello
            buf = b""
            deadline = 8  # секунд на чтение

            import time
            t0 = time.monotonic()

            while time.monotonic() - t0 < deadline:
                try:
                    chunk = sock.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                buf += chunk

                # Ищем CertificateStatus message в буфере
                # TLS record: [content_type(1)][version(2)][length(2)][data]
                # Handshake msg: [type(1)][length(3)][data]
                # CertificateStatus: handshake type = 22 (0x16)
                pos = 0
                while pos + 5 <= len(buf):
                    content_type = buf[pos]
                    rec_len      = struct.unpack(">H", buf[pos + 3: pos + 5])[0]

                    if pos + 5 + rec_len > len(buf):
                        break  # record ещё не полностью получен

                    record_data = buf[pos + 5: pos + 5 + rec_len]

                    if content_type == 0x15:  # Alert — сервер отклонил
                        return None

                    if content_type == 0x16:  # Handshake record
                        # Проходим по handshake-сообщениям внутри record
                        hpos = 0
                        while hpos + 4 <= len(record_data):
                            htype  = record_data[hpos]
                            hlen   = struct.unpack(">I", b"\x00" + record_data[hpos + 1: hpos + 4])[0]

                            if htype == 0x16:  # CertificateStatus (22)
                                # Сервер прислал OCSP staple!
                                return True

                            if htype == 0x0b:  # Certificate — значит ServerHello уже прошёл,
                                # но CertificateStatus не было → stapling не поддерживается
                                return False

                            hpos += 4 + hlen

                    pos += 5 + rec_len

                # Если уже видели Certificate и не было staple — выходим
                if b"\x0b" in buf[5:]:  # быстрая эвристика
                    # Проверяем точнее через повторный разбор
                    found_cert       = False
                    found_staple     = False
                    pos2 = 0
                    while pos2 + 5 <= len(buf):
                        ct   = buf[pos2]
                        rlen = struct.unpack(">H", buf[pos2 + 3: pos2 + 5])[0]
                        if pos2 + 5 + rlen > len(buf):
                            break
                        rdata = buf[pos2 + 5: pos2 + 5 + rlen]
                        if ct == 0x16:
                            hpos = 0
                            while hpos + 4 <= len(rdata):
                                ht   = rdata[hpos]
                                hlen = struct.unpack(">I", b"\x00" + rdata[hpos + 1: hpos + 4])[0]
                                if ht == 0x16:
                                    found_staple = True
                                if ht == 0x0b:
                                    found_cert = True
                                hpos += 4 + hlen
                        pos2 += 5 + rlen
                    if found_cert:
                        return found_staple

    except (socket.timeout, ConnectionRefusedError, OSError):
        return None
    except Exception:
        return None

    return None


def check_ocsp(domain: str) -> dict:
    """
    Критерий 6: OCSP Stapling.

    Production-метод (два канала):

    [A] Сырой TLS handshake с status_request extension (RFC 6066):
        Отправляем ClientHello вручную, парсим ответ побайтово.
        Ищем CertificateStatus handshake message (тип 22 / 0x16).
        Это единственный способ проверить именно OCSP STAPLING —
        то есть отдаёт ли сервер staple В TLS HANDSHAKE клиенту.
        Так работают: openssl s_client -status, sslyze, testssl.sh.

    [B] OCSP responder HTTP POST (RFC 6960) — fallback и доп. валидация:
        Если метод A вернул False или None — проверяем что OCSP
        responder доступен и сертификат не отозван.
        Это подтверждает что CA и цепочка валидны, но означает что
        stapling на сервере НЕ настроен.
    """
    result = {
        "ok":        False,
        "stapled":   False,   # staple получен в TLS handshake
        "ocsp_ok":   False,   # OCSP responder подтвердил валидность
        "error":     None,
    }

    # ── Метод A: сырой TLS + status_request ──
    stapled = _tls_has_ocsp_staple(domain)

    if stapled is True:
        result["ok"]      = True
        result["stapled"] = True
        result["ocsp_ok"] = True
        return result

    # ── Метод B: OCSP responder напрямую ──
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization, hashes
        from cryptography.x509 import ocsp as crypto_ocsp
        from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID

        # Получаем сертификат сервера
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(cafile=certifi.where())
        ctx.check_hostname = True
        ctx.verify_mode    = ssl.CERT_REQUIRED

        with socket.create_connection((domain, 443), timeout=10) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=domain) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)

        cert = x509.load_der_x509_certificate(cert_der)

        # AIA → OCSP URL + caIssuers
        try:
            aia = cert.extensions.get_extension_for_oid(
                ExtensionOID.AUTHORITY_INFORMATION_ACCESS
            ).value
        except x509.ExtensionNotFound:
            # Нет AIA — нельзя проверить ни stapling, ни OCSP
            result["error"] = "Сертификат не содержит AIA"
            return result

        ocsp_urls = [d.access_location.value for d in aia
                     if d.access_method == AuthorityInformationAccessOID.OCSP]
        ca_urls   = [d.access_location.value for d in aia
                     if d.access_method == AuthorityInformationAccessOID.CA_ISSUERS]

        if not ocsp_urls:
            result["error"] = "OCSP URL отсутствует в сертификате"
            return result

        # Скачиваем issuer сертификат
        issuer_cert = None
        for ca_url in ca_urls:
            try:
                with httpx.Client(timeout=10, verify=certifi.where()) as client:
                    r = client.get(ca_url, follow_redirects=True)
                raw = r.content
                issuer_cert = (
                    x509.load_pem_x509_certificate(raw)
                    if raw.startswith(b"-----")
                    else x509.load_der_x509_certificate(raw)
                )
                break
            except Exception:
                continue

        if issuer_cert is None:
            result["error"] = "Не удалось получить issuer-сертификат"
            return result

        # Строим и отправляем OCSP запрос
        builder  = crypto_ocsp.OCSPRequestBuilder()
        builder  = builder.add_certificate(cert, issuer_cert, hashes.SHA1())
        ocsp_req = builder.build()

        with httpx.Client(timeout=10, verify=certifi.where()) as client:
            resp = client.post(
                ocsp_urls[0],
                content=ocsp_req.public_bytes(serialization.Encoding.DER),
                headers={"Content-Type": "application/ocsp-request"},
                follow_redirects=True,
            )

        if resp.status_code != 200:
            result["error"] = f"OCSP сервер: HTTP {resp.status_code}"
            return result

        ocsp_resp = crypto_ocsp.load_der_ocsp_response(resp.content)

        if ocsp_resp.response_status == crypto_ocsp.OCSPResponseStatus.SUCCESSFUL:
            cert_status = ocsp_resp.certificate_status
            if cert_status == crypto_ocsp.OCSPCertStatus.GOOD:
                # OCSP responder говорит "хорошо", но staple не в handshake
                result["ocsp_ok"] = True
                result["ok"]      = False   # stapling НЕ настроен на сервере
            elif cert_status == crypto_ocsp.OCSPCertStatus.REVOKED:
                result["error"]   = "Сертификат отозван (REVOKED)"
            else:
                result["error"]   = "OCSP статус: UNKNOWN"
        else:
            result["error"] = f"OCSP ответ: {ocsp_resp.response_status.name}"

    except ssl.SSLCertVerificationError as e:
        result["error"] = f"Ошибка верификации сертификата: {e.reason}"
    except socket.timeout:
        result["error"] = "Таймаут соединения"
    except ImportError:
        result["error"] = "Пакет cryptography не установлен"
    except Exception as e:
        result["error"] = _clean_error(str(e))

    return result


def check_distance(site_lat, site_lon, server_ip: str) -> dict:
    """Критерий 4: Географическое расстояние между сайтом и сервером."""
    result = {
        "ok": False, "distance_km": None,
        "server_country": "?", "server_city": "?", "error": None,
    }
    if site_lat is None or site_lon is None:
        result["error"] = "Нет координат сайта"
        return result

    geo = check_geoip(server_ip)
    if geo["error"] or geo["lat"] is None:
        result["error"] = geo.get("error", "Нет данных GeoIP для сервера")
        return result

    km = haversine_km(site_lat, site_lon, geo["lat"], geo["lon"])
    result.update({
        "ok":             km < 5000,
        "distance_km":    round(km),
        "server_country": geo["country"],
        "server_city":    geo["city"],
    })
    return result


# ──────────────────────────────────────────────
# Основная логика одного домена
# ──────────────────────────────────────────────

def _clean_error(msg: str) -> str:
    """
    Преобразует технические сообщения об ошибках в читаемый вид.
    """
    if not msg:
        return "Неизвестная ошибка"
    # StreamReset
    if "StreamReset" in msg or "stream_id" in msg:
        return "Сервер сбросил соединение (StreamReset)"
    # SSL handshake timeout
    if "handshake operation timed out" in msg:
        return "Таймаут TLS-рукопожатия"
    if "timed out" in msg or "time out" in msg.lower():
        return "Таймаут соединения"
    # Cert errors
    if "CERTIFICATE_VERIFY_FAILED" in msg:
        return "Ошибка проверки сертификата"
    if "TLSV1_UNRECOGNIZED_NAME" in msg:
        return "Сервер не поддерживает SNI для этого домена"
    if "CONNECTION_REFUSED" in msg or "Connection refused" in msg:
        return "Соединение отклонено"
    # Обрезаем слишком длинные технические сообщения
    if len(msg) > 120:
        msg = msg[:117] + "..."
    return msg


def check_domain(domain: str, server_ip: str | None) -> dict:
    """Запускает все проверки для одного домена. Никогда не падает."""
    results = {"domain": domain}

    # DNS
    try:
        with console.status(f"[dim]DNS резолв {domain}...[/dim]"):
            ip = resolve_ip(domain)
        if not ip:
            results["ip"]    = None
            results["fatal"] = "Не удалось резолвить домен"
            return results
        results["ip"] = ip
    except Exception as e:
        results["ip"]    = None
        results["fatal"] = f"DNS ошибка: {_clean_error(str(e))}"
        return results

    # GeoIP
    try:
        with console.status(f"[dim]GeoIP {ip}...[/dim]"):
            results["geo"] = check_geoip(ip)
    except Exception as e:
        results["geo"] = {"ok": False, "country": "?", "country_code": "?",
                          "city": "?", "lat": None, "lon": None,
                          "org": "?", "error": _clean_error(str(e))}

    # TLS + HTTP/2
    try:
        with console.status(f"[dim]TLS handshake {domain}...[/dim]"):
            results["tls"] = check_tls_and_http2(domain)
    except Exception as e:
        results["tls"] = {"tls_version": None, "tls13": False, "http2": False,
                          "alpn": None, "encrypted_handshake": False,
                          "error": _clean_error(str(e))}

    # Редирект
    try:
        with console.status(f"[dim]HTTP запрос {domain}...[/dim]"):
            results["redirect"] = check_redirect(domain)
    except Exception as e:
        results["redirect"] = {"status": "fail", "status_code": None,
                               "final_url": None, "www_redirect": False,
                               "error": _clean_error(str(e))}

    # OCSP
    try:
        with console.status(f"[dim]OCSP stapling {domain}...[/dim]"):
            results["ocsp"] = check_ocsp(domain)
    except Exception as e:
        results["ocsp"] = {"ok": False, "error": _clean_error(str(e))}

    # Расстояние
    if server_ip:
        try:
            with console.status(f"[dim]Расстояние до сервера...[/dim]"):
                results["distance"] = check_distance(
                    results["geo"].get("lat"),
                    results["geo"].get("lon"),
                    server_ip,
                )
        except Exception as e:
            results["distance"] = {"ok": False, "distance_km": None,
                                   "server_country": "?", "server_city": "?",
                                   "error": _clean_error(str(e))}
    else:
        results["distance"] = None

    return results


# ──────────────────────────────────────────────
# Отрисовка результатов
# ──────────────────────────────────────────────

def ok_icon(ok: bool) -> str:
    return "[bold green]✅[/bold green]" if ok else "[bold red]❌[/bold red]"


def warn_icon() -> str:
    return "[bold yellow]⚠️ [/bold yellow]"


def _redir_score(redir: dict) -> float:
    """0.0 / 0.5 / 1.0 для fail / warning / ok."""
    return {"ok": 1.0, "warning": 0.5, "fail": 0.0}.get(redir.get("status", "fail"), 0.0)


def render_results(data: dict):
    domain = data["domain"]
    ip     = data.get("ip", "?")

    if data.get("fatal"):
        console.print(Panel(
            f"[bold red]{data['fatal']}[/bold red]",
            title=f"[bold]{domain}[/bold]",
            border_style="red",
        ))
        return

    geo   = data["geo"]
    tls   = data["tls"]
    redir = data["redirect"]
    ocsp  = data["ocsp"]
    dist  = data.get("distance")

    # ── Подсчёт баллов ──
    scores = [
        float(geo["ok"]),
        float(tls["tls13"]),
        float(tls["http2"]),
        _redir_score(redir),
        float(tls["encrypted_handshake"]),
        float(ocsp["ok"]),
    ]
    if dist is not None:
        scores.append(1.0 if dist.get("ok") else 0.0)

    total      = len(scores)
    passed     = sum(scores)
    passed_str = f"{int(passed)}" if passed == int(passed) else f"{passed:.1f}"
    score_color = (
        "green"  if passed == total else
        "yellow" if passed >= total - 1.5 else
        "red"
    )
    title = (
        f"[bold]{domain}[/bold]  [dim]({ip})[/dim]  "
        f"[{score_color}]{passed_str}/{total} ✅[/{score_color}]"
    )

    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    table.add_column("icon",     width=4)
    table.add_column("критерий", style="bold", min_width=34)
    table.add_column("детали",   style="dim")

    # [1] Вне РФ
    geo_detail = (
        f"{geo['country']} ({geo['country_code']}), {geo['city']}  |  {geo['org']}"
        if not geo["error"] else f"[red]Ошибка: {geo['error']}[/red]"
    )
    table.add_row(ok_icon(geo["ok"]), "[1] Сервер вне РФ", geo_detail)

    # [2a] TLS 1.3
    tls_detail = (
        tls["tls_version"] if tls["tls_version"]
        else (f"[red]Ошибка: {tls['error']}[/red]" if tls["error"] else "нет данных")
    )
    table.add_row(ok_icon(tls["tls13"]), "[2] TLS 1.3", tls_detail)

    # [2b] HTTP/2
    h2_detail = (
        f"[red]Ошибка: {tls['error']}[/red]"
        if (tls["error"] and not tls["tls_version"])
        else f"ALPN: {tls['alpn'] or 'нет'}"
    )
    table.add_row(ok_icon(tls["http2"]), "[2] HTTP/2", h2_detail)

    # [3] Редирект
    if redir["error"]:
        r_icon   = ok_icon(False)
        r_detail = f"[red]Ошибка: {redir['error']}[/red]"
    elif redir["status"] == "ok":
        r_icon   = ok_icon(True)
        r_detail = f"HTTP {redir['status_code']}  →  {redir['final_url']}"
    elif redir["status"] == "warning":
        r_icon   = warn_icon()
        r_detail = (
            f"HTTP {redir['status_code']}  →  {redir['final_url']}  "
            f"[yellow](www ↔ без www — допустимо, но нежелательно)[/yellow]"
        )
    else:
        r_icon   = ok_icon(False)
        r_detail = (
            f"HTTP {redir['status_code']}  →  {redir['final_url']}  [red](смена домена!)[/red]"
            if redir.get("final_url") else "[red]Нет ответа[/red]"
        )
    table.add_row(r_icon, "[3] Нет редиректа на другой домен", r_detail)

    # [4] Расстояние
    if dist is None:
        table.add_row("[dim]⏭️ [/dim]", "[4] Расстояние до сервера", "[dim]пропущено[/dim]")
    elif dist.get("error"):
        table.add_row(
            ok_icon(False), "[4] Расстояние до сервера",
            f"[red]Ошибка: {dist['error']}[/red]",
        )
    else:
        km      = dist["distance_km"]
        color   = "green" if km < 1000 else ("yellow" if km < 3000 else "red")
        d_detail = (
            f"[{color}]{km} км  "
            f"(сайт: {geo['city']}, {geo['country_code']}  →  "
            f"сервер: {dist['server_city']}, {dist['server_country']})[/{color}]"
        )
        table.add_row(ok_icon(dist["ok"]), "[4] Расстояние до сервера", d_detail)

    # [5] Шифрование после Server Hello
    enc_detail = (
        "Гарантировано стандартом RFC 8446 (TLS 1.3)"
        if tls["encrypted_handshake"] else "Требуется TLS 1.3"
    )
    table.add_row(
        ok_icon(tls["encrypted_handshake"]),
        "[5] Шифрование после Server Hello",
        enc_detail,
    )

    # [6] OCSP Stapling
    if ocsp.get("error"):
        ocsp_icon   = ok_icon(False)
        ocsp_detail = f"[red]Ошибка: {ocsp['error']}[/red]"
    elif ocsp.get("stapled"):
        ocsp_icon   = ok_icon(True)
        ocsp_detail = "Stapling активен  [dim](staple получен в TLS handshake)[/dim]"
    elif ocsp.get("ocsp_ok"):
        ocsp_icon   = ok_icon(False)
        ocsp_detail = "[yellow]Stapling не настроен  [dim](OCSP responder доступен, сертификат валиден)[/dim][/yellow]"
    else:
        ocsp_icon   = ok_icon(False)
        ocsp_detail = "Не поддерживается"
    table.add_row(ocsp_icon, "[6] OCSP Stapling", ocsp_detail)

    console.print(Panel(table, title=title, border_style=score_color, padding=(0, 1)))


# ──────────────────────────────────────────────
# Сводная таблица (несколько доменов)
# ──────────────────────────────────────────────

def render_summary(all_results: list[dict]):
    console.rule("[bold]Итоговая сводка[/bold]")
    summary = Table(box=box.ROUNDED, show_header=True, border_style="cyan")
    summary.add_column("Домен",       style="bold")
    summary.add_column("IP")
    summary.add_column("[1]\nвне РФ",  justify="center")
    summary.add_column("[2]\nTLS 1.3", justify="center")
    summary.add_column("[2]\nHTTP/2",  justify="center")
    summary.add_column("[3]\nРедирект",justify="center")
    summary.add_column("[4]\nРасст.",  justify="center")
    summary.add_column("[5]\nШифр.",   justify="center")
    summary.add_column("[6]\nOCSP",    justify="center")
    summary.add_column("Итог",         justify="center")

    for d in all_results:
        if d.get("fatal"):
            summary.add_row(d["domain"], "—", *["[red]ERR[/red]"] * 8)
            continue

        geo   = d["geo"]
        tls   = d["tls"]
        redir = d["redirect"]
        ocsp  = d["ocsp"]
        dist  = d.get("distance")

        def _i(ok): return "✅" if ok else "❌"

        redir_cell = {"ok": "✅", "warning": "⚠️", "fail": "❌"}.get(redir.get("status", "fail"), "❌")
        dist_cell  = "⏭️" if dist is None else _i(dist.get("ok", False))

        scores = [
            float(geo["ok"]), float(tls["tls13"]), float(tls["http2"]),
            _redir_score(redir), float(tls["encrypted_handshake"]), float(ocsp["ok"]),
        ]
        if dist is not None:
            scores.append(1.0 if dist.get("ok") else 0.0)
        total  = len(scores)
        passed = sum(scores)
        passed_str = f"{int(passed)}" if passed == int(passed) else f"{passed:.1f}"
        color  = "green" if passed == total else ("yellow" if passed >= total - 1.5 else "red")

        summary.add_row(
            d["domain"], d.get("ip", "?"),
            _i(geo["ok"]), _i(tls["tls13"]), _i(tls["http2"]),
            redir_cell, dist_cell,
            _i(tls["encrypted_handshake"]), _i(ocsp["ok"]),
            f"[{color}]{passed_str}/{total}[/{color}]",
        )
    console.print(summary)


# ──────────────────────────────────────────────
# Ввод данных
# ──────────────────────────────────────────────

def get_domains_from_input() -> list[str]:
    """Интерактивный ввод доменов."""
    console.print(
        "\n[bold]Введите домены для проверки[/bold] "
        "[dim](по одному, пустая строка — завершить ввод):[/dim]"
    )
    domains = []
    while True:
        try:
            line = input("  > ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not line:
            break
        domains.append(line)
    return domains


def get_server_ip() -> str | None:
    """Запрашивает IP сервера пользователя."""
    console.print(
        "\n[bold]IP-адрес вашего VPN-сервера[/bold] "
        "[dim](Enter — пропустить критерий 4):[/dim]"
    )
    try:
        raw = input("  > ").strip()
    except (EOFError, KeyboardInterrupt):
        return None
    if not raw:
        return None
    try:
        ipaddress.ip_address(raw)
        return raw
    except ValueError:
        console.print(
            f"[yellow]⚠  «{raw}» не является валидным IP-адресом, "
            f"критерий 4 пропущен.[/yellow]"
        )
        return None


def run_session() -> bool:
    """
    Один цикл ввода доменов → проверки → вывода.
    Возвращает True если пользователь хочет повторить, False — выход.
    """
    # Домены: из аргументов CLI (только первый запуск) или интерактивно
    if len(sys.argv) > 1:
        domains   = [normalize_domain(d) for d in sys.argv[1:]]
        server_ip = get_server_ip()
        # После первого запуска сбрасываем argv чтобы следующий цикл был интерактивным
        sys.argv = sys.argv[:1]
    else:
        raw_domains = get_domains_from_input()
        domains     = [normalize_domain(d) for d in raw_domains]
        if not domains:
            console.print("[yellow]Домены не введены.[/yellow]")
            return _ask_repeat()
        server_ip = get_server_ip()

    if server_ip:
        console.print(f"[dim]Сервер: {server_ip}[/dim]")
    else:
        console.print("[dim]Критерий 4 (расстояние) — пропущен.[/dim]")

    console.print()

    all_results = []
    for domain in domains:
        console.rule(f"[bold]{domain}[/bold]")
        data = check_domain(domain, server_ip)
        render_results(data)
        all_results.append(data)

    if len(all_results) > 1:
        render_summary(all_results)

    return _ask_repeat()


def _ask_repeat() -> bool:
    """Спрашивает пользователя: повторить или выйти. Возвращает True = повторить."""
    console.print()
    console.rule("[dim]Что дальше?[/dim]")
    console.print("  [bold cyan]1[/bold cyan]  — Проверить новые домены")
    console.print("  [bold cyan]2[/bold cyan]  — Выход")
    console.print()
    while True:
        try:
            answer = input("  Выбор [1/2]: ").strip()
        except (EOFError, KeyboardInterrupt):
            return False
        if answer == "1":
            return True
        if answer in ("2", "q", "quit", "exit", "выход", ""):
            return False
        console.print("  [yellow]Введите 1 или 2[/yellow]")


# ──────────────────────────────────────────────
# Точка входа
# ──────────────────────────────────────────────

def main():
    console.print(Panel(
        Text("VLESS+Reality  —  Camouflage Site Checker", justify="center", style="bold cyan"),
        subtitle="[dim]Проверяет сайты на пригодность для маскировки VLESS+Reality[/dim]",
        border_style="cyan",
        padding=(1, 4),
    ))

    while True:
        repeat = run_session()
        if not repeat:
            break
        console.print()
        console.rule("[dim]Новая проверка[/dim]")

    console.print("\n[dim]До свидания![/dim]")


if __name__ == "__main__":
    main()
