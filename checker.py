#!/usr/bin/env python3
"""
VLESS+Reality Camouflage Site Checker
Проверяет сайты на пригодность для использования в качестве камуфляжа VLESS+Reality.
"""

import sys
import ssl
import socket
import struct
import os
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
    """Убирает www. префикс для сравнения."""
    return host.lower().removeprefix("www.")


def compare_hosts(origin: str, final: str) -> tuple[bool, bool]:
    """
    Сравнивает два hostname.
    Возвращает (exact_match, www_variant):
      exact_match=True  — домены совпадают точно
      www_variant=True  — отличаются только www. префиксом
    """
    o = origin.lower().split(":")[0]
    f = final.lower().split(":")[0]
    exact = (o == f)
    www_v = (not exact) and (strip_www(o) == strip_www(f))
    return exact, www_v


def make_ssl_context() -> ssl.SSLContext:
    """
    Создаёт SSLContext с сертификатами certifi.
    Решает CERTIFICATE_VERIFY_FAILED в PyInstaller на Windows.
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
        result["error"] = str(e)
    return result


def check_redirect(domain: str) -> dict:
    """
    Критерий 3: Главная страница без редиректа на другой домен.

    status:
      "ok"      — hostname совпадает точно, код 2xx         → ✅
      "warning" — отличие только в www. префиксе            → ⚠️
      "fail"    — смена домена или ошибка соединения        → ❌
    """
    result = {
        "status": "fail",
        "status_code": None,
        "final_url": None,
        "redirect_chain": [],
        "www_redirect": False,
        "error": None,
    }
    try:
        with httpx.Client(
            http2=True,
            timeout=15,
            follow_redirects=True,
            verify=certifi.where(),
        ) as client:
            r = client.get(f"https://{domain}/")

        result["status_code"] = r.status_code
        result["final_url"]   = str(r.url)

        chain = [f"https://{domain}/"]
        for hist in r.history:
            chain.append(str(hist.url))
        chain.append(str(r.url))
        result["redirect_chain"] = chain

        final_host  = urlparse(str(r.url)).netloc
        exact, www_v = compare_hosts(domain, final_host)

        if exact and r.status_code < 400:
            result["status"] = "ok"
        elif www_v and r.status_code < 400:
            result["status"]       = "warning"
            result["www_redirect"] = True
        else:
            result["status"] = "fail"

    except Exception as e:
        result["error"] = str(e)
    return result


def check_ocsp(domain: str) -> dict:
    """
    Критерий 6: OCSP Stapling.

    Метод: делаем полноценный TLS-handshake через ssl с расширением
    status_request. После handshake читаем сырой буфер соединения и
    ищем TLS-запись типа CertificateStatus (handshake msg type = 22).

    Почему не pyOpenSSL: ненадёжен на Windows в PyInstaller-сборке.
    Почему не сырой ClientHello: сервер вправе игнорировать
    незавершённый handshake и не присылать CertificateStatus.
    Полноценный handshake через ssl + перехват ServerHello-записей
    через BIO-callback — самый надёжный способ без сторонних библиотек.
    """
    result = {"ok": False, "error": None}

    # --- Строим ClientHello вручную с расширением status_request ---
    # и шлём его сырым сокетом, затем читаем ответ до конца handshake.

    try:
        raw_sock = socket.create_connection((domain, 443), timeout=10)
    except Exception as e:
        result["error"] = str(e)
        return result

    try:
        # ClientHello с расширением status_request (OCSP)
        client_hello = _build_client_hello_with_ocsp(domain)
        raw_sock.sendall(client_hello)

        # Читаем ответ сервера — нам нужны записи до CertificateStatus
        # или до тех пор пока не получим ServerHelloDone / EncryptedExtensions
        buf = _recv_tls_records(raw_sock, timeout=8, max_bytes=65536)
        result["ok"] = _has_certificate_status(buf)

    except socket.timeout:
        result["error"] = "Таймаут"
    except Exception as e:
        result["error"] = str(e)
    finally:
        try:
            raw_sock.close()
        except Exception:
            pass

    return result


def _build_client_hello_with_ocsp(domain: str) -> bytes:
    """
    Строит минимальный TLS ClientHello с расширением status_request.
    Поддерживает TLS 1.2 / 1.3, SNI, ALPN h2.
    """
    random_bytes = os.urandom(32)
    session_id   = b""

    # Cipher suites
    ciphers = b"".join([
        b"\x13\x01",  # TLS_AES_128_GCM_SHA256        (TLS 1.3)
        b"\x13\x02",  # TLS_AES_256_GCM_SHA384        (TLS 1.3)
        b"\x13\x03",  # TLS_CHACHA20_POLY1305_SHA256   (TLS 1.3)
        b"\xc0\x2b",  # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        b"\xc0\x2f",  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        b"\xc0\x2c",  # TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        b"\xc0\x30",  # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    ])

    def ext(typ: int, body: bytes) -> bytes:
        return struct.pack(">HH", typ, len(body)) + body

    sni_name = domain.encode()
    sni_body = struct.pack(">H", len(sni_name) + 3) + b"\x00" + struct.pack(">H", len(sni_name)) + sni_name
    e_sni    = ext(0x0000, sni_body)                                  # server_name

    e_ocsp   = ext(0x0012, b"\x01\x00\x00\x00\x00")                  # status_request

    groups   = b"\x00\x1d\x00\x17\x00\x18"                           # x25519, secp256r1, secp384r1
    e_groups = ext(0x000a, struct.pack(">H", len(groups)) + groups)   # supported_groups

    e_ecpf   = ext(0x000b, b"\x01\x00")                              # ec_point_formats

    alpn_val = b"\x00\x02h2"
    e_alpn   = ext(0x0010, struct.pack(">H", len(alpn_val)) + alpn_val)  # ALPN

    sig_algs = b"\x04\x01\x05\x01\x06\x01\x08\x04\x08\x05\x08\x06\x04\x03\x05\x03\x06\x03"
    e_sig    = ext(0x000d, struct.pack(">H", len(sig_algs)) + sig_algs)  # signature_algorithms

    e_ver    = ext(0x002b, b"\x02\x03\x04")                           # supported_versions: TLS 1.3

    key_share_x25519 = os.urandom(32)
    ks_entry = b"\x00\x1d" + struct.pack(">H", len(key_share_x25519)) + key_share_x25519
    e_ks     = ext(0x0033, struct.pack(">H", len(ks_entry)) + ks_entry)  # key_share

    extensions = e_sni + e_ocsp + e_groups + e_ecpf + e_alpn + e_sig + e_ver + e_ks

    hello_body = (
        b"\x03\x03"                                          # legacy version TLS 1.2
        + random_bytes
        + struct.pack(">B", len(session_id)) + session_id
        + struct.pack(">H", len(ciphers)) + ciphers
        + b"\x01\x00"                                        # compression: none
        + struct.pack(">H", len(extensions)) + extensions
    )

    # Handshake record: type=1 (ClientHello)
    hs = b"\x01" + struct.pack(">I", len(hello_body))[1:] + hello_body
    # TLS record: type=22, version=TLS 1.0 (0x0301)
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


def _recv_tls_records(sock: socket.socket, timeout: float, max_bytes: int) -> bytes:
    """Читает TLS-записи из сокета до таймаута или лимита байт."""
    sock.settimeout(timeout)
    buf = b""
    try:
        while len(buf) < max_bytes:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
            # Останавливаемся если видим ServerHelloDone (TLS 1.2: 0x0e)
            # или первую зашифрованную запись (TLS 1.3: ApplicationData type=23 = 0x17)
            if _is_handshake_complete(buf):
                break
    except socket.timeout:
        pass
    return buf


def _is_handshake_complete(buf: bytes) -> bool:
    """
    Возвращает True если в буфере уже есть сигнал конца handshake:
    - TLS 1.2: ServerHelloDone (handshake type 14 = 0x0e)
    - TLS 1.3: первая зашифрованная запись (ChangeCipherSpec + ApplicationData)
    """
    offset = 0
    found_ccs = False
    while offset + 5 <= len(buf):
        rec_type = buf[offset]
        length   = struct.unpack(">H", buf[offset + 3:offset + 5])[0]
        payload  = buf[offset + 5: offset + 5 + length]

        if rec_type == 20:  # ChangeCipherSpec
            found_ccs = True
        if rec_type == 23 and found_ccs:  # ApplicationData после CCS → TLS 1.3 encrypted
            return True
        if rec_type == 22 and payload and payload[0] == 14:  # ServerHelloDone (TLS 1.2)
            return True

        offset += 5 + length
    return False


def _has_certificate_status(buf: bytes) -> bool:
    """
    Ищет в потоке TLS-записей сообщение CertificateStatus (handshake type = 22 = 0x16).
    Возвращает True если staple присутствует.
    """
    offset = 0
    while offset + 5 <= len(buf):
        rec_type = buf[offset]
        length   = struct.unpack(">H", buf[offset + 3:offset + 5])[0]
        payload_start = offset + 5
        payload_end   = payload_start + length

        if payload_end > len(buf):
            break

        if rec_type == 22 and length > 0:           # Handshake record
            msg_type = buf[payload_start]
            if msg_type == 22:                       # CertificateStatus
                return True

        offset = payload_end
    return False
    result = {
        "ok": False, "distance_km": None,
        "server_country": "?", "server_city": "?", "error": None,
    }
    if site_lat is None or site_lon is None:
        result["error"] = "Нет координат сайта"
        return result

    geo = check_geoip(server_ip)
    if geo["error"] or geo["lat"] is None:
        result["error"] = geo.get("error", "Нет GeoIP-данных для сервера")
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

def check_domain(domain: str, server_ip: str | None) -> dict:
    results = {}

    with console.status(f"[dim]DNS резолв {domain}...[/dim]"):
        ip = resolve_ip(domain)

    if not ip:
        return {"domain": domain, "ip": None, "fatal": "Не удалось резолвить домен"}

    results["domain"] = domain
    results["ip"]     = ip

    with console.status(f"[dim]GeoIP {ip}...[/dim]"):
        results["geo"] = check_geoip(ip)

    with console.status(f"[dim]TLS handshake {domain}...[/dim]"):
        results["tls"] = check_tls_and_http2(domain)

    with console.status(f"[dim]HTTP запрос {domain}...[/dim]"):
        results["redirect"] = check_redirect(domain)

    with console.status(f"[dim]OCSP Stapling {domain}...[/dim]"):
        results["ocsp"] = check_ocsp(domain)

    if server_ip:
        with console.status(f"[dim]Расстояние до сервера...[/dim]"):
            results["distance"] = check_distance(
                results["geo"].get("lat"),
                results["geo"].get("lon"),
                server_ip,
            )
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
    ocsp  = data.get("ocsp", {"ok": False, "error": "нет данных"})
    dist  = data.get("distance")

    redir_ok   = redir["status"] == "ok"
    redir_warn = redir["status"] == "warning"

    score_checks = [
        geo["ok"], tls["tls13"], tls["http2"],
        redir_ok,
        tls["encrypted_handshake"],
        ocsp["ok"],
    ]
    if dist is not None:
        score_checks.append(dist["ok"])

    passed = sum(score_checks)
    total  = len(score_checks)
    passed_display = f"{passed}.5/{total}" if redir_warn else f"{passed}/{total}"

    score_color = (
        "green"  if passed == total and not redir_warn else
        "yellow" if passed >= total - 2 else
        "red"
    )
    title = (
        f"[bold]{domain}[/bold]  [dim]({ip})[/dim]  "
        f"[{score_color}]{passed_display} ✅[/{score_color}]"
    )

    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    table.add_column("icon",     width=4)
    table.add_column("критерий", style="bold")
    table.add_column("детали",   style="dim")

    # [1] Сервер вне РФ
    geo_detail = f"{geo['country']} ({geo['country_code']}), {geo['city']}  |  {geo['org']}"
    if geo["error"]:
        geo_detail = f"[red]Ошибка: {geo['error']}[/red]"
    table.add_row(ok_icon(geo["ok"]), "[1] Сервер вне РФ", geo_detail)

    # [2] TLS 1.3
    tls_detail = tls["tls_version"] or (
        f"[red]Ошибка: {tls['error']}[/red]" if tls["error"] else "нет данных"
    )
    table.add_row(ok_icon(tls["tls13"]), "[2] TLS 1.3", tls_detail)

    # [2] HTTP/2
    h2_detail = f"ALPN: {tls['alpn'] or 'нет'}"
    if tls["error"] and not tls["tls_version"]:
        h2_detail = f"[red]Ошибка: {tls['error']}[/red]"
    table.add_row(ok_icon(tls["http2"]), "[2] HTTP/2", h2_detail)

    # [3] Редирект
    if redir["error"]:
        row_icon     = ok_icon(False)
        redir_detail = f"[red]Ошибка: {redir['error']}[/red]"
    elif redir["status"] == "ok":
        row_icon     = ok_icon(True)
        redir_detail = f"HTTP {redir['status_code']}  →  {redir['final_url']}"
    elif redir["status"] == "warning":
        row_icon     = warn_icon()
        redir_detail = (
            f"HTTP {redir['status_code']}  →  {redir['final_url']}  "
            f"[yellow](www ↔ без www — допустимо, но нежелательно)[/yellow]"
        )
    else:
        row_icon     = ok_icon(False)
        redir_detail = (
            f"HTTP {redir['status_code']}  →  {redir['final_url']}  "
            f"[red](смена домена!)[/red]"
            if redir["final_url"] else "[red]Нет ответа[/red]"
        )
    table.add_row(row_icon, "[3] Нет редиректа на другой домен", redir_detail)

    # [4] Расстояние
    if dist is None:
        table.add_row("[dim]⏭️ [/dim]", "[4] Расстояние до сервера", "[dim]пропущено[/dim]")
    elif dist["error"]:
        table.add_row(
            ok_icon(False), "[4] Расстояние до сервера",
            f"[red]Ошибка: {dist['error']}[/red]",
        )
    else:
        km = dist["distance_km"]
        dist_detail = (
            f"{km} км  "
            f"(сайт: {geo['city']}, {geo['country_code']}  →  "
            f"сервер: {dist['server_city']}, {dist['server_country']})"
        )
        if km < 1000:
            dist_detail = f"[green]{dist_detail}[/green]"
        elif km < 3000:
            dist_detail = f"[yellow]{dist_detail}[/yellow]"
        else:
            dist_detail = f"[red]{dist_detail}[/red]"
        table.add_row(ok_icon(dist["ok"]), "[4] Расстояние до сервера", dist_detail)

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
        ocsp_detail = f"[red]Ошибка: {ocsp['error']}[/red]"
    else:
        ocsp_detail = "Stapling активен" if ocsp["ok"] else "Не поддерживается"
    table.add_row(ok_icon(ocsp["ok"]), "[6] OCSP Stapling", ocsp_detail)

    console.print(Panel(table, title=title, border_style=score_color, padding=(0, 1)))


# ──────────────────────────────────────────────
# Сводная таблица (несколько доменов)
# ──────────────────────────────────────────────

def render_summary(all_results: list[dict]):
    console.rule("[bold]Итоговая сводка[/bold]")
    summary = Table(box=box.ROUNDED, show_header=True, border_style="cyan")
    summary.add_column("Домен",         style="bold")
    summary.add_column("IP")
    summary.add_column("[1]\nвне РФ",   justify="center")
    summary.add_column("[2]\nTLS 1.3",  justify="center")
    summary.add_column("[2]\nHTTP/2",   justify="center")
    summary.add_column("[3]\nРедирект", justify="center")
    summary.add_column("[4]\nРасст.",   justify="center")
    summary.add_column("[5]\nШифр.",    justify="center")
    summary.add_column("[6]\nOCSP",     justify="center")
    summary.add_column("Итог",          justify="center")

    def icon(ok: bool) -> str:
        return "✅" if ok else "❌"

    for d in all_results:
        if d.get("fatal"):
            summary.add_row(d["domain"], "—", *["[red]ERR[/red]"] * 8)
            continue

        geo   = d["geo"]
        tls   = d["tls"]
        redir = d["redirect"]
        ocsp  = d.get("ocsp", {"ok": False})
        dist  = d.get("distance")

        redir_ok   = redir["status"] == "ok"
        redir_warn = redir["status"] == "warning"
        redir_cell = "✅" if redir_ok else ("⚠️" if redir_warn else "❌")
        dist_cell  = "⏭️" if dist is None else icon(dist.get("ok", False))

        score_list = [
            geo["ok"], tls["tls13"], tls["http2"],
            redir_ok, tls["encrypted_handshake"], ocsp["ok"],
        ]
        if dist and not dist.get("error"):
            score_list.append(dist["ok"])

        passed = sum(score_list)
        total  = len(score_list)
        passed_display = f"{passed}.5/{total}" if redir_warn else f"{passed}/{total}"
        color = (
            "green"  if passed == total and not redir_warn else
            "yellow" if passed >= total - 2 else
            "red"
        )

        summary.add_row(
            d["domain"], d.get("ip", "?"),
            icon(geo["ok"]),
            icon(tls["tls13"]),
            icon(tls["http2"]),
            redir_cell,
            dist_cell,
            icon(tls["encrypted_handshake"]),
            icon(ocsp["ok"]),
            f"[{color}]{passed_display}[/{color}]",
        )

    console.print(summary)


# ──────────────────────────────────────────────
# Ввод данных
# ──────────────────────────────────────────────

def get_domains_from_input() -> list[str]:
    console.print(
        "\n[bold]Введите домены для проверки[/bold] "
        "[dim](по одному, пустая строка — начать проверку):[/dim]"
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
            f"[yellow]⚠  «{raw}» — не валидный IP-адрес, критерий 4 пропущен.[/yellow]"
        )
        return None


# ──────────────────────────────────────────────
# Главный цикл
# ──────────────────────────────────────────────

def run_checks(first_run: bool = True):
    """Один полный цикл ввода и проверки."""
    if first_run and len(sys.argv) > 1:
        domains = [normalize_domain(d) for d in sys.argv[1:]]
    else:
        raw = get_domains_from_input()
        domains = [normalize_domain(d) for d in raw]

    if not domains:
        console.print("[yellow]Не указано ни одного домена.[/yellow]")
        return

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


def main():
    console.print(Panel(
        Text("VLESS+Reality  —  Camouflage Site Checker", justify="center", style="bold cyan"),
        subtitle="[dim]Проверяет сайты на пригодность для маскировки VLESS+Reality[/dim]",
        border_style="cyan",
        padding=(1, 4),
    ))

    first_run = True
    while True:
        run_checks(first_run=first_run)
        first_run = False

        # ── Меню после завершения ──
        console.print()
        console.rule("[dim]Проверка завершена[/dim]")
        console.print(
            "\n"
            "  [bold cyan][1][/bold cyan]  Проверить новые домены\n"
            "  [bold cyan][2][/bold cyan]  Выход\n"
        )
        try:
            choice = input("  Ваш выбор (1/2): ").strip()
        except (EOFError, KeyboardInterrupt):
            break

        if choice == "1":
            console.print()
            continue
        else:
            break

    console.print("\n[dim]До свидания![/dim]\n")


if __name__ == "__main__":
    main()
