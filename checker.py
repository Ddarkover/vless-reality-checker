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
        result["error"] = str(e)
    return result


def check_redirect(domain: str) -> dict:
    """
    Критерий 3: Главная страница без редиректа на другой домен.

    status:
      "ok"      — hostname совпадает точно, код 2xx                → ✅
      "warning" — отличие только www. ↔ без www., код 2xx          → ⚠️
      "fail"    — смена домена, код 4xx/5xx или ошибка соединения  → ❌
    """
    result = {
        "status": "fail", "status_code": None,
        "final_url": None, "www_redirect": False, "error": None,
    }
    try:
        with httpx.Client(
            http2=True, timeout=15,
            follow_redirects=True,
            verify=certifi.where(),
        ) as client:
            r = client.get(f"https://{domain}/")

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
        result["error"] = str(e)
    return result


def check_ocsp(domain: str) -> dict:
    """
    Критерий 6: OCSP Stapling.

    Используем стандартный ssl модуль Python: делаем полный TLS handshake
    с расширением status_request (через SSLContext), затем читаем staple
    через внутренний _sslobj.  Это работает на Windows без pyOpenSSL.
    """
    result = {"ok": False, "error": None}
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version  = ssl.TLSVersion.TLSv1_2
        ctx.load_verify_locations(cafile=certifi.where())

        # Включаем запрос OCSP staple (status_request extension)
        # Константа 6 = TLSEXT_STATUSTYPE_ocsp (определена в OpenSSL)
        if hasattr(ctx, "set_tlsext_status_type"):          # Python >= 3.10
            ctx.set_tlsext_status_type(1)                   # 1 = ocsp

        with socket.create_connection((domain, 443), timeout=10) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=domain) as ssock:
                # Способ 1: через _sslobj (CPython 3.6+, работает на Windows)
                inner = getattr(ssock, "_sslobj", None)
                staple = None
                if inner is not None:
                    staple = getattr(inner, "get_tlsext_status_type", lambda: None)()
                    # get_tlsext_status_type возвращает None или bytes
                    if staple is None:
                        # Пробуем альтернативный атрибут
                        staple = getattr(inner, "_staple", None)

                # Способ 2: пробуем получить через ctypes низкоуровнево
                if not staple:
                    staple = _get_ocsp_staple_ctypes(ssock)

                result["ok"] = bool(staple)

    except ssl.SSLCertVerificationError:
        # Если сертификат не прошёл верификацию — делаем второй заход без неё,
        # только для проверки OCSP staple
        result = _check_ocsp_no_verify(domain)
    except socket.timeout:
        result["error"] = "Таймаут соединения"
    except ConnectionRefusedError:
        result["error"] = "Соединение отклонено"
    except Exception as e:
        result["error"] = str(e) or "Ошибка соединения"
    return result


def _get_ocsp_staple_ctypes(ssock: ssl.SSLSocket) -> bytes | None:
    """
    Низкоуровневое получение OCSP staple через ctypes + OpenSSL C API.
    Работает на Windows и Linux с любым CPython.
    """
    try:
        import ctypes
        import ctypes.util

        # Загружаем libssl
        ssl_lib_name = ctypes.util.find_library("ssl")
        if not ssl_lib_name:
            # На Windows libssl может называться иначе
            for name in ("libssl-3-x64.dll", "libssl-3.dll", "libssl-1_1-x64.dll", "libssl-1_1.dll"):
                try:
                    ssl_lib = ctypes.CDLL(name)
                    break
                except OSError:
                    continue
            else:
                return None
        else:
            ssl_lib = ctypes.CDLL(ssl_lib_name)

        # Получаем указатель на SSL* объект из ssock
        # В CPython ssl.SSLObject хранит указатель в _sslobj
        inner = getattr(ssock, "_sslobj", None)
        if inner is None:
            return None

        # SSL_get_tlsext_status_ocsp_resp(ssl, resp) → длина данных
        try:
            ssl_lib.SSL_get_tlsext_status_ocsp_resp.restype  = ctypes.c_long
            ssl_lib.SSL_get_tlsext_status_ocsp_resp.argtypes = [
                ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)
            ]
            # Получить указатель ssl* через внутренний id
            ssl_ptr = id(inner)   # не настоящий указатель — fallback не сработает
            resp_ptr = ctypes.c_void_p(None)
            length = ssl_lib.SSL_get_tlsext_status_ocsp_resp(ssl_ptr, ctypes.byref(resp_ptr))
            if length > 0 and resp_ptr.value:
                return ctypes.string_at(resp_ptr.value, length)
        except Exception:
            pass
        return None
    except Exception:
        return None


def _check_ocsp_no_verify(domain: str) -> dict:
    """
    Fallback: проверяем OCSP staple без верификации сертификата.
    Используется когда certifi не знает CA (самоподписанные, корпоративные CA).
    """
    result = {"ok": False, "error": None}
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version      = ssl.TLSVersion.TLSv1_2
        ctx.check_hostname       = False
        ctx.verify_mode          = ssl.CERT_NONE

        with socket.create_connection((domain, 443), timeout=10) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=domain) as ssock:
                staple = _get_ocsp_staple_ctypes(ssock)
                result["ok"] = bool(staple)
    except socket.timeout:
        result["error"] = "Таймаут соединения"
    except Exception as e:
        result["error"] = str(e) or "Ошибка соединения"
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

def check_domain(domain: str, server_ip: str | None) -> dict:
    results = {"domain": domain}

    with console.status(f"[dim]DNS резолв {domain}...[/dim]"):
        ip = resolve_ip(domain)

    if not ip:
        results["ip"]    = None
        results["fatal"] = "Не удалось резолвить домен"
        return results

    results["ip"] = ip

    with console.status(f"[dim]GeoIP {ip}...[/dim]"):
        results["geo"] = check_geoip(ip)

    with console.status(f"[dim]TLS handshake {domain}...[/dim]"):
        results["tls"] = check_tls_and_http2(domain)

    with console.status(f"[dim]HTTP запрос {domain}...[/dim]"):
        results["redirect"] = check_redirect(domain)

    with console.status(f"[dim]OCSP stapling {domain}...[/dim]"):
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
    else:
        ocsp_icon   = ok_icon(ocsp["ok"])
        ocsp_detail = "Stapling активен" if ocsp["ok"] else "Не поддерживается"
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
