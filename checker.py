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

import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box
from OpenSSL import SSL, crypto

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
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def resolve_ip(domain: str) -> str | None:
    """DNS-резолв домена в IP."""
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None


# ──────────────────────────────────────────────
# Проверки
# ──────────────────────────────────────────────

def check_geoip(ip: str) -> dict:
    """
    Критерий 1: Сервер вне РФ.
    Возвращает dict с полями: ok, country, country_code, city, lat, lon, org
    """
    result = {"ok": False, "country": "?", "country_code": "?",
              "city": "?", "lat": None, "lon": None, "org": "?", "error": None}
    try:
        with httpx.Client(timeout=10) as client:
            r = client.get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon,org")
            data = r.json()
        if data.get("status") == "success":
            result.update({
                "ok": data["countryCode"] != "RU",
                "country": data.get("country", "?"),
                "country_code": data.get("countryCode", "?"),
                "city": data.get("city", "?"),
                "lat": data.get("lat"),
                "lon": data.get("lon"),
                "org": data.get("org", "?"),
            })
        else:
            result["error"] = "ip-api вернул ошибку"
    except Exception as e:
        result["error"] = str(e)
    return result


def check_tls_and_http2(domain: str) -> dict:
    """
    Критерий 2: TLS 1.3 + HTTP/2.
    Критерий 5: шифрование после Server Hello (вытекает из TLS 1.3).
    """
    result = {
        "tls_version": None, "tls13": False,
        "http2": False, "alpn": None,
        "encrypted_handshake": False, "error": None
    }
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        ctx.load_default_certs()

        with socket.create_connection((domain, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                result["tls_version"] = ssock.version()
                result["alpn"] = ssock.selected_alpn_protocol()
                result["tls13"] = ssock.version() == "TLSv1.3"
                result["http2"] = ssock.selected_alpn_protocol() == "h2"
                # В TLS 1.3 всё после Server Hello шифруется — стандарт RFC 8446
                result["encrypted_handshake"] = result["tls13"]
    except Exception as e:
        result["error"] = str(e)
    return result


def check_redirect(domain: str) -> dict:
    """
    Критерий 3: Главная страница без редиректа на другой домен.
    Допускается: http→https того же домена.
    Не допускается: смена hostname.
    """
    result = {
        "ok": False, "status_code": None,
        "final_url": None, "redirect_chain": [],
        "error": None
    }
    try:
        # HTTP/2 клиент, следим за редиректами вручную
        with httpx.Client(
            http2=True,
            timeout=15,
            follow_redirects=True,
            verify=True,
        ) as client:
            r = client.get(f"https://{domain}/")

        result["status_code"] = r.status_code
        result["final_url"] = str(r.url)

        # Собираем цепочку
        chain = [f"https://{domain}/"]
        for hist in r.history:
            chain.append(str(hist.url))
        chain.append(str(r.url))
        result["redirect_chain"] = chain

        final_host = urlparse(str(r.url)).netloc.lower().split(":")[0]
        origin_host = domain.lower()

        # Допускаем www.<domain> → <domain> и обратно? Нет — строгая проверка.
        result["ok"] = (final_host == origin_host) and (r.status_code < 400)

    except Exception as e:
        result["error"] = str(e)
    return result


def check_ocsp(domain: str) -> dict:
    """
    Критерий 6: OCSP Stapling через pyOpenSSL.
    """
    result = {"ok": False, "error": None}
    try:
        ctx = SSL.Context(SSL.TLS_CLIENT_METHOD)
        ctx.set_ocsp_client_callback(lambda conn, data: True)
        ctx.load_verify_locations(cafile=None, capath=None)

        sock = socket.create_connection((domain, 443), timeout=10)
        conn = SSL.Connection(ctx, sock)
        conn.set_tlsext_host_name(domain.encode())
        conn.request_ocsp()
        conn.set_connect_state()
        conn.do_handshake()

        ocsp_data = conn.get_tlsext_status_ocsp_resp()
        result["ok"] = ocsp_data is not None
        conn.close()
        sock.close()
    except Exception as e:
        result["error"] = str(e)
    return result


def check_distance(site_lat, site_lon, server_ip: str) -> dict:
    """
    Критерий 4: Географическое расстояние между сайтом и сервером пользователя.
    """
    result = {
        "ok": False, "distance_km": None,
        "server_country": "?", "server_city": "?",
        "error": None
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
        "ok": km < 5000,   # условный порог — выводим цифру, пользователь решает
        "distance_km": round(km),
        "server_country": geo["country"],
        "server_city": geo["city"],
    })
    return result


# ──────────────────────────────────────────────
# Основная логика одного домена
# ──────────────────────────────────────────────

def check_domain(domain: str, server_ip: str | None) -> dict:
    results = {}

    # Резолвим IP сайта
    with console.status(f"[dim]DNS резолв {domain}...[/dim]"):
        ip = resolve_ip(domain)

    if not ip:
        return {"domain": domain, "ip": None, "fatal": "Не удалось резолвить домен"}

    results["domain"] = domain
    results["ip"] = ip

    # GeoIP (критерий 1)
    with console.status(f"[dim]GeoIP {ip}...[/dim]"):
        results["geo"] = check_geoip(ip)

    # TLS + HTTP/2 (критерии 2, 5)
    with console.status(f"[dim]TLS handshake {domain}...[/dim]"):
        results["tls"] = check_tls_and_http2(domain)

    # Редиректы (критерий 3)
    with console.status(f"[dim]HTTP запрос {domain}...[/dim]"):
        results["redirect"] = check_redirect(domain)

    # OCSP (критерий 6)
    with console.status(f"[dim]OCSP stapling {domain}...[/dim]"):
        results["ocsp"] = check_ocsp(domain)

    # Расстояние (критерий 4, опционально)
    if server_ip:
        with console.status(f"[dim]Расстояние до сервера...[/dim]"):
            results["distance"] = check_distance(
                results["geo"].get("lat"),
                results["geo"].get("lon"),
                server_ip
            )
    else:
        results["distance"] = None

    return results


# ──────────────────────────────────────────────
# Отрисовка результатов
# ──────────────────────────────────────────────

def ok_icon(ok: bool) -> str:
    return "[bold green]✅[/bold green]" if ok else "[bold red]❌[/bold red]"


def render_results(data: dict):
    domain = data["domain"]
    ip = data.get("ip", "?")

    if data.get("fatal"):
        console.print(Panel(
            f"[bold red]{data['fatal']}[/bold red]",
            title=f"[bold]{domain}[/bold]",
            border_style="red"
        ))
        return

    geo = data["geo"]
    tls = data["tls"]
    redir = data["redirect"]
    ocsp = data["ocsp"]
    dist = data.get("distance")

    # Подсчёт пройденных критериев
    checks = [
        geo["ok"],
        tls["tls13"],
        tls["http2"],
        redir["ok"],
        tls["encrypted_handshake"],  # критерий 5
        ocsp["ok"],
    ]
    if dist is not None:
        checks.append(dist["ok"])

    passed = sum(checks)
    total = len(checks)

    # Заголовок панели
    score_color = "green" if passed == total else ("yellow" if passed >= total - 2 else "red")
    title = f"[bold]{domain}[/bold]  [dim]({ip})[/dim]  [{score_color}]{passed}/{total} ✅[/{score_color}]"

    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 1))
    table.add_column("icon", width=3)
    table.add_column("критерий", style="bold")
    table.add_column("детали", style="dim")

    # Критерий 1
    geo_detail = f"{geo['country']} ({geo['country_code']}), {geo['city']}  |  {geo['org']}"
    if geo["error"]:
        geo_detail = f"[red]Ошибка: {geo['error']}[/red]"
    table.add_row(ok_icon(geo["ok"]), "[1] Сервер вне РФ", geo_detail)

    # Критерий 2a — TLS 1.3
    tls_detail = tls["tls_version"] or (f"[red]Ошибка: {tls['error']}[/red]" if tls["error"] else "нет данных")
    table.add_row(ok_icon(tls["tls13"]), "[2] TLS 1.3", tls_detail)

    # Критерий 2b — HTTP/2
    h2_detail = f"ALPN: {tls['alpn'] or 'нет'}"
    if tls["error"] and not tls["tls_version"]:
        h2_detail = f"[red]Ошибка: {tls['error']}[/red]"
    table.add_row(ok_icon(tls["http2"]), "[2] HTTP/2", h2_detail)

    # Критерий 3
    if redir["error"]:
        redir_detail = f"[red]Ошибка: {redir['error']}[/red]"
    else:
        redir_detail = f"HTTP {redir['status_code']}  →  {redir['final_url']}"
        if not redir["ok"] and redir["final_url"]:
            redir_detail += "  [red](смена домена!)[/red]"
    table.add_row(ok_icon(redir["ok"]), "[3] Нет редиректа на другой домен", redir_detail)

    # Критерий 4
    if dist is None:
        table.add_row("[dim]⏭️[/dim]", "[4] Расстояние до сервера", "[dim]пропущено[/dim]")
    elif dist["error"]:
        table.add_row(ok_icon(False), "[4] Расстояние до сервера", f"[red]Ошибка: {dist['error']}[/red]")
    else:
        dist_detail = (
            f"{dist['distance_km']} км  "
            f"(сайт: {geo['city']}, {geo['country_code']}  →  "
            f"сервер: {dist['server_city']}, {dist['server_country']})"
        )
        # Цветовой намёк: < 1000 км = хорошо, 1000–3000 = нормально, > 3000 = далеко
        km = dist["distance_km"]
        if km < 1000:
            dist_detail = f"[green]{dist_detail}[/green]"
        elif km < 3000:
            dist_detail = f"[yellow]{dist_detail}[/yellow]"
        else:
            dist_detail = f"[red]{dist_detail}[/red]"
        table.add_row(ok_icon(dist["ok"]), "[4] Расстояние до сервера", dist_detail)

    # Критерий 5
    enc_detail = (
        "Гарантировано стандартом RFC 8446 (TLS 1.3)"
        if tls["encrypted_handshake"]
        else "Требуется TLS 1.3"
    )
    table.add_row(ok_icon(tls["encrypted_handshake"]), "[5] Шифрование после Server Hello", enc_detail)

    # Критерий 6
    if ocsp["error"]:
        ocsp_detail = f"[red]Ошибка: {ocsp['error']}[/red]"
    else:
        ocsp_detail = "Stapling активен" if ocsp["ok"] else "Не поддерживается"
    table.add_row(ok_icon(ocsp["ok"]), "[6] OCSP Stapling", ocsp_detail)

    console.print(Panel(table, title=title, border_style=score_color, padding=(0, 1)))


# ──────────────────────────────────────────────
# Точка входа
# ──────────────────────────────────────────────

def get_domains_from_input() -> list[str]:
    """Интерактивный ввод доменов."""
    console.print("\n[bold]Введите домены для проверки[/bold] (по одному, пустая строка — завершить):")
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
    console.print("\n[bold]IP-адрес вашего VPN-сервера[/bold] (Enter — пропустить критерий 4):")
    try:
        raw = input("  > ").strip()
    except (EOFError, KeyboardInterrupt):
        return None
    if not raw:
        return None
    # Валидация IP
    try:
        ipaddress.ip_address(raw)
        return raw
    except ValueError:
        console.print(f"[yellow]⚠  «{raw}» не является валидным IP-адресом, критерий 4 пропущен.[/yellow]")
        return None


def main():
    console.print(Panel(
        Text("VLESS+Reality  —  Camouflage Site Checker", justify="center", style="bold cyan"),
        subtitle="[dim]Проверяет сайты на пригодность для маскировки VLESS+Reality[/dim]",
        border_style="cyan",
        padding=(1, 4),
    ))

    # Домены: из аргументов CLI или интерактивно
    if len(sys.argv) > 1:
        domains = [normalize_domain(d) for d in sys.argv[1:]]
    else:
        raw_domains = get_domains_from_input()
        domains = [normalize_domain(d) for d in raw_domains]

    if not domains:
        console.print("[yellow]Не указано ни одного домена. Выход.[/yellow]")
        sys.exit(0)

    # IP сервера
    server_ip = get_server_ip()
    if server_ip:
        console.print(f"[dim]Сервер: {server_ip}[/dim]")
    else:
        console.print("[dim]Критерий 4 (расстояние) — пропущен.[/dim]")

    console.print()

    # Проверяем каждый домен
    all_results = []
    for domain in domains:
        console.rule(f"[bold]{domain}[/bold]")
        data = check_domain(domain, server_ip)
        render_results(data)
        all_results.append(data)

    # Итоговая сводка если доменов > 1
    if len(all_results) > 1:
        console.rule("[bold]Итоговая сводка[/bold]")
        summary = Table(box=box.ROUNDED, show_header=True, border_style="cyan")
        summary.add_column("Домен", style="bold")
        summary.add_column("IP")
        summary.add_column("[1]\nвне РФ", justify="center")
        summary.add_column("[2]\nTLS1.3", justify="center")
        summary.add_column("[2]\nHTTP/2", justify="center")
        summary.add_column("[3]\nРедирект", justify="center")
        summary.add_column("[4]\nРасст.", justify="center")
        summary.add_column("[5]\nШифр.", justify="center")
        summary.add_column("[6]\nOCSP", justify="center")
        summary.add_column("Итог", justify="center")

        for d in all_results:
            if d.get("fatal"):
                summary.add_row(d["domain"], "—", *["[red]ERR[/red]"] * 8)
                continue

            geo = d["geo"]
            tls = d["tls"]
            redir = d["redirect"]
            ocsp = d["ocsp"]
            dist = d.get("distance")

            def icon(ok): return "✅" if ok else "❌"

            dist_cell = "⏭️" if dist is None else icon(dist["ok"])

            checks_row = [
                icon(geo["ok"]),
                icon(tls["tls13"]),
                icon(tls["http2"]),
                icon(redir["ok"]),
                dist_cell,
                icon(tls["encrypted_handshake"]),
                icon(ocsp["ok"]),
            ]
            score_list = [geo["ok"], tls["tls13"], tls["http2"], redir["ok"],
                          tls["encrypted_handshake"], ocsp["ok"]]
            if dist:
                score_list.append(dist["ok"])
            passed = sum(score_list)
            total = len(score_list)
            color = "green" if passed == total else ("yellow" if passed >= total - 2 else "red")

            summary.add_row(
                d["domain"], d.get("ip", "?"),
                *checks_row,
                f"[{color}]{passed}/{total}[/{color}]"
            )

        console.print(summary)

    console.print()
    console.print("[dim]Готово. Нажмите Enter для выхода...[/dim]")
    try:
        input()
    except (EOFError, KeyboardInterrupt):
        pass


if __name__ == "__main__":
    main()
