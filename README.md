# VLESS+Reality — Camouflage Site Checker

Консольная утилита для проверки веб-сайтов на пригодность в качестве камуфляжного адреса для **VLESS+Reality**.

![Windows](https://img.shields.io/badge/Windows-10%2F11-blue?logo=windows)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![License](https://img.shields.io/badge/License-MIT-green)

---

## Что проверяется

| # | Критерий | Описание |
|---|----------|----------|
| 1 | **Сервер вне РФ** | GeoIP-проверка через ip-api.com |
| 2 | **TLS 1.3 + HTTP/2** | Проверка версии TLS и ALPN-протокола |
| 3 | **Нет редиректа на другой домен** | Главная страница отдаётся без смены hostname |
| 4 | **Расстояние до вашего сервера** | Географическое расстояние в км (опционально) |
| 5 | **Шифрование после Server Hello** | Гарантировано TLS 1.3 / RFC 8446 |
| 6 | **OCSP Stapling** | Прямой запрос к OCSP-серверу по RFC 6960 |

> **Про критерий 3:** редирект `www.domain.com ↔ domain.com` считается допустимым, но нежелательным — отображается как ⚠️ предупреждение.

---

## Скачать готовый EXE (Windows)

Перейди в раздел [**Releases**](../../releases) и скачай `checker.exe` из последней версии.
Python **не требуется** — всё включено в один файл.

---

## Запуск

### Готовый EXE (рекомендуется для Windows)

```
checker.exe
```

Или передай домены сразу аргументами:

```
checker.exe google.com github.com apple.com
```

### Из исходников (Python 3.10+)

```bash
# Установить зависимости
pip install -r requirements.txt

# Запустить
python checker.py
python checker.py google.com github.com
```

---

## Пример вывода

```
╭──────────────────────────────────────────────────────╮
│      VLESS+Reality  —  Camouflage Site Checker       │
╰──────────────────────────────────────────────────────╯

Введите домены для проверки (по одному, пустая строка — завершить ввод):
  > www.apple.com
  >

IP-адрес вашего VPN-сервера (Enter — пропустить критерий 4):
  > 47.245.158.145
Сервер: 47.245.158.145

──────────────────────────── www.apple.com ────────────────────────────

╭──────────────────── www.apple.com  (184.24.145.53)  7/7 ✅ ─────────────────────╮
│                                                                                  │
│  ✅  [1] Сервер вне РФ                  Sweden (SE), Stockholm  |  Akamai        │
│  ✅  [2] TLS 1.3                        TLSv1.3                                  │
│  ✅  [2] HTTP/2                         ALPN: h2                                 │
│  ✅  [3] Нет редиректа на другой домен  HTTP 200  →  https://www.apple.com/      │
│  ✅  [4] Расстояние до сервера          6 120 км  (Stockholm → Frankfurt)        │
│  ✅  [5] Шифрование после Server Hello  Гарантировано стандартом RFC 8446        │
│  ✅  [6] OCSP Stapling                  Stapling активен                         │
│                                                                                  │
╰──────────────────────────────────────────────────────────────────────────────────╯

───────────────────────────── Что дальше? ──────────────────────────────
  1  — Проверить новые домены
  2  — Выход

  Выбор [1/2]:
```

---

## Структура репозитория

```
vless-reality-checker/
│
├── checker.py                 # Основной скрипт
│
├── requirements.txt           # Зависимости для запуска из исходников
├── requirements-dev.txt       # Зависимости для разработки (pyinstaller)
│
├── CHANGELOG.md               # История изменений
├── README.md                  # Документация
├── .gitignore
│
└── .github/
    └── workflows/
        └── build.yml          # GitHub Actions: автосборка EXE при релизе
```

---

## Сборка EXE вручную

```bash
pip install -r requirements.txt
pip install pyinstaller

pyinstaller --onefile --name checker --console \
  --collect-all rich \
  --collect-all certifi \
  --collect-all cryptography \
  checker.py

# Результат: dist/checker.exe
```

Автоматическая сборка настроена через **GitHub Actions**.
При создании тега `v*` (например `v1.2.0`) EXE автоматически появляется в Releases:

```bash
git tag v1.2.0
git push origin v1.2.0
```

Также можно запустить сборку вручную через **Actions → Build Windows EXE → Run workflow**.

---

## Зависимости

| Пакет | Назначение |
|-------|-----------|
| `httpx[http2]` | HTTP-запросы с поддержкой HTTP/2 и автоматическим fallback на HTTP/1.1 |
| `rich` | Красивый вывод таблиц и панелей в терминале |
| `certifi` | Актуальные CA-сертификаты (решает CERTIFICATE_VERIFY_FAILED в EXE) |
| `cryptography` | Работа с X.509, построение и разбор OCSP-запросов (RFC 6960) |

---

## Лицензия

MIT
