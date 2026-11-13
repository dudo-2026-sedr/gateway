# Noesphere — прокси (пакет для развёртывания)

Файлов: 39 · размер: 2.5 МБ

> **Начинать отсюда → [`INSTALL.md`](INSTALL.md)** — 14 разделов: пакеты,
> пользователь, окружение, секреты, служба, nginx, DNS, сертификат, консоль,
> проверка и разбор типовых сбоев.

## Что это

Шлюз, который отдаёт чужие модели под именами Claude и OpenAI: имитирует заголовки,
коды ошибок и подписи блоков `thinking`. Слушает `127.0.0.1:8787`, наружу отдаёт
nginx на `api.<ДОМЕН>`. Консоль — `https://api.<ДОМЕН>/admin?key=<ADMIN_KEY>`.

Ротатор бесплатных моделей (`rout`) в этот пакет **не входит** — он отдельный.

## Что внутри

| Раздел | Что это |
|---|---|
| `opt/noesphere/proxy.py` | код шлюза |
| `opt/noesphere/noesphere.db` | база: 1 апстрим, 1 маппинг, 2 клиентских ключа |
| `opt/noesphere/fonts/` | 10 шрифтов консоли (Instrument Serif, Inter, IBM Plex Mono) |
| `opt/noesphere/proxy_test.py` | тесты шлюза |
| `opt/noesphere/tests_mock_upstream.py` | тесты с поддельным апстримом |
| `opt/noesphere/backups/` | снимки конфига, базы и кода за 5 дней |
| `etc/nginx/sites-available/` | виртуалхост `api.<ДОМЕН>` |
| `etc/systemd/system/` | служба + таймеры бэкапа и сертификата |
| `usr/local/bin/` | скрипты бэкапа и выпуска сертификата |
| `req/noesphere.txt` | 19 пакетов для venv |

## Чего внутри НЕТ

* `venv/` — 151 МБ зависимостей, восстанавливаются из `req/noesphere.txt` (шаг 5).
* `__pycache__` и `*.pyc` — кеш байткода.
* TLS-сертификаты — выпускаются заново (шаг 10).
* Файлы `*.db-wal` и `*.db-shm` — снимок базы уже содержит все данные.
* Черновики `proxy.py.bak-*` (10 штук, ~2.9 МБ) — промежуточные версии при
  разработке; все перекрыты текущим `proxy.py`. Убраны, чтобы не путать того,
  кто будет разворачивать. Остались на сервере и в полном архиве.
* Лендинг `noetic` и конфиг основного домена — это не прокси.

## Секреты

В пакете лежат рабочие данные. Перед передачей кому-то ещё посмотрите сами:

* `etc/systemd/system/noesphere.service` — `ADMIN_KEY` (сейчас слабый `dudo_2026`,
  в INSTALL есть шаг со сменой) и `SIGNATURE_SECRET`.
* `opt/noesphere/noesphere.db` — два клиентских ключа (`sk-ant-api03`) и адрес
  апстрима. Ключи апстримов лежат **открытым текстом**, шифрования в базе нет.

Уточнение: `SIGNATURE_SECRET` не шифрует данные, а только подписывает блоки
`thinking`. Менять его можно свободно — сломается лишь проверка подписей в уже
выданных ответах.

## Опись

```
    1714  etc/nginx/sites-available/api.noe.l.cd.conf
     118  etc/systemd/system/noesphere-backup.service
     125  etc/systemd/system/noesphere-backup.timer
     127  etc/systemd/system/noesphere-cert.service
     160  etc/systemd/system/noesphere-cert.timer
    1781  etc/systemd/system/noesphere.service
    3646  opt/noesphere/backups/cfg-2026-09-28.tgz
    3646  opt/noesphere/backups/cfg-2026-09-29.tgz
    4238  opt/noesphere/backups/cfg-2026-09-30.tgz
    4239  opt/noesphere/backups/cfg-2026-10-01.tgz
    4239  opt/noesphere/backups/cfg-2026-10-02.tgz
   45056  opt/noesphere/backups/noesphere-2026-09-28.db
   49152  opt/noesphere/backups/noesphere-2026-09-29.db
   49152  opt/noesphere/backups/noesphere-2026-09-30.db
   49152  opt/noesphere/backups/noesphere-2026-10-01.db
   49152  opt/noesphere/backups/noesphere-2026-10-02.db
  260145  opt/noesphere/backups/proxy-2026-09-28.py
  278907  opt/noesphere/backups/proxy-2026-09-29.py
  285044  opt/noesphere/backups/proxy-2026-09-30.py
  294036  opt/noesphere/backups/proxy-2026-10-01.py
  290086  opt/noesphere/backups/proxy-2026-10-02.py
   13348  opt/noesphere/fonts/ibmplexmono-400-normal-latin-ext.woff2
   14708  opt/noesphere/fonts/ibmplexmono-400-normal-latin.woff2
   13432  opt/noesphere/fonts/ibmplexmono-500-normal-latin-ext.woff2
   14888  opt/noesphere/fonts/ibmplexmono-500-normal-latin.woff2
   12384  opt/noesphere/fonts/instrumentserif-400-italic-latin-ext.woff2
   22128  opt/noesphere/fonts/instrumentserif-400-italic-latin.woff2
   11604  opt/noesphere/fonts/instrumentserif-400-normal-latin-ext.woff2
   21032  opt/noesphere/fonts/instrumentserif-400-normal-latin.woff2
   85068  opt/noesphere/fonts/inter-300-700-normal-latin-ext.woff2
   48256  opt/noesphere/fonts/inter-300-700-normal-latin.woff2
   49152  opt/noesphere/noesphere.db
  290086  opt/noesphere/proxy.py
  281328  opt/noesphere/proxy_test.py
   49152  opt/noesphere/test_protocol.db
    4059  opt/noesphere/tests_mock_upstream.py
     340  req/noesphere.txt
     575  usr/local/bin/noesphere-backup.sh
    1512  usr/local/bin/noesphere-issue-cert.sh
```
