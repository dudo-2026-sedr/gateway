# Установка Noesphere (только прокси)

Пошаговое развёртывание шлюза Noesphere на новом сервере. Только прокси —
ротатор `rout` в этот пакет не входит.

Рассчитано на **чистый сервер**, все команды от root. Порядок важен:
служба → nginx → DNS → сертификат → настройка в консоли.

Проверено на: **Ubuntu 24.04.4 LTS, Python 3.12, nginx 1.24, sqlite 3.45**.

**О путях.** Все относительные пути (`opt/...`, `req/...`, `etc/...`) указаны от корня
распакованной папки `proxy/` — это тот каталог, где лежат `INSTALL.md` и `README.md`.
Перед началом перейдите в него:

```bash
cd proxy        # или как вы назвали папку после распаковки
```

Дальше везде предполагается, что вы находитесь в нём.

---

## 0. Что это

**Noesphere** — шлюз, который отдаёт чужие модели под именами Claude и OpenAI.
Он не хранит моделей у себя: запрос уходит на апстрим (любой OpenAI-совместимый),
а наружу ответ отдаётся с антроповскими или опенаевскими заголовками, кодами
ошибок и подписями блоков `thinking` — так, что клиент не отличает его от оригинала.

| Параметр | Значение |
|---|---|
| Порт | `8787`, слушает только `127.0.0.1` |
| Наружу | отдаёт nginx на `api.<ДОМЕН>` |
| Консоль | `https://api.<ДОМЕН>/admin?key=<ADMIN_KEY>` |
| Стек | FastAPI + uvicorn |

Что уже лежит в базе пакета (работает сразу после установки):

* апстрим `newapi` → `https://new-api-production-44f4.up.railway.app`, **ключ не требуется**;
* маппинг `claude-opus-5` → `claude-opus-5`, `owned_by=Anthropic`;
* два клиентских ключа в формате `sk-ant-api03` (заметки «Тест» и «Раздача 1»).

---

## 1. Что нужно от вас

| Что | Пример | Комментарий |
|---|---|---|
| `<ДОМЕН>` | `example.com` | ваш домен |
| `<IP>` | `203.0.113.10` | публичный IP этого сервера |
| `<EMAIL>` | `admin@example.com` | для сертификата |

Дальше в командах меняйте `noe.l.cd` на `<ДОМЕН>`, а `api.noe.l.cd` — на `api.<ДОМЕН>`.

DNS-запись нужна одна, создайте заранее (шаг 7):

```
api.<ДОМЕН>   A   <IP>
```

Поддомен `api` можно взять любой — тогда поменяйте его в `server_name` конфига nginx
и в сертификате.

---

## 2. Пакеты

```bash
apt update
apt install -y nginx-extras sqlite3 certbot python3-venv python3-pip curl jq dnsutils ca-certificates
```

**`nginx-extras` обязателен, а не «желателен».** Конфиг использует
`more_set_headers "Server: cloudflare"` — это директива модуля headers-more, которого
в обычном пакете `nginx` нет. С обычным nginx `nginx -t` упадёт с
`unknown directive "more_set_headers"`, и nginx не поднимется.

Проверьте, что модуль на месте:

```bash
nginx -V 2>&1 | tr ' ' '\n' | grep headers-more
```

## 3. Пользователь и каталоги

```bash
useradd --system --no-create-home --shell /usr/sbin/nologin noesphere || true
mkdir -p /opt/noesphere /var/www/html
chown -R noesphere:noesphere /opt/noesphere
```

## 4. Файлы

Из корня распакованного архива:

```bash
tar czf - opt etc usr | tar xzf - -C /
chmod +x /usr/local/bin/noesphere-backup.sh /usr/local/bin/noesphere-issue-cert.sh
chown -R noesphere:noesphere /opt/noesphere
```

Должны появиться:

* `/opt/noesphere/proxy.py` — сам шлюз;
* `/opt/noesphere/noesphere.db` — база: апстримы, маппинги, клиентские ключи;
* `/opt/noesphere/fonts/` — 10 файлов шрифтов для консоли;
* `/opt/noesphere/proxy_test.py`, `tests_mock_upstream.py`, `test_protocol.db` — тесты;
* `/opt/noesphere/backups/` — история снимков (конфиг, база, код за 5 дней);
* `/etc/nginx/sites-available/api.noe.l.cd.conf`;
* `/etc/systemd/system/noesphere*.service|timer` — 5 юнитов;
* `/usr/local/bin/noesphere-backup.sh`, `noesphere-issue-cert.sh`.

## 5. Окружение Python

venv в архив не входит — 19 пакетов восстанавливаются из списка:

```bash
python3 -m venv /opt/noesphere/venv
/opt/noesphere/venv/bin/pip install -q --upgrade pip
/opt/noesphere/venv/bin/pip install -q -r req/noesphere.txt
chown -R noesphere:noesphere /opt/noesphere/venv
```

`pip install` удобнее от root, а `chown` — после, иначе pip не сможет писать кеш.

## 6. Секреты

В юните уже лежат значения с прошлого сервера. Разберитесь с каждым:

| Переменная | Что делать |
|---|---|
| `ADMIN_KEY` | **смените** — старый (`dudo_2026`) слабый и теперь публичен |
| `SIGNATURE_SECRET` | можно менять свободно, см. ниже |

```bash
NEW_ADMIN=$(openssl rand -hex 16)
sed -i "s/^Environment=ADMIN_KEY=.*/Environment=ADMIN_KEY=$NEW_ADMIN/" \
  /etc/systemd/system/noesphere.service
echo "новый ADMIN_KEY: $NEW_ADMIN"     # сохраните, он нужен для входа в консоль
```

Про `SIGNATURE_SECRET` важное уточнение: он **не шифрует** данные в базе. Ключи
апстримов лежат в `noesphere.db` открытым текстом, а `SIGNATURE_SECRET` используется
только как HMAC-ключ для подписей блоков `thinking`. Поэтому его можно менять
свободно — сломается лишь проверка подписей в уже выданных ответах.

## 7. Запуск службы

```bash
systemctl daemon-reload
systemctl enable --now noesphere
sleep 5
systemctl is-active noesphere      # ожидаем: active
curl -s http://127.0.0.1:8787/health
```

`/health` должен вернуть `{"status":"ok",...}`. Если пусто —
`journalctl -u noesphere -n 50 --no-pager`.

Служба работает от пользователя `noesphere`, поэтому права на `/opt/noesphere`
и `venv` должны принадлежать ему (шаги 4 и 5).

## 8. nginx

В конфиге захардкожен старый домен. Замените:

```bash
cd /etc/nginx/sites-available
sed -i 's/api\.noe\.l\.cd/api.<ДОМЕН>/g' api.noe.l.cd.conf
mv api.noe.l.cd.conf api.<ДОМЕН>.conf
```

Что ещё проверить внутри файла:

* **`ssl_certificate` / `ssl_certificate_key`** — указывают на
  `/etc/ssl/certs/noe.l.cd.fullchain.pem` и `/etc/ssl/private/noe.l.cd.key`.
  Оставьте эти пути и положите сертификат туда (так делает скрипт в архиве),
  либо поправьте пути под свои.
* **`proxy_pass http://127.0.0.1:8787;`** — порт службы, менять не нужно.
* **`proxy_buffering off;`** — критично для SSE: с буферизацией ответы приходят
  рывками в конце, а не потоком.
* **`client_max_body_size 128m;`** — для загрузки файлов в консоль.

Включите сайт и уберите дефолтную заглушку:

```bash
rm -f /etc/nginx/sites-enabled/default
ln -sf /etc/nginx/sites-available/api.<ДОМЕН>.conf /etc/nginx/sites-enabled/
nginx -t
systemctl reload nginx
```

## 9. DNS

Создайте запись из шага 1. Если домен на Cloudflare — **выключите проксирование
(оранжевое облако)**: сертификат выпускается через HTTP-01, прокси может помешать.

Проверять распространение надёжнее через DNS-over-HTTPS, а не через `dig`: на части
хостов исходящий UDP/53 закрыт, и `dig` молчит даже на живых доменах.

```bash
curl -s -H 'accept: application/dns-json' \
  "https://cloudflare-dns.com/dns-query?name=api.<ДОМЕН>&type=A" | jq -r '.Answer[]?.data'
```

## 10. Сертификат

Конфиг уже содержит `location /.well-known/acme-challenge/ { root /var/www/html; }`,
поэтому подходит проверка через webroot. Два пути — выберите один.

**A. acme.sh + ZeroSSL** — так был выдан сертификат на исходном сервере:

```bash
curl -s https://get.acme.sh | sh -s email=<EMAIL>
~/.acme.sh/acme.sh --register-account -m <EMAIL> --server zerossl

~/.acme.sh/acme.sh --issue --server zerossl \
  -d api.<ДОМЕН> --webroot /var/www/html --keylength ec-256

~/.acme.sh/acme.sh --install-cert -d api.<ДОМЕН> --ecc \
  --key-file       /etc/ssl/private/<ДОМЕН>.key \
  --fullchain-file /etc/ssl/certs/<ДОМЕН>.fullchain.pem \
  --reloadcmd      "systemctl reload nginx"
```

Почему ZeroSSL, а не Let's Encrypt: у Let's Encrypt лимит 50 сертификатов на
зарегистрированный домен за 168 часов, и на исходном домене он был исчерпан.

**B. Скрипт из архива** — `noesphere-issue-cert.sh` на certbot. Он повторяет попытку
каждые 20 минут и выключает свой таймер после успеха.

```bash
sed -i 's/noe\.l\.cd/<ДОМЕН>/g' /usr/local/bin/noesphere-issue-cert.sh
systemctl enable --now noesphere-cert.timer
journalctl -u noesphere-cert -n 20 --no-pager
```

Скрипт выпускает один сертификат на три имени (`<ДОМЕН>`, `www.<ДОМЕН>`,
`api.<ДОМЕН>`) и кладёт его в `/etc/letsencrypt/live/<ДОМЕН>/`. Ради этого `LIVE`
внутри скрипта тоже переписывается на `<ДОМЕН>` — имя каталога certbot берёт из
первого `-d`.

Если вам нужен только `api.<ДОМЕН>` (для прокси больше ничего), уберите лишние `-d`
**и** поправьте `LIVE` — иначе скрипт будет проверять несуществующий каталог и
каждый раз считать, что сертификата нет:

```bash
sed -i 's|LIVE=/etc/letsencrypt/live/<ДОМЕН>|LIVE=/etc/letsencrypt/live/api.<ДОМЕН>|' \
  /usr/local/bin/noesphere-issue-cert.sh
```

По умолчанию таймер `noesphere-cert.timer` **выключен** — это нормально: на исходном
сервере он выключил себя сам после успешного выпуска.

## 11. Настройка в консоли

Откройте `http://127.0.0.1:8787/admin?key=<ADMIN_KEY>` (затем то же на домене).

С базой из пакета уже работать можно — но проверьте три вещи:

**Upstreams.** Один апстрим `newapi` с пустым ключом — он не требует авторизации.
Если нужен свой, добавьте второй: базовый URL и ключ (любой OpenAI-совместимый:
OpenRouter, Groq, собственный шлюз).

**Models.** Один маппинг `claude-opus-5` → `claude-opus-5`. Здесь два поля
определяют поведение:

* `real_model` — имя модели **на апстриме**; `fake_model` — имя, которое видят клиенты;
* **`owned_by` управляет имитацией:** `Anthropic` или `claude` → антроповские
  заголовки, коды ошибок и подписи `thinking`; `OpenAI` → заголовки OpenAI.

Поля `is_reasoning` (отдавать блок `thinking`) и `is_vision` (принимать картинки)
зависят от возможностей реальной модели на апстриме.

**API Keys.** Два готовых клиентских ключа. При создании нового выбирается формат:
`sk-noe-v1`, `sk-ant-api03`, `sk-proj`, `sk-` — шлюз принимает все четыре.

## 12. Проверка

```bash
# 1. Служба
systemctl is-active noesphere

# 2. Локально
curl -s http://127.0.0.1:8787/health

# 3. Через домен
for U in https://api.<ДОМЕН>/health; do
  curl -s -o /dev/null -w 'http=%{http_code} verify=%{ssl_verify_result}\n' "$U"
done
# ожидаем http=200 verify=0

# 4. Заголовок не палит nginx
curl -sI https://api.<ДОМЕН>/health | grep -i '^server'
# ожидаем: server: cloudflare

# 5. Консоль просит ключ (403 — правильное поведение)
curl -s -o /dev/null -w '%{http_code}\n' https://api.<ДОМЕН>/admin

# 6. Шрифты консоли отдаются (иначе консоль выглядит чужой)
curl -s -o /dev/null -w '%{http_code}\n' \
  https://api.<ДОМЕН>/fonts/inter-300-700-normal-latin.woff2     # ожидаем 200

# 7. Запрос к модели
curl -s https://api.<ДОМЕН>/v1/messages \
  -H "x-api-key: <КЛИЕНТСКИЙ_КЛЮЧ>" -H "anthropic-version: 2023-06-01" \
  -H "content-type: application/json" \
  -d '{"model":"claude-opus-5","max_tokens":64,"messages":[{"role":"user","content":"Скажи ок"}]}'
```

## 13. Грабли, которые уже случались

Каждый пункт стоил времени на реальном развёртывании.

1. **Консоль теряла свою типографику.** Шлюз отдаёт шрифты по `/fonts/<файл>` из
   каталога `/opt/noesphere/fonts`, а он на сервере отсутствовал — endpoint отвечал
   **404**, и браузер подставлял системные шрифты вместо Instrument Serif / Inter /
   IBM Plex Mono. Каталог теперь в пакете — проверяйте пунктом 6 из шага 12.
2. **`server: nginx` вместо ожидаемого.** nginx подменяет заголовок `Server` своим.
   Без `nginx-extras` директива `more_set_headers` просто не работает.
3. **`dig` молчит на живом домене.** Если исходящий UDP/53 закрыт, `dig @1.1.1.1
   google.com` вернёт пусто. Проверяйте через DNS-over-HTTPS (шаг 9).
4. **Копия живой базы SQLite может быть битой.** У базы WAL-режим. Делайте
   `sqlite3 файл ".backup копия"`, а не `cp`; проверяйте `PRAGMA integrity_check`.
   Так же работает ежедневный бэкап из архива.
5. **Правка базы в обход консоли не применялась.** Приложение держит снимок в памяти
   и перечитывает его раз в минуту. Правьте через консоль либо подождите.
6. **`rm` в некоторых окружениях подменён на перемещение в корзину**, а
   `find -exec rm` может быть запрещён политикой. Для пустых каталогов — `rmdir`.
7. **Файлов `*.db-wal` и `*.db-shm` в архиве нет намеренно** — снимок базы уже
   содержит все данные. Не ищите их.

## 14. Что делать, если не работает

| Симптом | Куда смотреть |
|---|---|
| `nginx -t` падает на `more_set_headers` | не установлен `nginx-extras` (шаг 2) |
| Служба не стартует | `journalctl -u noesphere -n 50 --no-pager` |
| 502 от nginx | служба не слушает порт: `ss -tlnp \| grep 8787` |
| Сайт открыт, сертификат нет | `ls -la /etc/ssl/certs/<ДОМЕН>.fullchain.pem` и имя в `ssl_certificate` |
| Консоль отдаёт 403 | добавьте `?key=<ADMIN_KEY>` из юнита |
| Ошибки прав у службы | `chown -R noesphere:noesphere /opt/noesphere` |
| Ответ приходит рывками в конце | потерян `proxy_buffering off;` в конфиге nginx |
| Консоль выглядит чужой | не отдаются шрифты — проверьте пункт 6 из шага 12 |
| Апстрим отвечает ошибкой | в консоли **Upstreams** проверьте URL и ключ; `/health` шлюза покажет состояние апстрима |

---

## Что лежит рядом

* `README.md` — опись всех файлов с размерами.
* `req/noesphere.txt` — 19 пакетов для venv.
* `opt/noesphere/backups/` — снимки конфига, базы и кода за 5 дней. Если что-то
  сломается после правок, откатитесь на снимок за предыдущий день.
* `opt/noesphere/proxy_test.py` — тесты; запуск:
  `/opt/noesphere/venv/bin/python -m pytest /opt/noesphere/proxy_test.py`

**В пакете есть секреты:** `ADMIN_KEY` в юните, ключи апстримов и два клиентских
ключа в `noesphere.db`. Перед передачей архива кому-то ещё — смените `ADMIN_KEY`
и удалите `opt/noesphere/noesphere.db`.
