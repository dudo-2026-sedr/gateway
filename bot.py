#!/usr/bin/env python3
"""
Karma — Telegram bot for the Claude gateway.

Панель для клиентов (свой ключ, токены, ранги, рефералы) плюс полная админка
для владельца. Живёт рядом с прокси и работает с той же базой SQLite, а статус
моделей берёт через его /health/deep.

Запуск:
    BOT_TOKEN=123:abc DB_FILE=/data/noesphere.db python3 tgbot.py

Env:
    BOT_TOKEN           токен бота (обязателен)
    ADMIN_TG_ID         id владельца, по умолчанию 5480751648
    DB_FILE             база прокси (по умолчанию /data/noesphere.db или ./noesphere.db)
    PROXY_BASE_URL      адрес прокси, по умолчанию http://127.0.0.1:8000
    PROXY_ADMIN_KEY     пароль админки прокси (нужен для /health/deep)
    START_TOKENS        устарело: квота теперь дневная, см. DAILY_TOKENS_*
    CHECKIN_TOKENS      бонус за чек-ин раз в сутки, по умолчанию 500000
    DAILY_TOKENS_1/2/3  дневная норма рангов: 3000000 / 7500000 / 15000000
    RESET_TZ_OFFSET     часовой пояс сброса квоты (3 = UTC+3, полночь по МСК)
    REF_BONUS           бонус за подтверждённого реферала, по умолчанию 3000000
    REF_CONFIRM_REQUESTS реферал подтверждён после N запросов + подписки (5)
    REQUIRED_CHANNEL_ID/REQUIRED_CHAT_ID  канал и чат, обязательные к подписке
    CHANNEL_URL/CHAT_URL ссылки для кнопок «подписаться»
    SUB_CHECK_EVERY     как часто фоном перепроверять подписку, сек (600)
    RANK2_TOKENS/RANK2_REFS   порог ранга Профи (400000 / 3)
    RANK3_TOKENS/RANK3_REFS   порог ранга Легенда (2000000 / 8)
    DEFAULT_RPM         rpm для новых ключей
    KEY_FORMAT          noe | anthropic | openai | openai-legacy
"""
from __future__ import annotations

import asyncio
import html
import json
import logging
import os
import re
import secrets
import sqlite3
import string
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import httpx

# ══════════════════════════════════════════════════════════════════════
#  CONFIG
# ══════════════════════════════════════════════════════════════════════

BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
ADMIN_ID = int(os.getenv("ADMIN_TG_ID", "5480751648"))

DB_FILE = os.getenv("DB_FILE", "/data/noesphere.db" if os.path.exists("/data") else "noesphere.db")
PROXY_BASE = os.getenv("PROXY_BASE_URL", "https://api.funtro.cyou").rstrip("/")
PROXY_ADMIN_KEY = os.getenv("PROXY_ADMIN_KEY", "dudo_2026").strip()

START_TOKENS = int(os.getenv("START_TOKENS", "0"))
REF_BONUS = int(os.getenv("REF_BONUS", "3000000"))
RANK2_TOKENS = int(os.getenv("RANK2_TOKENS", "400000"))
RANK2_REFS = int(os.getenv("RANK2_REFS", "3"))
RANK3_TOKENS = int(os.getenv("RANK3_TOKENS", "2000000"))
RANK3_REFS = int(os.getenv("RANK3_REFS", "8"))
# Дневная квота по рангам и бонус за чек-ин. Квота не копится: в 00:00
# (локальное время, RESET_TZ_OFFSET) счётчик расхода обнуляется и лимит
# заново выставляется по рангу. Постоянные бонусы живут в bonus_tokens.
CHECKIN_TOKENS = int(os.getenv("CHECKIN_TOKENS", "500000"))
DAILY_TOKENS = {
    0: int(os.getenv("DAILY_TOKENS_0", "0")),
    1: int(os.getenv("DAILY_TOKENS_1", "3000000")),
    2: int(os.getenv("DAILY_TOKENS_2", "7500000")),
    3: int(os.getenv("DAILY_TOKENS_3", "15000000")),
}
RESET_TZ_OFFSET = float(os.getenv("RESET_TZ_OFFSET", "3"))
DEFAULT_RPM = int(os.getenv("DEFAULT_RPM", "120"))
# Сколько токенов выставлять ключу, создаваемому без явной квоты (0 в учёте
# означает «без лимита»).
BOT_DEFAULT_LIMIT = int(os.getenv("DEFAULT_KEY_TOKENS", "3000000"))
KEY_FORMAT = (os.getenv("KEY_FORMAT", "anthropic") or "anthropic").strip().lower()
PROBE_TTL = float(os.getenv("PROBE_TTL", "60"))
TICK_SEC = float(os.getenv("TICK_SEC", "60"))
# Обязательная подписка. ID могут быть числами (-100...) или @username; бот
# должен быть админом в канале и в чате, иначе статус участника не проверить.
REQUIRED_CHANNEL_ID = os.getenv("REQUIRED_CHANNEL_ID", "-1004294464731").strip()
REQUIRED_CHAT_ID = os.getenv("REQUIRED_CHAT_ID", "-1003959021367").strip()
CHANNEL_URL = os.getenv("CHANNEL_URL", "https://t.me/anthropc_claude").strip()
CHAT_URL = os.getenv("CHAT_URL", "https://t.me/+b2t10tfRDGEyMGY0").strip()
SUB_CACHE_TTL = float(os.getenv("SUB_CACHE_TTL", "20"))
SUB_CHECK_EVERY = float(os.getenv("SUB_CHECK_EVERY", "600"))
REF_CONFIRM_REQUESTS = int(os.getenv("REF_CONFIRM_REQUESTS", "5"))

# Бонусы за упоминание тега: в имени/фамилии +1M к дневному лимиту,
# в описании профиля («@cer_ai — бесплатный клод») ещё +500k.
BONUS_TAG = os.getenv("BONUS_TAG", "@cer_ai").strip().lower()
BONUS_NAME = int(os.getenv("BONUS_NAME", "1000000"))
BONUS_BIO = int(os.getenv("BONUS_BIO", "500000"))
PROFILE_TTL = float(os.getenv("PROFILE_TTL", "120"))
PROFILE_CHECK_EVERY = float(os.getenv("PROFILE_CHECK_EVERY", "1800"))

if not BOT_TOKEN:
    raise SystemExit("BOT_TOKEN env var is required")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("karma")

B62 = string.ascii_letters + string.digits
B64U = string.ascii_letters + string.digits + "-_"

RANK_TIERS = {
    0: ("Новичок", "🔒"),
    1: ("Новичок", "🌱"),
    2: ("Профи", "⚡"),
    3: ("Легенда", "👑"),
}
# Доступ по рангам — та же карта, что в прокси (RANK_MODELS).
RANK_MODELS = {
    0: [],
    1: ["claude-sonnet-5-5"],
    2: ["claude-sonnet-5-5", "claude-opus-5"],
}
INF = "∞"

SEP = "───────────────"

# ══════════════════════════════════════════════════════════════════════
#  БАЗА: SQLite или PostgreSQL
#  Если задан DATABASE_URL (Railway/Supabase) — работаем с Postgres,
#  иначе с локальным sqlite-файлом. SQL один: «?» → «%s» и мелкие
#  sqlite-привычки переводятся на лету.
# ══════════════════════════════════════════════════════════════════════

DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
PG_MODE = DATABASE_URL.startswith(("postgres://", "postgresql://"))

if PG_MODE:
    try:
        import psycopg  # type: ignore
    except ImportError as _e:  # pragma: no cover
        raise RuntimeError("DATABASE_URL задан, но psycopg не установлен: "
                           "pip install 'psycopg[binary]'") from _e
    DB_ERRORS: tuple = (sqlite3.Error, psycopg.Error)
else:
    DB_ERRORS = (sqlite3.Error,)


class DbRow(dict):
    """Строка, у которой работает и r["col"], и r[0]."""

    def __init__(self, cols, vals):
        super().__init__((c, v) for c, v in zip(cols, vals))
        self._vals = tuple(vals)

    def __getitem__(self, key):
        if isinstance(key, int):
            return self._vals[key]
        return super().__getitem__(key)


def _sql_fix(sql: str) -> str:
    out = sql.replace("?", "%s")
    out = re.sub(r"\bAUTOINCREMENT\b", "", out, flags=re.I)
    out = re.sub(r"\bINTEGER\s+PRIMARY\s+KEY\b", "BIGSERIAL PRIMARY KEY", out, flags=re.I)
    out = re.sub(r"\bMAX\s*\(", "GREATEST(", out, flags=re.I)
    out = re.sub(r"\bMIN\s*\(", "LEAST(", out, flags=re.I)
    return out


def _split_sql(script: str) -> list[str]:
    parts: list[str] = []
    buf: list[str] = []
    quote: Optional[str] = None
    for ch in script:
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in ("'", '"'):
            quote = ch
            buf.append(ch)
            continue
        if ch == ";":
            parts.append("".join(buf))
            buf = []
            continue
        buf.append(ch)
    if "".join(buf).strip():
        parts.append("".join(buf))
    return [p.strip() for p in parts
            if p.strip() and not p.strip().upper().startswith("PRAGMA")]


_PG_LOCK = threading.Lock()
_PG_IDLE: list = []
PG_POOL_SIZE = int(os.getenv("PG_POOL_SIZE", "4"))


class PgCursor:
    def __init__(self, cur):
        self._cur = cur

    def _cols(self) -> list[str]:
        return [d.name for d in (self._cur.description or [])]

    def fetchone(self):
        row = self._cur.fetchone()
        return None if row is None else DbRow(self._cols(), row)

    def fetchall(self):
        cols = self._cols()
        return [DbRow(cols, r) for r in self._cur.fetchall()]

    def __iter__(self):
        return iter(self.fetchall())


def _pg_new():
    dsn = DATABASE_URL
    if "sslmode=" not in dsn:
        dsn += ("&" if "?" in dsn else "?") + "sslmode=require"
    return psycopg.connect(dsn, prepare_threshold=None,
                           connect_timeout=int(os.getenv("PG_CONNECT_TIMEOUT", "15")))


def _pg_checkout():
    with _PG_LOCK:
        if _PG_IDLE:
            return _PG_IDLE.pop()
    return _pg_new()


def _pg_checkin(conn) -> None:
    try:
        if conn.closed or conn.broken:
            conn.close()
            return
    except Exception:
        try:
            conn.close()
        except Exception:
            pass
        return
    with _PG_LOCK:
        if len(_PG_IDLE) < PG_POOL_SIZE:
            _PG_IDLE.append(conn)
            return
    try:
        conn.close()
    except Exception:
        pass


class PgConn:
    """Адаптер с интерфейсом sqlite3.Connection поверх пула соединений.

    Соединение с Supabase/pooler стоит 2-3 секунды, поэтому одноразовые
    коннекты убивают отзывчивость: держим пул и переиспользуем.
    """

    def __init__(self):
        self._c = _pg_checkout()
        self.row_factory = None
        self._done = False

    def execute(self, sql: str, params=()):
        try:
            return PgCursor(self._c.execute(_sql_fix(sql), params or None))
        except (psycopg.OperationalError, psycopg.InterfaceError):
            self._c = _pg_new()
            return PgCursor(self._c.execute(_sql_fix(sql), params or None))

    def executescript(self, script: str) -> None:
        for stmt in _split_sql(script):
            self._c.execute(_sql_fix(stmt))

    def commit(self) -> None:
        self._c.commit()

    def rollback(self) -> None:
        self._c.rollback()

    def close(self) -> None:
        if self._done:
            return
        self._done = True
        _pg_checkin(self._c)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            if exc_type:
                self._c.rollback()
            else:
                self._c.commit()
        except Exception:
            try:
                self._c.close()
            except Exception:
                pass
            self._done = True
            return False
        self.close()
        return False


def connect_db():
    if PG_MODE:
        return PgConn()
    return sqlite3.connect(DB_FILE, timeout=15)


def table_cols(c, table: str) -> set[str]:
    if PG_MODE:
        rows = c.execute("SELECT column_name FROM information_schema.columns "
                         "WHERE table_schema='public' AND table_name=?", (table,)).fetchall()
        return {r[0] for r in rows}
    return {r[1] for r in c.execute(f"PRAGMA table_info({table})")}


# ══════════════════════════════════════════════════════════════════════
#  DATABASE
# ══════════════════════════════════════════════════════════════════════


def db():
    c = connect_db()
    if not PG_MODE:
        c.row_factory = sqlite3.Row
    return c


def _pg_widen_ids() -> None:
    """Telegram id больше 2^31, а INTEGER в Postgres — 32 бита.

    На sqlite это не видно (там INTEGER 64-битный), поэтому фикс только для PG.
    Каждый ALTER — в своей транзакции: упавшая команда не должна ломать остальные.
    """
    if not PG_MODE:
        return
    for table, column in (("api_keys", "tg_id"), ("tg_events", "tg_id"),
                          ("tg_users", "referred_by"), ("tg_users", "tg_id")):
        try:
            with connect_db() as c:
                c.execute(f"ALTER TABLE {table} ALTER COLUMN {column} TYPE BIGINT")
        except DB_ERRORS:
            pass


def init_db() -> None:
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS api_keys (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            public_key   TEXT NOT NULL UNIQUE,
            note         TEXT DEFAULT '',
            rpm_limit    INTEGER DEFAULT 60,
            enabled      INTEGER DEFAULT 1,
            created_at   TEXT DEFAULT '',
            upstream_key TEXT DEFAULT '',
            key_format   TEXT DEFAULT 'noe',
            token_limit  INTEGER DEFAULT 0,
            log_content  INTEGER DEFAULT 0,
            rank         INTEGER DEFAULT 3,
            tg_id        BIGINT DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS key_usage (
            key_id        INTEGER PRIMARY KEY,
            requests      INTEGER DEFAULT 0,
            input_tokens  INTEGER DEFAULT 0,
            output_tokens INTEGER DEFAULT 0,
            billed_tokens INTEGER DEFAULT 0,
            hidden_tokens INTEGER DEFAULT 0,
            last_used     TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS tg_users (
            tg_id        BIGINT PRIMARY KEY,
            username     TEXT DEFAULT '',
            first_name   TEXT DEFAULT '',
            api_key      TEXT DEFAULT '',
            rank         INTEGER DEFAULT 0,
            referred_by  BIGINT DEFAULT 0,
            ref_confirmed INTEGER DEFAULT 0,
            checkin_at   TEXT DEFAULT '',
            banned       INTEGER DEFAULT 0,
            created_at   TEXT DEFAULT '',
            last_seen    TEXT DEFAULT '',
            note         TEXT DEFAULT '',
            lifetime_tokens INTEGER DEFAULT 0,
            bonus_tokens    INTEGER DEFAULT 0,
            last_reset      TEXT DEFAULT '',
            subscribed      INTEGER DEFAULT 0,
            last_sub_check  TEXT DEFAULT '',
            rank_manual     INTEGER DEFAULT 0,
            bonus_name      INTEGER DEFAULT 0,
            bonus_bio       INTEGER DEFAULT 0,
            bio             TEXT DEFAULT '',
            profile_checked TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS tg_events (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            ts      TEXT DEFAULT '',
            tg_id   BIGINT DEFAULT 0,
            kind    TEXT DEFAULT '',
            text    TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS settings (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        """)
        _cols = table_cols(c, "api_keys")
        for name, decl in (("upstream_key", "TEXT DEFAULT ''"),
                           ("key_format", "TEXT DEFAULT 'noe'"),
                           ("token_limit", "INTEGER DEFAULT 0"),
                           ("log_content", "INTEGER DEFAULT 0"),
                           ("rank", "INTEGER DEFAULT 3"),
                           ("tg_id", "BIGINT DEFAULT 0")):
            if name not in _cols:
                c.execute(f"ALTER TABLE api_keys ADD COLUMN {name} {decl}")
        _ucols = table_cols(c, "key_usage")
        for name, decl in (("billed_tokens", "INTEGER DEFAULT 0"),
                           ("hidden_tokens", "INTEGER DEFAULT 0")):
            if name not in _ucols:
                c.execute(f"ALTER TABLE key_usage ADD COLUMN {name} {decl}")
        _tcols = table_cols(c, "tg_users")
        for name, decl in (("lifetime_tokens", "INTEGER DEFAULT 0"),
                           ("bonus_tokens", "INTEGER DEFAULT 0"),
                           ("last_reset", "TEXT DEFAULT ''"),
                           ("subscribed", "INTEGER DEFAULT 0"),
                           ("last_sub_check", "TEXT DEFAULT ''"),
                           ("rank_manual", "INTEGER DEFAULT 0"),
                           ("bonus_name", "INTEGER DEFAULT 0"),
                           ("bonus_bio", "INTEGER DEFAULT 0"),
                           ("bio", "TEXT DEFAULT ''"),
                           ("profile_checked", "TEXT DEFAULT ''")):
            if name not in _tcols:
                c.execute(f"ALTER TABLE tg_users ADD COLUMN {name} {decl}")
        c.commit()
    _pg_widen_ids()


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def log_event(tg_id: int, kind: str, text: str = "") -> None:
    try:
        with db() as c:
            c.execute("INSERT INTO tg_events (ts, tg_id, kind, text) VALUES (?,?,?,?)",
                      (now_iso(), tg_id, kind, text[:400]))
            c.commit()
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════════
#  KEYS / USERS
# ══════════════════════════════════════════════════════════════════════


def gen_key(fmt: str = "") -> str:
    f = (fmt or KEY_FORMAT).lower()
    if f == "anthropic":
        return "sk-ant-api03-" + "".join(secrets.choice(B64U) for _ in range(95))
    if f == "openai":
        return ("sk-proj-" + "".join(secrets.choice(B64U) for _ in range(48))
                + "T3BlbkFJ" + "".join(secrets.choice(B64U) for _ in range(100)))
    if f == "openai-legacy":
        return "sk-" + "".join(secrets.choice(B62) for _ in range(48))
    return "sk-noe-v1-" + "".join(secrets.choice(B62) for _ in range(80))


def mask_key(k: str) -> str:
    if not k:
        return "—"
    return f"{k[:14]}…{k[-4:]}" if len(k) > 20 else k


def create_key_for(tg_id: int, label: str, tokens: int = START_TOKENS,
                   rank: int = 0, rpm: int = DEFAULT_RPM) -> str:
    key = gen_key()
    with db() as c:
        c.execute("""INSERT INTO api_keys
                     (public_key, note, rpm_limit, enabled, created_at, upstream_key,
                      key_format, token_limit, log_content, rank, tg_id)
                     VALUES (?,?,?,1,?,'',?,?,0,?,?)""",
                  (key, label[:120], rpm, now_iso(), KEY_FORMAT, tokens, rank, tg_id))
        c.commit()
    return key


def user_key(tg_id: int) -> Optional[sqlite3.Row]:
    with db() as c:
        return c.execute("SELECT * FROM api_keys WHERE tg_id=? ORDER BY id DESC LIMIT 1",
                         (tg_id,)).fetchone()


def key_stats(key_id: int) -> dict:
    with db() as c:
        r = c.execute("SELECT * FROM key_usage WHERE key_id=?", (key_id,)).fetchone()
    if not r:
        return {"requests": 0, "billed": 0, "in": 0, "out": 0, "last": ""}
    return {"requests": r["requests"] or 0, "billed": r["billed_tokens"] or 0,
            "in": r["input_tokens"] or 0, "out": r["output_tokens"] or 0,
            "last": r["last_used"] or ""}


def get_user(tg_id: int) -> Optional[sqlite3.Row]:
    with db() as c:
        return c.execute("SELECT * FROM tg_users WHERE tg_id=?", (tg_id,)).fetchone()


def upsert_user(tg_id: int, username: str = "", first_name: str = "",
                referred_by: int = 0) -> sqlite3.Row:
    u = get_user(tg_id)
    if u:
        with db() as c:
            c.execute("UPDATE tg_users SET username=?, first_name=?, last_seen=? WHERE tg_id=?",
                      (username or "", first_name or "", now_iso(), tg_id))
            c.commit()
        return get_user(tg_id)
    with db() as c:
        c.execute("""INSERT INTO tg_users
                     (tg_id, username, first_name, api_key, rank, referred_by,
                      ref_confirmed, checkin_at, banned, created_at, last_seen)
                     VALUES (?,?,?,?,0,?,0,'',0,?,?)""",
                  (tg_id, username or "", first_name or "", "", referred_by,
                   now_iso(), now_iso()))
        c.commit()
    return get_user(tg_id)


def confirmed_refs(tg_id: int) -> int:
    with db() as c:
        r = c.execute("SELECT COUNT(*) FROM tg_users WHERE referred_by=? AND ref_confirmed=1",
                      (tg_id,)).fetchone()
    return int(r[0] or 0)


def total_refs(tg_id: int) -> int:
    with db() as c:
        r = c.execute("SELECT COUNT(*) FROM tg_users WHERE referred_by=?", (tg_id,)).fetchone()
    return int(r[0] or 0)


def local_today() -> str:
    """Дата по часовому поясу сброса (по умолчанию UTC+3)."""
    return (datetime.now(timezone.utc) + timedelta(hours=RESET_TZ_OFFSET)).strftime("%Y-%m-%d")


def local_now_str() -> str:
    return (datetime.now(timezone.utc) + timedelta(hours=RESET_TZ_OFFSET)).strftime("%Y-%m-%d %H:%M")


def hours_to_reset() -> int:
    now = datetime.now(timezone.utc) + timedelta(hours=RESET_TZ_OFFSET)
    nxt = (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    return max(1, int((nxt - now).total_seconds() // 3600) + (1 if (nxt - now).seconds % 3600 else 0))


def checked_in_today(u: Optional[sqlite3.Row]) -> bool:
    if not u:
        return False
    return str(u["checkin_at"] or "").startswith(local_today())


def daily_amount(rank: int) -> int:
    return DAILY_TOKENS.get(int(rank or 0), 0)


def refresh_quota(tg_id: int) -> int:
    """Пересчитать дневной лимит: норма ранга + постоянные бонусы + чек-ин."""
    u = get_user(tg_id)
    k = user_key(tg_id)
    if not u or not k:
        return 0
    limit = (daily_amount(u["rank"]) + int(u["bonus_tokens"] or 0)
             + int(u["bonus_name"] or 0) + int(u["bonus_bio"] or 0))
    if int(u["rank"] or 0) >= 1 and checked_in_today(u):
        limit += CHECKIN_TOKENS
    with db() as c:
        c.execute("UPDATE api_keys SET token_limit=? WHERE id=?", (limit, k["id"]))
        c.commit()
    return limit


def total_used(tg_id: int) -> int:
    """Всё, что сожжено за всё время (для рангов)."""
    u = get_user(tg_id)
    k = user_key(tg_id)
    life = int(u["lifetime_tokens"] or 0) if u else 0
    today = key_stats(k["id"])["billed"] if k else 0
    return life + today


# ── бонусы за профиль: @cer_ai в имени и в описании ─────────────────
# Имя/фамилию и bio бот берёт через getChat (поле bio доступно для личных чатов).
# Результат кэшируется, чтобы меню открывалось мгновенно.
_profile_cache: dict[int, tuple[float, dict]] = {}


def _tag_in(text: str) -> bool:
    return bool(BONUS_TAG) and BONUS_TAG in (text or "").lower()


def _bio_is_ad(text: str) -> bool:
    low = (text or "").lower()
    if not _tag_in(low):
        return False
    return "бесплатн" in low and ("клод" in low or "claude" in low)


async def fetch_profile(uid: int, force: bool = False) -> Optional[dict]:
    now = time.time()
    if not force:
        hit = _profile_cache.get(uid)
        if hit and now - hit[0] < PROFILE_TTL:
            return hit[1]
    chat = await api("getChat", chat_id=uid)
    if not isinstance(chat, dict):
        return None
    first = str(chat.get("first_name") or "")
    last = str(chat.get("last_name") or "")
    bio = str(chat.get("bio") or "")
    st = {
        "first_name": first, "last_name": last, "bio": bio,
        "name_hit": _tag_in(f"{first} {last}"),
        "bio_hit": _bio_is_ad(bio),
    }
    _profile_cache[uid] = (now, st)
    return st


async def refresh_profile_bonuses(uid: int, force: bool = False) -> dict:
    """Перепроверить ник/bio и обновить бонусы в лимите."""
    st = await fetch_profile(uid, force)
    if st is None:
        return {"changed": False, "unknown": True}
    u = get_user(uid)
    if not u:
        return {"changed": False}
    b_name = BONUS_NAME if st["name_hit"] else 0
    b_bio = BONUS_BIO if st["bio_hit"] else 0
    changed = (int(u["bonus_name"] or 0) != b_name) or (int(u["bonus_bio"] or 0) != b_bio)
    with db() as c:
        c.execute("UPDATE tg_users SET bonus_name=?, bonus_bio=?, bio=?, profile_checked=? "
                  "WHERE tg_id=?", (b_name, b_bio, st["bio"][:500], now_iso(), uid))
        c.commit()
    if changed:
        log_event(uid, "profile_bonus", f"name={b_name} bio={b_bio}")
        refresh_quota(uid)
    return {"changed": changed, "name_hit": st["name_hit"], "bio_hit": st["bio_hit"],
            "bonus": b_name + b_bio, "bio": st["bio"],
            "first_name": st["first_name"], "last_name": st["last_name"]}


async def profile_loop() -> None:
    while True:
        await asyncio.sleep(PROFILE_CHECK_EVERY)
        try:
            with db() as c:
                rows = c.execute("SELECT tg_id FROM tg_users WHERE banned=0").fetchall()
            for r in rows:
                uid = int(r["tg_id"])
                res = await refresh_profile_bonuses(uid, force=True)
                if res.get("changed"):
                    u = get_user(uid)
                    if u and res.get("bonus"):
                        await send(uid, f"🎁 Бонус за профиль: +{human(res['bonus'])} к дневному лимиту.")
                await asyncio.sleep(0.05)
        except Exception as e:                   # noqa: BLE001
            log.warning("profile loop: %r", e)


def daily_reset() -> list[int]:
    """Сброс дневной квоты. Вызывается из тика; идемпотентно."""
    today = local_today()
    done: list[int] = []
    with db() as c:
        rows = c.execute("SELECT tg_id, last_reset FROM tg_users").fetchall()
    for r in rows:
        if str(r["last_reset"] or "") == today:
            continue
        uid = int(r["tg_id"])
        k = user_key(uid)
        if k:
            used = key_stats(k["id"])["billed"]
            with db() as c:
                if used:
                    c.execute("UPDATE tg_users SET lifetime_tokens = "
                              "COALESCE(lifetime_tokens,0) + ? WHERE tg_id=?", (used, uid))
                c.execute("UPDATE key_usage SET requests=0, input_tokens=0, output_tokens=0, "
                          "billed_tokens=0, hidden_tokens=0 WHERE key_id=?", (k["id"],))
                c.execute("UPDATE tg_users SET last_reset=? WHERE tg_id=?", (today, uid))
                c.commit()
        sync_rank(uid)
        refresh_quota(uid)
        done.append(uid)
    return done


def rank_for(tokens_used: int, refs: int) -> int:
    if refs >= RANK3_REFS and tokens_used >= RANK3_TOKENS:
        return 3
    if refs >= RANK2_REFS and tokens_used >= RANK2_TOKENS:
        return 2
    return 1


def sync_rank(tg_id: int) -> tuple[int, int]:
    """Пересчитать ранг пользователя. Возвращает (было, стало)."""
    u = get_user(tg_id)
    if not u:
        return 0, 0
    k = user_key(tg_id)
    old = int(u["rank"] or 0)
    if int(u["rank_manual"] or 0) or old == 0:
        return old, old          # ранг выдан вручную или ещё нет чек-ина — не трогаем
    used = total_used(tg_id)
    want = rank_for(used, confirmed_refs(tg_id))
    if want != old:
        with db() as c:
            c.execute("UPDATE tg_users SET rank=? WHERE tg_id=?", (want, tg_id))
            if k:
                c.execute("UPDATE api_keys SET rank=? WHERE id=?", (want, k["id"]))
            c.commit()
        log_event(tg_id, "rank", f"{old} -> {want}")
        refresh_quota(tg_id)
        return old, want
    return old, old


def bump_tokens(tg_id: int, amount: int) -> tuple[bool, int]:
    """Постоянный бонус: переживает ежедневный сброс."""
    u = get_user(tg_id)
    k = user_key(tg_id)
    if not u or not k:
        return False, 0
    with db() as c:
        c.execute("UPDATE tg_users SET bonus_tokens = MAX(0, COALESCE(bonus_tokens,0) + ?) "
                  "WHERE tg_id=?", (int(amount), tg_id))
        c.commit()
    return True, refresh_quota(tg_id)


def set_key_field(tg_id: int, field: str, value: Any) -> None:
    if field not in ("rank", "token_limit", "rpm_limit", "enabled", "upstream_key",
                     "log_content", "note"):
        raise ValueError(field)
    with db() as c:
        c.execute(f"UPDATE api_keys SET {field}=? WHERE tg_id=?", (value, tg_id))
        c.commit()


# ══════════════════════════════════════════════════════════════════════
#  ПОДПИСКА (канал + чат)
# ══════════════════════════════════════════════════════════════════════

_sub_cache: dict[int, tuple[float, bool]] = {}


def required_chats() -> list[tuple[str, str]]:
    out = []
    if REQUIRED_CHANNEL_ID:
        out.append((REQUIRED_CHANNEL_ID, "канал"))
    if REQUIRED_CHAT_ID:
        out.append((REQUIRED_CHAT_ID, "чат"))
    return out


async def chat_member(chat: str, uid: int) -> Optional[bool]:
    """True — подписан, False — нет, None — не смогли проверить."""
    res = await api("getChatMember", chat_id=chat, user_id=uid)
    if res is None:
        return None
    st = str(res.get("status") or "")
    if st in ("creator", "administrator", "member"):
        return True
    if st == "restricted":
        return bool(res.get("is_member"))
    return False


async def subscription_state(uid: int, force: bool = False) -> tuple[bool, list[str]]:
    need = required_chats()
    if not need:
        return True, []
    now = time.time()
    if not force:
        hit = _sub_cache.get(uid)
        if hit and now - hit[0] < SUB_CACHE_TTL:
            return hit[1], ([] if hit[1] else [n for _, n in need])
    missing: list[str] = []
    for cid, name in need:
        ok = await chat_member(cid, uid)
        if ok is False:
            missing.append(name)
        elif ok is None:
            log.warning("getChatMember(%s) не ответил — считаю проверку пройденной", cid)
    ok = not missing
    _sub_cache[uid] = (now, ok)
    return ok, missing


def apply_subscription(tg_id: int, ok: bool) -> bool:
    """Записать статус и включить/выключить ключ. Возвращает «изменилось»."""
    u = get_user(tg_id)
    k = user_key(tg_id)
    if not u:
        return False
    was = int(u["subscribed"] or 0)
    want = 1 if ok else 0
    with db() as c:
        c.execute("UPDATE tg_users SET subscribed=?, last_sub_check=? WHERE tg_id=?",
                  (want, now_iso(), tg_id))
        if k and not int(u["banned"] or 0):
            c.execute("UPDATE api_keys SET enabled=? WHERE id=?", (want, k["id"]))
        c.commit()
    if was != want:
        log_event(tg_id, "sub", "on" if ok else "off")
        return True
    return False


def render_gate(missing: list[str]) -> tuple[str, dict]:
    names = ", ".join(missing) if missing else "канал и чат"
    rows: list[list[dict]] = []
    if CHANNEL_URL:
        rows.append([url_btn("📢 Подписаться на канал", CHANNEL_URL)])
    if CHAT_URL:
        rows.append([url_btn("💬 Вступить в чат", CHAT_URL)])
    rows.append([btn("✅ Я сделал", "m:gatesub")])
    text = (
        f"🔐 <b>Доступ по подписке</b>\n{SEP}\n"
        f"Чтобы пользоваться ботом и API, подпишись на канал и вступи в чат.\n\n"
        f"Без подписки ключ останавливается.\n"
        f"Не хватает: <b>{esc(names)}</b>"
    )
    return text, kb(rows)


async def enforce_loop() -> None:
    while True:
        await asyncio.sleep(SUB_CHECK_EVERY)
        if not required_chats():
            continue
        try:
            with db() as c:
                rows = c.execute("SELECT tg_id FROM tg_users WHERE banned=0").fetchall()
            for r in rows:
                uid = int(r["tg_id"])
                ok, _ = await subscription_state(uid, force=True)
                if apply_subscription(uid, ok) and not ok:
                    await send(uid, f"⚠️ Подписка потеряна — API-ключ остановлен.\n"
                                    f"Подпишись снова и нажми «Я сделал».")
                await asyncio.sleep(0.05)
        except Exception as e:                   # noqa: BLE001
            log.warning("sub enforce: %r", e)


# ══════════════════════════════════════════════════════════════════════
#  REFERRALS
# ══════════════════════════════════════════════════════════════════════


def maybe_confirm_refs() -> list[tuple[int, int]]:
    """Подтвердить рефералов: >= N запросов и действующая подписка."""
    out: list[tuple[int, int]] = []
    with db() as c:
        rows = c.execute("""SELECT u.tg_id, u.referred_by FROM tg_users u
                            WHERE u.referred_by > 0 AND u.ref_confirmed = 0""").fetchall()
    for r in rows:
        uid, inviter = int(r["tg_id"]), int(r["referred_by"])
        k = user_key(uid)
        if not k:
            continue
        u = get_user(uid)
        if not u or not int(u["subscribed"] or 0):
            continue
        if key_stats(k["id"])["requests"] < REF_CONFIRM_REQUESTS:
            continue
        with db() as c:
            c.execute("UPDATE tg_users SET ref_confirmed=1 WHERE tg_id=?", (uid,))
            c.commit()
        ok, _lim = bump_tokens(inviter, REF_BONUS)
        log_event(inviter, "ref_bonus",
                  f"+{REF_BONUS} за {uid}" if ok else f"за {uid} (у пригласившего нет ключа)")
        out.append((inviter, uid))
    return out


# ══════════════════════════════════════════════════════════════════════
#  TELEGRAM API
# ══════════════════════════════════════════════════════════════════════

client: Optional[httpx.AsyncClient] = None
_me: dict = {}


async def api(method: str, **params: Any) -> Any:
    assert client is not None
    try:
        r = await client.post(f"https://api.telegram.org/bot{BOT_TOKEN}/{method}", json=params)
    except Exception as e:
        log.warning("tg %s failed: %r", method, e)
        return None
    try:
        data = r.json()
    except Exception:
        return None
    if not data.get("ok"):
        desc = str(data.get("description") or "")
        if "message is not modified" not in desc:
            log.warning("tg %s: %s", method, desc)
        return None
    return data.get("result")


async def send(chat_id: int, text: str, kb: Optional[dict] = None,
               preview: bool = False) -> Any:
    params: dict[str, Any] = {"chat_id": chat_id, "text": text, "parse_mode": "HTML",
                              "disable_web_page_preview": not preview}
    if kb:
        params["reply_markup"] = kb
    return await api("sendMessage", **params)


async def edit(chat_id: int, message_id: int, text: str, kb: Optional[dict] = None) -> None:
    params: dict[str, Any] = {"chat_id": chat_id, "message_id": message_id, "text": text,
                              "parse_mode": "HTML", "disable_web_page_preview": True}
    if kb:
        params["reply_markup"] = kb
    await api("editMessageText", **params)


async def answer_cb(cb_id: str, text: str = "", alert: bool = False) -> None:
    await api("answerCallbackQuery", callback_query_id=cb_id, text=text, show_alert=alert)


# ══════════════════════════════════════════════════════════════════════
#  UI HELPERS
# ══════════════════════════════════════════════════════════════════════


def btn(text: str, data: str) -> dict:
    return {"text": text, "callback_data": data}


def url_btn(text: str, url: str) -> dict:
    return {"text": text, "url": url}


def kb(rows: list[list[dict]]) -> dict:
    return {"inline_keyboard": rows}


def human(n: int) -> str:
    n = int(n or 0)
    if n >= 1_000_000_000:
        return f"{n / 1_000_000_000:.1f}B".replace(".0B", "B")
    if n >= 1_000_000:
        return f"{n / 1_000_000:.2f}M".replace(".00M", "M")
    if n >= 1_000:
        return f"{n / 1_000:.1f}k".replace(".0k", "k")
    return str(n)


def limit_text(rank: int, limit: int) -> str:
    """Как показывать квоту: до чек-ина её нет, без лимита — «∞»."""
    if int(rank or 0) == 0 and not int(limit or 0):
        return "—"
    return human(limit) if int(limit or 0) else INF


def bar(done: int, total: int, width: int = 10) -> str:
    if total <= 0:
        return "▰" * width
    pct = max(0, min(1.0, done / total))
    filled = int(round(pct * width))
    return "▰" * filled + "▱" * (width - filled)


def rank_title(rank: int) -> str:
    name, icon = RANK_TIERS.get(int(rank or 0), RANK_TIERS[0])
    return f"{icon} <b>{name}</b>"


def models_for(rank: int) -> str:
    if int(rank or 0) >= 3:
        return "все модели"
    items = RANK_MODELS.get(int(rank or 0), [])
    return ", ".join(f"<code>{m}</code>" for m in items) if items else "—"


def esc(v: Any) -> str:
    return html.escape(str(v or ""))


# ══════════════════════════════════════════════════════════════════════
#  MODEL STATUS
# ══════════════════════════════════════════════════════════════════════

_probe_cache: dict[str, Any] = {"at": 0.0, "data": None}


async def probe_models(force: bool = False) -> dict:
    """Статус моделей через /health/deep прокси (один мелкий запрос на модель).

    503 — это НОРМАЛЬНЫЙ ответ: прокси так сигналит «часть моделей лежит», но
    тело с каналами и миллисекундами приходит полностью. Поэтому парсим JSON
    при любом статусе; если тело без каналов — показываем список моделей из базы
    со статусом «неизвестно», чтобы экран не был пустым.
    """
    now = time.time()
    if not force and _probe_cache["data"] is not None and now - _probe_cache["at"] < PROBE_TTL:
        return _probe_cache["data"]
    if client is None:
        return {"error": "нет HTTP-клиента"}
    err = ""
    try:
        r = await client.get(f"{PROXY_BASE}/health/deep",
                             params={"key": PROXY_ADMIN_KEY}, timeout=90.0)
        data = r.json() or {}
        channels = data.get("channels") or {}
        if channels:
            _probe_cache["at"] = now
            _probe_cache["data"] = channels
            return channels
        err = f"HTTP {r.status_code}: нет поля channels"
    except Exception as e:
        err = repr(e)[:120]
    # прокси молчит или старый билд — показываем модели из базы
    fallback = {}
    try:
        with db() as c:
            rows = c.execute("SELECT fake_model, enabled FROM mappings ORDER BY id").fetchall()
        fallback = {r["fake_model"]: {"state": "unknown" if r["enabled"] else "no-upstream"}
                    for r in rows}
    except Exception:
        pass
    if fallback:
        fallback["_note"] = f"прокси не ответил ({err})"
        _probe_cache["at"] = now
        _probe_cache["data"] = fallback
        return fallback
    return {"error": err or "прокси недоступен"}


# ══════════════════════════════════════════════════════════════════════
#  RENDERERS
# ══════════════════════════════════════════════════════════════════════


_USER_FIELDS = ("tg_id", "username", "first_name", "rank", "referred_by", "ref_confirmed",
                "checkin_at", "banned", "created_at", "last_seen", "note",
                "lifetime_tokens", "bonus_tokens", "last_reset", "subscribed",
                "last_sub_check", "rank_manual", "bonus_name", "bonus_bio", "bio")

_STATS_SQL = """
    SELECT u.*,
           k.id          AS k_id,
           k.public_key  AS k_public_key,
           k.rpm_limit   AS k_rpm_limit,
           k.enabled     AS k_enabled,
           k.token_limit AS k_token_limit,
           COALESCE(ku.billed_tokens, 0) AS u_used,
           COALESCE(ku.requests, 0)      AS u_requests,
           (SELECT COUNT(*) FROM tg_users r WHERE r.referred_by = u.tg_id) AS refs_all,
           (SELECT COUNT(*) FROM tg_users r WHERE r.referred_by = u.tg_id
                                               AND r.ref_confirmed = 1)   AS refs_conf
      FROM tg_users u
      LEFT JOIN api_keys k ON k.id = (SELECT id FROM api_keys WHERE tg_id = u.tg_id
                                      ORDER BY id DESC LIMIT 1)
      LEFT JOIN key_usage ku ON ku.key_id = k.id
     WHERE u.tg_id = ?
"""


def user_stats(tg_id: int) -> dict:
    """Всё для экранов одним запросом — в Postgres каждый запрос это round-trip."""
    with db() as c:
        row = c.execute(_STATS_SQL, (tg_id,)).fetchone()
    if row is None:
        return {"user": None, "key": None, "rank": 0, "used": 0, "requests": 0,
                "limit": 0, "refs": 0, "refs_all": 0, "cap": "none"}
    raw = dict(row)
    user = {f: raw.get(f) for f in _USER_FIELDS}
    key = None
    if raw.get("k_id"):
        key = {"id": raw["k_id"], "public_key": raw.get("k_public_key"),
               "rpm_limit": raw.get("k_rpm_limit"), "enabled": raw.get("k_enabled"),
               "token_limit": raw.get("k_token_limit")}
    rank = int(user.get("rank") or 0)
    return {
        "user": user, "key": key, "rank": rank,
        "used": int(raw.get("u_used") or 0),
        "requests": int(raw.get("u_requests") or 0),
        "limit": int((key or {}).get("token_limit") or 0),
        "refs": int(raw.get("refs_conf") or 0),
        "refs_all": int(raw.get("refs_all") or 0),
        "cap": "unlimited" if not key or not (key.get("token_limit") or 0) else "limited",
    }


def render_menu(tg_id: int, name: str) -> tuple[str, dict]:
    s = user_stats(tg_id)
    u = s["user"]
    left = ("—" if s["rank"] == 0 and not s["limit"]
            else INF if not s["limit"] else human(max(0, s["limit"] - s["used"])))
    main = kb([
        [btn("📊 Статус моделей", "m:models"), btn("👤 Профиль", "m:profile")],
        [btn("🎁 Реферальная программа", "m:ref"), btn("🏅 Ранг", "m:rank")],
        [btn("🔑 Мой ключ", "m:key")],
    ])
    if s["rank"] == 0 or not checked_in_today(u):
        label = ("✅ Чек-ин · +" + human(CHECKIN_TOKENS) + " · открыть доступ"
                 if s["rank"] == 0 else "✅ Чек-ин · +" + human(CHECKIN_TOKENS))
        main["inline_keyboard"].insert(0, [btn(label, "m:checkin")])
    if tg_id == ADMIN_ID:
        main["inline_keyboard"].append([btn("🛠 Админ-панель", "a:home")])

    text = (
        f"✦ <b>Karma</b> · <i>Claude API</i>\n"
        f"{SEP}\n"
        f"{esc(name)} · <code>{tg_id}</code>\n"
        f"Ранг — {rank_title(s['rank'])}\n"
        f"Сегодня — <b>{human(s['used'])}</b> / <b>{limit_text(s['rank'], s['limit'])}</b>\n"
        f"Осталось — <b>{left}</b> · сброс в 00:00\n"
        f"{SEP}\n"
        f"<i>Квота обновляется каждый день.</i>"
    )
    return text, main


def render_profile(tg_id: int) -> tuple[str, dict]:
    s = user_stats(tg_id)
    u, k = s["user"] or {}, s["key"] or {}
    used, limit = s["used"], s["limit"]
    pct = f"{bar(used, limit)}  {int(min(1.0, used / limit) * 100) if limit else 100}%" if limit else ""
    uname = f"@{esc(u['username'])}" if u.get("username") else "—"
    text = (
        f"👤 <b>Профиль</b>\n{SEP}\n"
        f"ID: <code>{tg_id}</code>\n"
        f"Username: {uname}\n"
        f"Ранг: {rank_title(s['rank'])}\n"
        f"Ключ: <code>{esc(mask_key(k['public_key']) if k else '—')}</code>\n"
        f"{SEP}\n"
        f"Сегодня: <b>{human(used)}</b> / <b>{limit_text(s['rank'], limit)}</b>\n"
        f"{pct}\n"
        f"Дневная норма: {human(daily_amount(s['rank']))}"
        f" · чек-ин: {'✅ ' + human(CHECKIN_TOKENS) if checked_in_today(u) else 'не взят'}\n"
        f"Бонусы: ник {human(u.get('bonus_name') or 0)} · био {human(u.get('bonus_bio') or 0)}\n"
        f"Сброс квоты: 00:00 (через {hours_to_reset()} ч)\n"
        f"Всего сожжено: <b>{human(total_used(tg_id))}</b>\n"
        f"Запросов сегодня: <b>{s['requests']}</b>\n"
        f"Рефералы: <b>{s['refs']}</b> подтверждено · {s['refs_all']} всего\n"
        f"Регистрация: {esc((u.get('created_at') or '')[:16])}\n"
        f"Последняя активность: {esc((u.get('last_seen') or '')[:16])}"
    )
    rows = [
        [btn("📋 Скопировать ключ", "m:copykey"), btn("📋 Скопировать base_url", "m:copyurl")],
        [btn("🔄 Обновить", "m:profile"), btn("◀ Меню", "m:menu")],
    ]
    return text, kb(rows)


def render_key(tg_id: int) -> tuple[str, dict]:
    k = user_key(tg_id)
    if not k:
        return ("🔑 <b>Ключ</b>\n" + SEP + "\nКлюч ещё не выдан — нажми /start.", kb([[btn("◀ Меню", "m:menu")]]))
    text = (
        f"🔑 <b>Твой API-ключ</b>\n{SEP}\n"
        f"<code>{esc(k['public_key'])}</code>\n{SEP}\n"
        f"Base URL: <code>{esc(PROXY_BASE)}</code>\n"
        f"RPM: <b>{k['rpm_limit']}</b> · состояние: <b>{'active' if k['enabled'] else 'off'}</b>\n\n"
        f"<i>Anthropic SDK: base_url = {esc(PROXY_BASE)}</i>"
    )
    rows = [
        [btn("📋 Скопировать ключ", "m:copykey"), btn("📋 Скопировать URL", "m:copyurl")],
        [btn("◀ Меню", "m:menu")],
    ]
    return text, kb(rows)


async def render_models(tg_id: int, force: bool = False) -> tuple[str, dict]:
    channels = await probe_models(force=force)
    if "error" in channels:
        return (f"📊 <b>Статус моделей</b>\n{SEP}\n⚠️ Прокси недоступен: {esc(channels['error'])}",
                kb([[btn("🔄 Проверить", "m:models:force")], [btn("◀ Меню", "m:menu")]]))
    rank = int((get_user(tg_id) or {"rank": 0})["rank"] or 0)
    allowed = None if rank >= 3 else set(RANK_MODELS.get(rank, []))

    def icon(st: str) -> str:
        return {"ok": "🟢", "down": "🔴", "no-upstream": "⚪️",
                "no-key": "⚪️", "unknown": "🟡"}.get(st, "⚪️")

    lines, rows = [], []
    for name in sorted(channels):
        ch = channels[name] or {}
        st = ch.get("state") or "unknown"
        ms = ch.get("ms")
        ms_s = f"{ms} ms" if isinstance(ms, int) else "—"
        locked = allowed is not None and name not in allowed
        tag = "" if not locked else "  🔒"
        lines.append(f"{icon(st)} <code>{esc(name):<20}</code> {ms_s:>8}{tag}")
        if st == "ok" and not locked:
            rows.append([btn(f"⚡ Пинг {name}", f"m:ping:{name}")])
    text = (
        f"📊 <b>Статус моделей</b>\n{SEP}\n"
        "<pre>" + "\n".join(lines) + "</pre>\n"
        f"{SEP}\n🟢 онлайн · 🟡 неизвестно · 🔴 лежит · 🔒 закрыто рангом"
    )
    rows.append([btn("🔄 Обновить", "m:models:force"), btn("◀ Меню", "m:menu")])
    return text, kb(rows)


def render_ref(tg_id: int, bot_username: str) -> tuple[str, dict]:
    s = user_stats(tg_id)
    link = f"https://t.me/{bot_username}?start=ref_{tg_id}"
    text = (
        f"🎁 <b>Реферальная программа</b>\n{SEP}\n"
        f"За каждого друга, который начнёт пользоваться — "
        f"<b>+{human(REF_BONUS)}</b> токенов.\n\n"
        f"Твоя ссылка:\n<code>{esc(link)}</code>\n{SEP}\n"
        f"Приглашено: <b>{s['refs_all']}</b>\n"
        f"Подтверждено: <b>{s['refs']}</b>\n"
        f"Бонусов получено: <b>{human(s['refs'] * REF_BONUS)}</b>\n\n"
        f"<i>Реферал подтверждается после {REF_CONFIRM_REQUESTS} запросов "
        f"и обязательной подписки на канал и чат.</i>"
    )
    share = ("https://t.me/share/url?url=" + link.replace(":", "%3A").replace("/", "%2F")
             + "&text=" + "Karma%20%C2%B7%20Claude%20API")
    rows = [
        [btn("📋 Скопировать ссылку", "m:copyref")],
        [url_btn("📨 Поделиться", share)],
        [btn("🔄 Обновить", "m:ref"), btn("◀ Меню", "m:menu")],
    ]
    return text, kb(rows)


def render_rank(tg_id: int) -> tuple[str, dict]:
    s = user_stats(tg_id)
    rank, refs = s["rank"], s["refs"]
    used = total_used(tg_id)
    if rank >= 3:
        next_block = "Максимальный ранг достигнут."
    elif rank == 2:
        next_block = (
            f"До 👑 <b>Легенды</b>:\n"
            f"· токены {bar(used, RANK3_TOKENS)} {human(used)} / {human(RANK3_TOKENS)}\n"
            f"· рефералы {bar(refs, RANK3_REFS)} {refs} / {RANK3_REFS}"
        )
    elif rank == 1:
        next_block = (
            f"До ⚡ <b>Профи</b>:\n"
            f"· токены {bar(used, RANK2_TOKENS)} {human(used)} / {human(RANK2_TOKENS)}\n"
            f"· рефералы {bar(refs, RANK2_REFS)} {refs} / {RANK2_REFS}"
        )
    else:
        next_block = "Возьми чек-ин в меню, чтобы открыть первый ранг."
    ladder = "\n".join(
        f"{RANK_TIERS[r][1]} <b>{RANK_TIERS[r][0]}</b> — {human(DAILY_TOKENS[r])}/день"
        for r in (1, 2, 3))
    text = (
        f"🏅 <b>Ранг</b>\n{SEP}\n"
        f"Текущий: {rank_title(rank)}\n"
        f"Квота: <b>{human(daily_amount(rank))}</b> в день + чек-ин {human(CHECKIN_TOKENS)}\n"
        f"Модели: {models_for(rank)}\n{SEP}\n"
        f"{next_block}\n{SEP}\n"
        f"<b>Лестница</b>\n{ladder}"
    )
    return text, kb([[btn("✅ Чек-ин", "m:checkin")],
                     [btn("🔄 Обновить", "m:rank"), btn("◀ Меню", "m:menu")]])


# ══════════════════════════════════════════════════════════════════════
#  ADMIN RENDERERS
# ══════════════════════════════════════════════════════════════════════


def table_exists(c, table: str) -> bool:
    """Есть ли таблица (по-разному в sqlite и postgres)."""
    if PG_MODE:
        return bool(c.execute("SELECT 1 FROM information_schema.tables "
                              "WHERE table_schema='public' AND table_name=?",
                              (table,)).fetchone())
    return bool(c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?",
                          (table,)).fetchone())


def admin_stats() -> dict:
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d") + "%"
    with db() as c:
        r = c.execute("""
            SELECT (SELECT COUNT(*) FROM tg_users) AS n_users,
                   (SELECT COUNT(*) FROM tg_users WHERE banned=1) AS n_banned,
                   (SELECT COUNT(*) FROM api_keys) AS n_keys,
                   (SELECT COALESCE(SUM(requests),0) FROM key_usage) AS sum_req,
                   (SELECT COALESCE(SUM(billed_tokens),0) FROM key_usage) AS sum_tok,
                   (SELECT COUNT(*) FROM tg_users WHERE created_at LIKE ?) AS n_new
        """, (today,)).fetchone()
        ranks = {int(x[0] or 0): int(x[1]) for x in c.execute(
            "SELECT rank, COUNT(*) FROM tg_users GROUP BY rank").fetchall()}
        models = (c.execute("SELECT COUNT(*) FROM mappings").fetchone()[0]
                  if table_exists(c, "mappings") else 0)
        ups = (c.execute("SELECT COUNT(*) FROM upstreams").fetchone()[0]
               if table_exists(c, "upstreams") else 0)
        unlim = c.execute("SELECT COUNT(*) FROM api_keys "
                          "WHERE COALESCE(token_limit,0)=0").fetchone()[0]
    return {"users": r["n_users"], "banned": r["n_banned"], "keys": r["n_keys"],
            "requests": r["sum_req"] or 0, "tokens": r["sum_tok"] or 0,
            "models": models, "ups": ups, "ranks": ranks,
            "new_today": r["n_new"], "unlimited": unlim}


def render_admin_home() -> tuple[str, dict]:
    s = admin_stats()
    text = (
        f"🛠 <b>Админ-панель</b>\n{SEP}\n"
        f"👥 Пользователи: <b>{s['users']}</b> · новых сегодня: {s['new_today']}\n"
        f"🚫 Забанено: <b>{s['banned']}</b>\n"
        f"🔑 Ключей: <b>{s['keys']}</b>\n"
        f"📈 Запросов: <b>{human(s['requests'])}</b>\n"
        f"🔋 Токенов: <b>{human(s['tokens'])}</b>\n"
        f"🧩 Моделей: <b>{s['models']}</b> · 🏦 Апстримов: <b>{s['ups']}</b>\n"
        f"{SEP}\n"
        f"📊 Ранги: 🌱 {s['ranks'].get(1,0)} · ⚡ {s['ranks'].get(2,0)} · 👑 {s['ranks'].get(3,0)}"
        + (f"\n🔓 Безлимитных ключей: <b>{s['unlimited']}</b>" if s.get("unlimited") else "")
    )
    rows = [
        [btn("👥 Пользователи", "a:users:0"), btn("🩺 Диагностика", "a:probe")],
        [btn("🧩 Модели", "a:models"), btn("🏦 Апстримы", "a:ups")],
        [btn("📈 Топ по расходу", "a:top"), btn("🆕 Новые", "a:new")],
        [btn("🎁 Выдать токены", "a:bonus"), btn("🏅 Выдать ранг", "a:setrank")],
        [btn("📢 Рассылка", "a:broadcast"), btn("✉️ Написать юзеру", "a:dm")],
        [btn("🔎 Поиск", "a:search"), btn("🚫 Баны", "a:bans")],
        [btn("📤 Экспорт CSV", "a:csv"), btn("🧹 Сервис", "a:service")],
        [btn("⚙️ Настройки", "a:settings"), btn("🧾 События", "a:events")],
        [btn("🔓 Безлимитные ключи", "a:unlim")],
        [btn("◀ В меню", "m:menu")],
    ]
    return text, kb(rows)


def render_admin_users(page: int) -> tuple[str, dict]:
    per = 8
    with db() as c:
        total = c.execute("SELECT COUNT(*) FROM tg_users").fetchone()[0]
        rows = c.execute("""SELECT u.*, COALESCE(ku.billed_tokens,0) AS used
                            FROM tg_users u
                            LEFT JOIN api_keys k ON k.id = (
                                SELECT id FROM api_keys WHERE tg_id=u.tg_id ORDER BY id DESC LIMIT 1)
                            LEFT JOIN key_usage ku ON ku.key_id = k.id
                            ORDER BY u.created_at DESC LIMIT ? OFFSET ?""",
                         (per, page * per)).fetchall()
    lines = [f"👥 <b>Пользователи</b> · стр. {page + 1}/{max(1, (total + per - 1) // per)}\n{SEP}"]
    buttons = []
    for r in rows:
        name = esc(r["username"] or r["first_name"] or "—")
        flag = " 🚫" if r["banned"] else ""
        lines.append(f"<code>{r['tg_id']}</code> @{name} · {human(r['used'])} · "
                     f"{RANK_TIERS.get(int(r['rank'] or 0), RANK_TIERS[0])[1]}{flag}")
        buttons.append([btn(f"{r['tg_id']} · @{name[:14]}", f"a:u:{r['tg_id']}")])
    nav = []
    if page > 0:
        nav.append(btn("◀", f"a:users:{page - 1}"))
    nav.append(btn("◀ Админка", "a:home"))
    if (page + 1) * per < total:
        nav.append(btn("▶", f"a:users:{page + 1}"))
    buttons.append(nav)
    return ("\n".join(lines), kb(buttons))


def render_admin_user(tg_id: int) -> tuple[str, dict]:
    u = get_user(tg_id)
    if not u:
        return ("Пользователь не найден.", kb([[btn("◀ Назад", "a:users:0")]]))
    k = user_key(tg_id)
    st = key_stats(k["id"]) if k else {"requests": 0, "billed": 0, "in": 0, "out": 0, "last": ""}
    text = (
        f"👤 <b>Пользователь {tg_id}</b>\n{SEP}\n"
        f"Username: @{esc(u['username']) or '—'}\n"
        f"Имя: {esc(u['first_name'])}\n"
        f"Ранг: {rank_title(u['rank'])}{' 🔒' if int(u['rank_manual'] or 0) else ''}\n"
        f"Ключ: <code>{esc(mask_key(k['public_key']) if k else '—')}</code>\n"
        f"Токены сегодня: <b>{human(st['billed'])}</b> / <b>{human((k['token_limit'] if k else 0)) or INF}</b>\n"
        f"Всего сожжено: <b>{human(total_used(tg_id))}</b>\n"
        f"Запросов: <b>{st['requests']}</b>\n"
        f"Рефералы: {confirmed_refs(tg_id)}/{total_refs(tg_id)}\n"
        f"Подписка: {'✅ есть' if u['subscribed'] else '❌ нет'}\n"
        f"Бонусы: ник {human(u.get('bonus_name') or 0)} · био {human(u.get('bonus_bio') or 0)}\n"
        f"Био: {esc((u['bio'] or '—')[:60])}\n"
        f"Пригласил: {esc(u['referred_by'] or '—')}\n"
        f"Бан: {'да' if u['banned'] else 'нет'}\n"
        f"Создан: {esc(u['created_at'][:16])}"
    )
    rows = [
        [btn("🎁 +токены", f"a:u:{tg_id}:bonus"), btn("🏅 ранг", f"a:u:{tg_id}:rank")],
        [btn("🔄 рефреᵢш ключ", f"a:u:{tg_id}:rekey"), btn("♻️ сброс usage", f"a:u:{tg_id}:reset")],
        [btn("🚫 бан" if not u["banned"] else "✅ разбан", f"a:u:{tg_id}:ban"),
         btn("🗑 удалить", f"a:u:{tg_id}:del")],
        [btn("✉️ написать", f"a:u:{tg_id}:dm"), btn("⬆️ ранги пересчитать", f"a:u:{tg_id}:sync")],
        [btn("🔄 проверить подписку", f"a:u:{tg_id}:sub"),
         btn("🎁 проверить профиль", f"a:u:{tg_id}:prof")],
        [btn("♻️ авто-ранг", f"a:u:{tg_id}:autorank")],
        [btn("◀ Назад", "a:users:0")],
    ]
    return text, kb(rows)


def render_admin_models() -> tuple[str, dict]:
    try:
        with db() as c:
            rows = c.execute("""SELECT fake_model, real_model, upstream_id, enabled, endpoint_mode,
                                       context_length, system_prompt
                                FROM mappings ORDER BY id""").fetchall()
    except DB_ERRORS:
        return ("🧩 <b>Модели</b>\n" + SEP + "\nБаза прокси ещё не создала таблицу <code>mappings</code>.",
                kb([[btn("🔄", "a:models"), btn("◀ Админка", "a:home")]]))
    lines = [f"🧩 <b>Модели</b>\n{SEP}"]
    buttons = []
    for r in rows:
        mark = "🟢" if r["enabled"] else "⚪️"
        sysm = " · sys" if (r["system_prompt"] or "").strip() else ""
        lines.append(f"{mark} <code>{esc(r['fake_model'])}</code> → "
                     f"<code>{esc(r['real_model'])}</code>{sysm}")
        buttons.append([btn(f"{'🟢' if r['enabled'] else '⚪️'} {r['fake_model']}",
                            f"a:m:{r['fake_model']}")])
    buttons.append([btn("🔄 Обновить", "a:models"), btn("◀ Админка", "a:home")])
    return ("\n".join(lines), kb(buttons))


def render_admin_ups() -> tuple[str, dict]:
    try:
        with db() as c:
            rows = c.execute("SELECT id, name, url, enabled FROM upstreams ORDER BY id").fetchall()
    except DB_ERRORS:
        return ("🏦 <b>Апстримы</b>\n" + SEP + "\nТаблица <code>upstreams</code> ещё не создана.",
                kb([[btn("🔄", "a:ups"), btn("◀ Админка", "a:home")]]))
    lines = [f"🏦 <b>Апстримы</b>\n{SEP}"]
    buttons = []
    for r in rows:
        mark = "🟢" if r["enabled"] else "⚪️"
        lines.append(f"{mark} #{r['id']} <b>{esc(r['name'])}</b>\n   <code>{esc(r['url'])}</code>")
        buttons.append([btn(f"{mark} #{r['id']} {r['name'][:18]}", f"a:up:{r['id']}")])
    buttons.append([btn("◀ Админка", "a:home")])
    return ("\n".join(lines), kb(buttons))


def unlimited_keys() -> list:
    """Ключи, у которых token_limit=0 — в учёте это «без лимита»."""
    try:
        with db() as c:
            return c.execute("SELECT id, tg_id, note, public_key FROM api_keys "
                             "WHERE COALESCE(token_limit,0)=0 ORDER BY id").fetchall()
    except DB_ERRORS:
        return []


def render_unlimited() -> tuple[str, dict]:
    rows = unlimited_keys()
    lines = [f"🔓 <b>Безлимитные ключи</b>\n{SEP}"]
    for r in rows:
        who = f"tg {r['tg_id']}" if r["tg_id"] else "панель"
        lines.append(f"#{r['id']} · {who} · <code>{esc(mask_key(r['public_key']))}</code>")
    if not rows:
        lines.append("нет — у всех ключей есть лимит")
    else:
        lines.append(f"\n<i>Кнопка выставит {human(BOT_DEFAULT_LIMIT)} токенов.</i>")
    buttons = []
    if rows:
        buttons.append([btn(f"🔒 Закрыть все ({len(rows)})", "a:unlim:fix")])
    buttons.append([btn("◀ Админка", "a:home")])
    return "\n".join(lines), kb(buttons)


def render_admin_top() -> tuple[str, dict]:
    with db() as c:
        rows = c.execute("""SELECT u.tg_id, u.username, COALESCE(ku.billed_tokens,0) AS used,
                                   COALESCE(ku.requests,0) AS req
                            FROM tg_users u
                            LEFT JOIN api_keys k ON k.id = (
                                SELECT id FROM api_keys WHERE tg_id=u.tg_id ORDER BY id DESC LIMIT 1)
                            LEFT JOIN key_usage ku ON ku.key_id=k.id
                            ORDER BY used DESC LIMIT 10""").fetchall()
    lines = [f"📈 <b>Топ по расходу</b>\n{SEP}"]
    for i, r in enumerate(rows, 1):
        lines.append(f"{i}. <code>{r['tg_id']}</code> @{esc(r['username']) or '—'} — "
                     f"<b>{human(r['used'])}</b> · {r['req']} req")
    return ("\n".join(lines), kb([[btn("◀ Админка", "a:home")]]))


def render_admin_events() -> tuple[str, dict]:
    with db() as c:
        rows = c.execute("SELECT * FROM tg_events ORDER BY id DESC LIMIT 15").fetchall()
    lines = [f"🧾 <b>События</b>\n{SEP}"]
    for r in rows:
        lines.append(f"<code>{r['ts'][:16]}</code> {esc(r['kind'])} · {r['tg_id']} · {esc(r['text'][:40])}")
    if not rows:
        lines.append("пусто")
    return ("\n".join(lines), kb([[btn("🔄", "a:events"), btn("◀ Админка", "a:home")]]))


def render_service() -> tuple[str, dict]:
    rows = [
        [btn("♻️ Перечитать базу прокси", "a:svc:reload")],
        [btn("🔍 Проверить все модели", "a:svc:probe")],
        [btn("◀ Админка", "a:home")],
    ]
    text = (f"🧹 <b>Сервис</b>\n{SEP}\n"
            f"База: <code>{esc(DB_FILE)}</code>\n"
            f"Прокси: <code>{esc(PROXY_BASE)}</code>\n"
            f"{SEP}\n<i>Действия применяются сразу.</i>")
    return text, kb(rows)


def render_settings() -> tuple[str, dict]:
    ladder = "\n".join(
        f"{RANK_TIERS[r][1]} {RANK_TIERS[r][0]} — <b>{human(DAILY_TOKENS[r])}</b>/день"
        for r in (1, 2, 3))
    text = (
        f"⚙️ <b>Настройки</b>\n{SEP}\n"
        f"<b>Дневные квоты</b>\n{ladder}\n"
        f"✅ Чек-ин: <b>+{human(CHECKIN_TOKENS)}</b> раз в сутки\n"
        f"⏰ Сброс: <b>00:00</b> (UTC{RESET_TZ_OFFSET:+g})\n{SEP}\n"
        f"Бонус за реферала: <b>{human(REF_BONUS)}</b> (постоянный)\n"
        f"Бонусы профиля: ник <b>+{human(BONUS_NAME)}</b> · био <b>+{human(BONUS_BIO)}</b>\n"
        f"Тег для бонусов: <b>{esc(BONUS_TAG)}</b>\n"
        f"Подтверждение реферала: <b>{REF_CONFIRM_REQUESTS}</b> запросов + подписка\n"
        f"Обязательная подписка: <b>{esc(REQUIRED_CHANNEL_ID or '—')}</b> / <b>{esc(REQUIRED_CHAT_ID or '—')}</b>\n"
        f"Профи: <b>{human(RANK2_TOKENS)}</b> всего + <b>{RANK2_REFS}</b> реф.\n"
        f"Легенда: <b>{human(RANK3_TOKENS)}</b> всего + <b>{RANK3_REFS}</b> реф.\n"
        f"RPM по умолчанию: <b>{DEFAULT_RPM}</b>\n"
        f"Формат ключа: <b>{esc(KEY_FORMAT)}</b>\n"
        f"{SEP}\n<i>Меняется переменными окружения бота.</i>"
    )
    return text, kb([[btn("◀ Админка", "a:home")]])


# ══════════════════════════════════════════════════════════════════════
#  CALLBACK HANDLERS
# ══════════════════════════════════════════════════════════════════════

INPUT: dict[int, dict] = {}


async def show(chat_id: int, message_id: Optional[int], text: str, markup: dict) -> None:
    if message_id:
        await edit(chat_id, message_id, text, markup)
    else:
        await send(chat_id, text, markup)


async def on_start(tg_id: int, name: str, username: str, payload: str) -> None:
    referred_by = 0
    m = re.match(r"^ref_(\d+)$", payload or "")
    if m:
        rid = int(m.group(1))
        if rid != tg_id and get_user(rid):
            referred_by = rid
    existed = get_user(tg_id) is not None
    u = upsert_user(tg_id, username, name, 0 if existed else referred_by)
    if not user_key(tg_id):
        key = create_key_for(tg_id, f"TG {username or tg_id}", 0, 0)
        with db() as c:
            c.execute("UPDATE tg_users SET api_key=? WHERE tg_id=?", (key, tg_id))
            c.commit()
        log_event(tg_id, "register", f"key {mask_key(key)}")
        if referred_by:
            log_event(referred_by, "referral", f"new user {tg_id}")
    refresh_quota(tg_id)
    await refresh_profile_bonuses(tg_id, force=True)
    if tg_id != ADMIN_ID:
        ok_sub, missing = await subscription_state(tg_id, force=True)
        apply_subscription(tg_id, ok_sub)
        if not ok_sub:
            text, markup = render_gate(missing)
            await send(tg_id, text, markup)
            return
    text, markup = render_menu(tg_id, name or username or str(tg_id))
    await send(tg_id, text, markup)


async def on_callback(cq: dict) -> None:
    cb_id = cq["id"]
    data = cq.get("data") or ""
    msg = cq.get("message") or {}
    chat_id = (msg.get("chat") or {}).get("id") or cq["from"]["id"]
    message_id = msg.get("message_id")
    tg_id = cq["from"]["id"]
    is_admin = tg_id == ADMIN_ID
    if not (data.startswith("m:ping:") or data in ("m:checkin", "m:gatesub")):
        await answer_cb(cb_id)

    try:
        if data.startswith("a:") and not is_admin:
            await send(chat_id, "⛔️ Доступ только для владельца.")
            return

        # без подписки любое действие ведёт на ворота
        if not is_admin and data != "m:gatesub":
            ok_sub, missing = await subscription_state(tg_id)
            if not ok_sub:
                apply_subscription(tg_id, False)
                text, markup = render_gate(missing)
                await show(chat_id, message_id, text, markup)
                return

        if data == "m:gatesub":
            ok_sub, missing = await subscription_state(tg_id, force=True)
            apply_subscription(tg_id, ok_sub)
            if ok_sub:
                await answer_cb(cb_id, "Подписка подтверждена ✅", alert=True)
                u = get_user(tg_id)
                text, markup = render_menu(tg_id, (u["first_name"] if u else "") or str(tg_id))
            else:
                await answer_cb(cb_id, "Пока не вижу подписку: " + ", ".join(missing),
                                alert=True)
                text, markup = render_gate(missing)
            await show(chat_id, message_id, text, markup)
            return

        if data == "m:menu":
            await refresh_profile_bonuses(tg_id)
            u = get_user(tg_id)
            text, markup = render_menu(tg_id, (u["first_name"] if u else "") or str(tg_id))
            await show(chat_id, message_id, text, markup)
            return

        if data == "m:checkin":
            u = get_user(tg_id)
            if not u:
                return
            if checked_in_today(u):
                await answer_cb(cb_id, "Чек-ин уже взят сегодня. Новый — после 00:00.",
                                alert=True)
            else:
                first = int(u["rank"] or 0) < 1
                with db() as c:
                    c.execute("UPDATE tg_users SET rank=MAX(rank,1), checkin_at=? WHERE tg_id=?",
                              (local_now_str(), tg_id))
                    c.execute("UPDATE api_keys SET rank=MAX(rank,1) WHERE tg_id=?", (tg_id,))
                    c.commit()
                log_event(tg_id, "checkin", f"+{CHECKIN_TOKENS}")
                sync_rank(tg_id)
                lim = refresh_quota(tg_id)
                await answer_cb(
                    cb_id,
                    ("Доступ открыт: 🌱 Новичок\n" if first else "") +
                    f"+{human(CHECKIN_TOKENS)} токенов\nЛимит на сегодня: {human(lim)}",
                    alert=True)
            text, markup = render_menu(tg_id, (u["first_name"] if u else "") or str(tg_id))
            await show(chat_id, message_id, text, markup)
            return

        if data == "m:profile":
            await refresh_profile_bonuses(tg_id, force=True)
            sync_rank(tg_id)
            text, markup = render_profile(tg_id)
            await show(chat_id, message_id, text, markup)
            return

        if data == "m:key":
            text, markup = render_key(tg_id)
            await show(chat_id, message_id, text, markup)
            return

        if data == "m:rank":
            await refresh_profile_bonuses(tg_id, force=True)
            sync_rank(tg_id)
            text, markup = render_rank(tg_id)
            await show(chat_id, message_id, text, markup)
            return

        if data == "m:ref":
            text, markup = render_ref(tg_id, _me.get("username") or "your_bot")
            await show(chat_id, message_id, text, markup)
            return

        if data.startswith("m:models"):
            force = data.endswith(":force")
            text, markup = await render_models(tg_id, force=force)
            await show(chat_id, message_id, text, markup)
            return

        if data.startswith("m:ping:"):
            model = data.split(":", 2)[2]
            ch = (await probe_models(force=True)).get(model) or {}
            await answer_cb(cb_id, f"{model}: {ch.get('state','?')} · {ch.get('ms','—')} ms",
                            alert=True)
            return

        if data == "m:copykey":
            k = user_key(tg_id)
            if k:
                await send(chat_id, f"<code>{esc(k['public_key'])}</code>")
            return

        if data == "m:copyurl":
            await send(chat_id, f"<code>{esc(PROXY_BASE)}</code>")
            return

        if data == "m:copyref":
            link = f"https://t.me/{_me.get('username') or 'your_bot'}?start=ref_{tg_id}"
            await send(chat_id, f"<code>{esc(link)}</code>")
            return

        # ── админка ──
        if data == "a:home":
            text, markup = render_admin_home()
            await show(chat_id, message_id, text, markup)
            return

        if data.startswith("a:users:"):
            parts = data.split(":")
            if len(parts) == 3 and parts[2].isdigit():
                text, markup = render_admin_users(int(parts[2]))
                await show(chat_id, message_id, text, markup)
            return

        if data.startswith("a:u:"):
            parts = data.split(":")
            uid = int(parts[2])
            action = parts[3] if len(parts) > 3 else ""
            if not action:
                text, markup = render_admin_user(uid)
                await show(chat_id, message_id, text, markup)
                return
            await admin_user_action(chat_id, message_id, cq, uid, action)
            return

        if data == "a:models":
            text, markup = render_admin_models()
            await show(chat_id, message_id, text, markup)
            return

        if data.startswith("a:m:"):
            model = data[4:]
            with db() as c:
                c.execute("UPDATE mappings SET enabled = 1 - enabled WHERE fake_model=?", (model,))
                c.commit()
            text, markup = render_admin_models()
            await show(chat_id, message_id, text, markup)
            return

        if data == "a:ups":
            text, markup = render_admin_ups()
            await show(chat_id, message_id, text, markup)
            return

        if data.startswith("a:up:"):
            uid = int(data.split(":")[2])
            with db() as c:
                c.execute("UPDATE upstreams SET enabled = 1 - enabled WHERE id=?", (uid,))
                c.commit()
                row = c.execute("SELECT name, enabled FROM upstreams WHERE id=?", (uid,)).fetchone()
            await answer_cb(cb_id, f"{row['name']}: {'on' if row['enabled'] else 'off'}", alert=True)
            text, markup = render_admin_ups()
            await show(chat_id, message_id, text, markup)
            return

        if data == "a:probe":
            channels = await probe_models(force=True)
            if "error" in channels:
                await send(chat_id, f"⚠️ {esc(channels['error'])}")
                return
            lines = [f"🩺 <b>Диагностика</b>\n{SEP}"]
            for name in sorted(channels):
                ch = channels[name] or {}
                st = ch.get("state")
                icon = {"ok": "🟢", "down": "🔴"}.get(st, "🟡")
                lines.append(f"{icon} <code>{esc(name)}</code> · {ch.get('ms','—')} ms"
                             + (f" · {esc(ch.get('detail',''))[:40]}" if ch.get("detail") else ""))
            await show(chat_id, message_id, "\n".join(lines),
                       kb([[btn("🔄", "a:probe"), btn("◀ Админка", "a:home")]]))
            return

        if data == "a:top":
            text, markup = render_admin_top()
            await show(chat_id, message_id, text, markup)
            return

        if data == "a:new":
            with db() as c:
                rows = c.execute("SELECT tg_id, username, created_at FROM tg_users "
                                 "ORDER BY created_at DESC LIMIT 10").fetchall()
            lines = [f"🆕 <b>Новые</b>\n{SEP}"]
            for r in rows:
                lines.append(f"<code>{r['tg_id']}</code> @{esc(r['username']) or '—'} · "
                             f"{esc(r['created_at'][:16])}")
            await show(chat_id, message_id, "\n".join(lines), kb([[btn("◀ Админка", "a:home")]]))
            return

        if data == "a:bans":
            with db() as c:
                rows = c.execute("SELECT tg_id, username FROM tg_users WHERE banned=1").fetchall()
            lines = [f"🚫 <b>Баны</b>\n{SEP}"]
            buttons = []
            for r in rows:
                lines.append(f"<code>{r['tg_id']}</code> @{esc(r['username']) or '—'}")
                buttons.append([btn(f"✅ {r['tg_id']}", f"a:u:{r['tg_id']}:ban")])
            if not rows:
                lines.append("пусто")
            buttons.append([btn("◀ Админка", "a:home")])
            await show(chat_id, message_id, "\n".join(lines), kb(buttons))
            return

        if data == "a:service":
            text, markup = render_service()
            await show(chat_id, message_id, text, markup)
            return

        if data.startswith("a:svc:"):
            what = data.split(":")[2]
            if what == "probe":
                channels = await probe_models(force=True)
                await answer_cb(cb_id, f"моделей: {len(channels)}", alert=True)
            else:
                await answer_cb(cb_id, "прокси перечитывает базу сам каждые RELOAD_SEC", alert=True)
            return

        if data == "a:settings":
            text, markup = render_settings()
            await show(chat_id, message_id, text, markup)
            return

        if data == "a:events":
            text, markup = render_admin_events()
            await show(chat_id, message_id, text, markup)
            return

        if data == "a:csv":
            await export_csv(chat_id)
            return

        if data == "a:unlim":
            text, markup = render_unlimited()
            await show(chat_id, message_id, text, markup)
            return

        if data == "a:unlim:fix":
            rows = unlimited_keys()
            with db() as c:
                c.execute("UPDATE api_keys SET token_limit=? WHERE COALESCE(token_limit,0)=0",
                          (BOT_DEFAULT_LIMIT,))
                c.commit()
            log_event(0, "unlim_fix", f"{len(rows)} keys -> {BOT_DEFAULT_LIMIT}")
            await answer_cb(cb_id, f"выставлен лимит {len(rows)} ключам", alert=True)
            text, markup = render_unlimited()
            await show(chat_id, message_id, text, markup)
            return

        if data == "a:bonus":
            INPUT[tg_id] = {"kind": "bonus"}
            await send(chat_id, "🎁 <b>Выдать токены</b>\n\nОтправь: <code>id сумма</code>\n"
                                "Например: <code>123456789 1000000</code>")
            return

        if data == "a:setrank":
            INPUT[tg_id] = {"kind": "setrank"}
            await send(chat_id, "🏅 <b>Выдать ранг</b>\n\nОтправь: <code>id ранг(0-3)</code>")
            return

        if data == "a:broadcast":
            INPUT[tg_id] = {"kind": "broadcast"}
            await send(chat_id, "📢 <b>Рассылка</b>\n\nОтправь текст сообщения (HTML разрешён).")
            return

        if data == "a:dm":
            INPUT[tg_id] = {"kind": "dm"}
            await send(chat_id, "✉️ <b>Сообщение юзеру</b>\n\nОтправь: <code>id текст</code>")
            return

        if data == "a:search":
            INPUT[tg_id] = {"kind": "search"}
            await send(chat_id, "🔎 <b>Поиск</b>\n\nОтправь id, часть ключа или username.")
            return

    except Exception as e:                       # noqa: BLE001
        log.exception("callback %s failed", data)
        try:
            await send(chat_id, f"⚠️ Ошибка: {esc(repr(e)[:200])}")
        except Exception:
            pass


async def admin_user_action(chat_id: int, message_id: Optional[int], cq: dict,
                            uid: int, action: str) -> None:
    cb_id = cq["id"]
    if action == "bonus":
        INPUT[ADMIN_ID] = {"kind": "bonus", "ctx": {"uid": uid}}
        await send(chat_id, f"🎁 Сколько токенов выдать <code>{uid}</code>? (число, можно с минусом)")
        return
    if action == "rank":
        buttons = [[btn(f"{name} {icon}", f"a:set:{uid}:{r}")]
                   for r, (name, icon) in sorted(RANK_TIERS.items())]
        buttons.append([btn("◀ Назад", f"a:u:{uid}")])
        await show(chat_id, message_id, f"🏅 Ранг для <code>{uid}</code>:", kb(buttons))
        return
    if action.startswith("set") or action == "":
        pass
    if action == "rekey":
        old_rank = int((get_user(uid) or {"rank": 0})["rank"] or 0)
        key = create_key_for(uid, f"TG {uid} reissue", 0, old_rank)
        with db() as c:
            c.execute("UPDATE api_keys SET enabled=0 WHERE tg_id=? AND public_key<>?", (uid, key))
            c.execute("UPDATE tg_users SET api_key=? WHERE tg_id=?", (key, uid))
            c.commit()
        refresh_quota(uid)
        log_event(uid, "rekey", mask_key(key))
        await answer_cb(cb_id, "Ключ перевыпущен", alert=True)
        text, markup = render_admin_user(uid)
        await show(chat_id, message_id, text, markup)
        return
    if action == "reset":
        k = user_key(uid)
        if k:
            with db() as c:
                c.execute("DELETE FROM key_usage WHERE key_id=?", (k["id"],))
                c.commit()
        await answer_cb(cb_id, "Usage сброшен", alert=True)
        text, markup = render_admin_user(uid)
        await show(chat_id, message_id, text, markup)
        return
    if action == "ban":
        with db() as c:
            c.execute("UPDATE tg_users SET banned = 1 - banned WHERE tg_id=?", (uid,))
            row = c.execute("SELECT banned FROM tg_users WHERE tg_id=?", (uid,)).fetchone()
            c.execute("UPDATE api_keys SET enabled=? WHERE tg_id=?",
                      (0 if row["banned"] else 1 if int((get_user(uid) or {"subscribed": 0})["subscribed"] or 0) else 0, uid))
            c.commit()
        log_event(uid, "ban", str(row["banned"]))
        await answer_cb(cb_id, "Забанен" if row["banned"] else "Разбанен", alert=True)
        text, markup = render_admin_user(uid)
        await show(chat_id, message_id, text, markup)
        return
    if action == "del":
        with db() as c:
            c.execute("DELETE FROM api_keys WHERE tg_id=?", (uid,))
            c.execute("DELETE FROM tg_users WHERE tg_id=?", (uid,))
            c.commit()
        log_event(uid, "delete", "")
        await answer_cb(cb_id, "Удалён", alert=True)
        text, markup = render_admin_users(0)
        await show(chat_id, message_id, text, markup)
        return
    if action == "dm":
        INPUT[ADMIN_ID] = {"kind": "dm", "ctx": {"uid": uid}}
        await send(chat_id, f"✉️ Текст для <code>{uid}</code>:")
        return
    if action == "sync":
        old, new = sync_rank(uid)
        await answer_cb(cb_id, f"ранг: {old} → {new}", alert=True)
        text, markup = render_admin_user(uid)
        await show(chat_id, message_id, text, markup)
        return
    if action == "sub":
        ok_sub, missing = await subscription_state(uid, force=True)
        apply_subscription(uid, ok_sub)
        await answer_cb(cb_id, "подписан" if ok_sub else "нет: " + ", ".join(missing), alert=True)
        text, markup = render_admin_user(uid)
        await show(chat_id, message_id, text, markup)
        return
    if action == "prof":
        res = await refresh_profile_bonuses(uid, force=True)
        await answer_cb(cb_id, f"ник +{human(BONUS_NAME if res.get('name_hit') else 0)} · "
                               f"био +{human(BONUS_BIO if res.get('bio_hit') else 0)}", alert=True)
        text, markup = render_admin_user(uid)
        await show(chat_id, message_id, text, markup)
        return
    if action == "autorank":
        with db() as c:
            c.execute("UPDATE tg_users SET rank_manual=0 WHERE tg_id=?", (uid,))
            c.commit()
        old, new = sync_rank(uid)
        await answer_cb(cb_id, f"авто-ранг: {old} → {new}", alert=True)
        text, markup = render_admin_user(uid)
        await show(chat_id, message_id, text, markup)
        return


async def export_csv(chat_id: int) -> None:
    import io
    buf = io.StringIO()
    buf.write("tg_id,username,rank,banned,key_masked,tokens_used,token_limit,requests,refs,created\n")
    with db() as c:
        rows = c.execute("""SELECT u.*, COALESCE(ku.billed_tokens,0) AS used,
                                   COALESCE(ku.requests,0) AS req,
                                   COALESCE(k.token_limit,0) AS lim,
                                   COALESCE(k.public_key,'') AS pk
                            FROM tg_users u
                            LEFT JOIN api_keys k ON k.id = (
                                SELECT id FROM api_keys WHERE tg_id=u.tg_id ORDER BY id DESC LIMIT 1)
                            LEFT JOIN key_usage ku ON ku.key_id=k.id
                            ORDER BY u.created_at""").fetchall()
    for r in rows:
        buf.write(f"{r['tg_id']},{r['username']},{r['rank']},{r['banned']},"
                  f"{mask_key(r['pk'])},{r['used']},{r['lim']},{r['req']},"
                  f"{confirmed_refs(r['tg_id'])},{r['created_at']}\n")
    data = buf.getvalue().encode()
    if client is None:
        return
    try:
        await client.post(
            f"https://api.telegram.org/bot{BOT_TOKEN}/sendDocument",
            data={"chat_id": str(chat_id), "caption": "users.csv"},
            files={"document": ("users.csv", data, "text/csv")},
            timeout=60.0,
        )
    except Exception as e:
        await send(chat_id, f"⚠️ Не отправилось: {esc(repr(e)[:120])}")


# ══════════════════════════════════════════════════════════════════════
#  TEXT INPUT (админ)
# ══════════════════════════════════════════════════════════════════════


async def on_text(msg: dict) -> None:
    tg_id = msg["from"]["id"]
    text = (msg.get("text") or "").strip()
    if not text:
        return
    if text.startswith("/start"):
        parts = text.split(maxsplit=1)
        payload = parts[1].strip() if len(parts) > 1 else ""
        f = msg["from"]
        await on_start(tg_id, f.get("first_name") or "", f.get("username") or "", payload)
        return
    if text in ("/menu", "/help"):
        u = get_user(tg_id)
        if tg_id != ADMIN_ID:
            ok_sub, missing = await subscription_state(tg_id)
            if not ok_sub:
                apply_subscription(tg_id, False)
                t, m = render_gate(missing)
                await send(tg_id, t, m)
                return
        t, m = render_menu(tg_id, (u["first_name"] if u else "") or str(tg_id))
        await send(tg_id, t, m)
        return
    if tg_id != ADMIN_ID:
        return
    if text == "/admin":
        t, m = render_admin_home()
        await send(tg_id, t, m)
        return

    st = INPUT.pop(tg_id, None)
    if not st:
        return
    kind = st.get("kind")
    ctx = st.get("ctx") or {}
    try:
        if kind == "bonus":
            uid = int(ctx.get("uid") or text.split()[0])
            amount = int(ctx["amount"] if "amount" in ctx else text.split()[-1])
            ok, lim = bump_tokens(uid, amount)
            await send(tg_id, "✅ Готово" if ok else "⚠️ Ключ не найден")
            if ok:
                log_event(uid, "bonus", f"{amount:+d}")
                await send(uid, f"🎁 Тебе начислено <b>{amount:+d}</b> токенов.\n"
                                f"Лимит: <b>{human(lim)}</b>")
                t, m = render_admin_user(uid)
                await send(tg_id, t, m)
        elif kind == "setrank":
            uid_s, rank_s = text.split()[:2]
            uid, rank = int(uid_s), max(0, min(3, int(rank_s)))
            with db() as c:
                c.execute("UPDATE tg_users SET rank=?, rank_manual=1 WHERE tg_id=?", (rank, uid))
                c.execute("UPDATE api_keys SET rank=? WHERE tg_id=?", (rank, uid))
                c.commit()
            refresh_quota(uid)
            log_event(uid, "setrank", f"{rank} manual")
            await send(tg_id, f"✅ {uid} → ранг {rank}")
            t, m = render_admin_user(uid)
            await send(tg_id, t, m)
        elif kind == "broadcast":
            with db() as c:
                rows = c.execute("SELECT tg_id FROM tg_users WHERE banned=0").fetchall()
            sent = failed = 0
            for r in rows:
                if await send(r["tg_id"], text):
                    sent += 1
                else:
                    failed += 1
                await asyncio.sleep(0.05)
            await send(tg_id, f"📢 Отправлено: {sent} · ошибок: {failed}")
        elif kind == "dm":
            if "uid" in ctx:
                uid, body = ctx["uid"], text
            else:
                uid_s, body = text.split(maxsplit=1)
                uid = int(uid_s)
            await send(uid, f"✉️ <b>Сообщение от администрации</b>\n{SEP}\n{body}")
            await send(tg_id, "✅ Отправлено")
        elif kind == "search":
            rows = []
            with db() as c:
                if text.isdigit():
                    rows = c.execute("SELECT * FROM tg_users WHERE tg_id=?", (int(text),)).fetchall()
                else:
                    rows = c.execute("SELECT * FROM tg_users WHERE username LIKE ? OR "
                                     "api_key LIKE ? LIMIT 10",
                                     (f"%{text}%", f"%{text}%")).fetchall()
            if not rows:
                await send(tg_id, "Ничего не найдено")
                return
            for r in rows:
                k = user_key(r["tg_id"])
                await send(tg_id,
                           f"<code>{r['tg_id']}</code> @{esc(r['username']) or '—'} · "
                           f"ранг {r['rank']} · <code>{esc(mask_key(k['public_key']) if k else '—')}</code>",
                           kb([[btn("Открыть", f"a:u:{r['tg_id']}")]]))
    except Exception as e:                       # noqa: BLE001
        log.exception("input %s failed", kind)
        await send(tg_id, f"⚠️ {esc(repr(e)[:150])}")


async def on_callback_rank_choice(data: str) -> None:
    _, _, uid_s, rank_s = data.split(":")
    uid, rank = int(uid_s), int(rank_s)
    with db() as c:
        c.execute("UPDATE tg_users SET rank=?, rank_manual=1 WHERE tg_id=?", (rank, uid))
        c.execute("UPDATE api_keys SET rank=? WHERE tg_id=?", (rank, uid))
        c.commit()
    refresh_quota(uid)
    log_event(uid, "setrank", f"{rank} manual")
    t, m = render_admin_user(uid)
    await send(ADMIN_ID, t, m)


# ══════════════════════════════════════════════════════════════════════
#  BACKGROUND
# ══════════════════════════════════════════════════════════════════════


async def tick_loop() -> None:
    while True:
        try:
            for uid in daily_reset():
                u = get_user(uid)
                if u and int(u["rank"] or 0) >= 1:
                    await send(uid, f"🔄 Квота обновлена: <b>{human(daily_amount(u['rank']))}</b>"
                                    f" + чек-ин {human(CHECKIN_TOKENS)} ждёт в меню.")
            for inviter, uid in maybe_confirm_refs():
                await send(inviter, f"🎁 Реферал <code>{uid}</code> подтверждён.\n"
                                    f"Начислено <b>+{human(REF_BONUS)}</b> токенов.")
                sync_rank(inviter)
            with db() as c:
                rows = c.execute("SELECT tg_id FROM tg_users WHERE rank>0").fetchall()
            for r in rows:
                old, new = sync_rank(r["tg_id"])
                if new > old:
                    await send(r["tg_id"], f"🏅 Новый ранг: {rank_title(new)}\n"
                                           f"Квота: <b>{human(daily_amount(new))}</b>/день\n"
                                           f"Модели: {models_for(new)}")
        except Exception as e:                   # noqa: BLE001
            log.warning("tick: %r", e)
        await asyncio.sleep(TICK_SEC)


async def poll_loop() -> None:
    offset = 0
    while True:
        try:
            updates = await api("getUpdates", offset=offset, timeout=25,
                                allowed_updates=["message", "callback_query"])
            for up in updates or []:
                offset = max(offset, int(up["update_id"]) + 1)
                if "callback_query" in up:
                    cb = up["callback_query"]
                    if (cb.get("data") or "").startswith("a:set:"):
                        await answer_cb(cb["id"])
                        await on_callback_rank_choice(cb["data"])
                    else:
                        await on_callback(cb)
                elif "message" in up:
                    await on_text(up["message"])
        except asyncio.CancelledError:
            raise
        except Exception as e:                   # noqa: BLE001
            log.warning("poll: %r", e)
            await asyncio.sleep(3)


async def main() -> None:
    global client, _me
    init_db()
    client = httpx.AsyncClient(timeout=httpx.Timeout(connect=10.0, read=60.0,
                                                     write=60.0, pool=10.0))
    _me = await api("getMe") or {}
    log.info("bot @%s up | db=%s | proxy=%s | admin=%s",
             _me.get("username"), DB_FILE, PROXY_BASE, ADMIN_ID)
    try:
        await asyncio.gather(poll_loop(), tick_loop(), enforce_loop(), profile_loop())
    finally:
        await client.aclose()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
