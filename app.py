from dotenv import load_dotenv
load_dotenv()

import os
import json
import sqlite3
import ipaddress
import time
import secrets
import base64
import argparse
from datetime import datetime, timedelta, date
from typing import Optional, Dict, Any, List

import boto3
from botocore.config import Config as BotoConfig
import httpx
from apscheduler.schedulers.background import BackgroundScheduler
from dateutil.tz import tzlocal
from passlib.hash import pbkdf2_sha256
from contextlib import asynccontextmanager

from fastapi import APIRouter, FastAPI, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse, HTMLResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates
from fastapi.security import APIKeyHeader

from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# ------------------------- Constants -------------------------
DB_PATH = "./enrichment.db"

# ------------------------- Settings -------------------------
class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    APP_HOST: str = "127.0.0.1"
    APP_PORT: int = 8000
    # development | production
    APP_ENV: str = "development"
    APP_GLOBAL_ALLOWLIST: Optional[str] = None

    REGION: str = "ap-southeast-2"
    NETBOX_BASE_URL: str

    # Secrets (dev vs prod)
    NETBOX_API_TOKEN: Optional[str] = None
    NETBOX_API_TOKEN__SECRET_NAME: Optional[str] = None

    SES_ROLE_ARN: Optional[str] = None
    SES_ROLE_ARN__PARAM_NAME: Optional[str] = None

    SES_FROM: str
    SES_TO: str
    EMAIL_TOP_N: int = 30

    CACHE_TTL_HOURS: int = 24
    RETENTION_DAYS: int = 90

    REFRESH_CRON_HOUR: int = 2
    REPORT_CRON_HOUR: int = 3

    # TLS / NetBox client options
    NETBOX_VERIFY_SSL: bool = True               # false disables TLS verification (testing only)
    NETBOX_CA_BUNDLE: Optional[str] = None       # path to custom CA bundle (takes precedence)

    # Behavior toggles
    NETBOX_ONDEMAND_LOOKUP: bool = True          # set false to rely on nightly cache only

settings = Settings()

# ------------------------- AWS helpers -------------------------
_boto = boto3.session.Session(region_name=settings.REGION)
_ssm = _boto.client("ssm", config=BotoConfig(retries={"max_attempts": 3}))
_secrets = _boto.client("secretsmanager", config=BotoConfig(retries={"max_attempts": 3}))

def _clean_token(tok: str) -> str:
    t = (tok or "").strip().strip('"').strip("'")
    if not t:
        raise RuntimeError("Empty NetBox token after parsing")
    return t

def get_netbox_token() -> str:
    if settings.APP_ENV.lower() == "development":
        return _clean_token(settings.NETBOX_API_TOKEN or "")
    # production: read from Secrets Manager, format "TOKEN:<value>"
    secret_name = settings.NETBOX_API_TOKEN__SECRET_NAME
    if not secret_name:
        raise RuntimeError("NETBOX_API_TOKEN__SECRET_NAME not set for production")
    resp = _secrets.get_secret_value(SecretId=secret_name)
    s = resp.get("SecretString") or (resp.get("SecretBinary") and resp["SecretBinary"].decode())
    if not s or not s.startswith("TOKEN:"):
        raise RuntimeError("Secret format invalid. Expected 'TOKEN:<value>'")
    return _clean_token(s.split(":", 1)[1])

def get_ses_role_arn() -> str:
    if settings.APP_ENV.lower() == "development":
        if not settings.SES_ROLE_ARN:
            raise RuntimeError("SES_ROLE_ARN not set for development")
        return settings.SES_ROLE_ARN
    param_name = settings.SES_ROLE_ARN__PARAM_NAME
    if not param_name:
        raise RuntimeError("SES_ROLE_ARN__PARAM_NAME not set for production")
    return _ssm.get_parameter(Name=param_name, WithDecryption=False)["Parameter"]["Value"]

def get_ses_client_assumed():
    arn = get_ses_role_arn()
    sts = _boto.client("sts")
    creds = sts.assume_role(RoleArn=arn, RoleSessionName="netbox-enrich-sender")["Credentials"]
    return boto3.client(
        "ses",
        region_name=settings.REGION,
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        config=BotoConfig(retries={"max_attempts": 3}),
    )

# ------------------------- DB init -------------------------
def db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = db()
    cur = conn.cursor()
    cur.executescript("""
    PRAGMA journal_mode=WAL;

    CREATE TABLE IF NOT EXISTS devices (
      ip TEXT PRIMARY KEY,
      hostname TEXT,
      status TEXT,
      device_url TEXT,
      site TEXT,
      location TEXT,
      role TEXT,
      type TEXT,
      tags_json TEXT,
      device_criticality TEXT,
      last_refreshed INTEGER,
      source TEXT
    );

    CREATE TABLE IF NOT EXISTS not_found (
      ip TEXT PRIMARY KEY,
      first_seen INTEGER,
      last_seen INTEGER,
      ttl_until INTEGER
    );

    CREATE TABLE IF NOT EXISTS hits (
      ip TEXT,
      day TEXT,
      count INTEGER,
      PRIMARY KEY (ip, day)
    );

    CREATE TABLE IF NOT EXISTS misses (
      ip TEXT,
      day TEXT,
      count INTEGER,
      PRIMARY KEY (ip, day)
    );

    CREATE TABLE IF NOT EXISTS api_keys (
      key_id TEXT PRIMARY KEY,
      hash   TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      expires_at INTEGER,
      status TEXT NOT NULL DEFAULT 'active',
      scopes TEXT
    );

    CREATE TABLE IF NOT EXISTS api_key_allowlist (
      key_id TEXT NOT NULL,
      cidr   TEXT NOT NULL,
      PRIMARY KEY (key_id, cidr),
      FOREIGN KEY (key_id) REFERENCES api_keys(key_id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_hits_day ON hits(day);
    CREATE INDEX IF NOT EXISTS idx_misses_day ON misses(day);
    """)
    conn.commit()
    conn.close()

init_db()

# ------------------------- API Key helpers -------------------------
def now_epoch() -> int:
    return int(time.time())

def create_api_key_record(key_id: str, raw_token: str, ttl_days: Optional[int], scopes: Optional[List[str]]):
    h = pbkdf2_sha256.hash(raw_token)
    now = now_epoch()
    exp = now + ttl_days * 86400 if ttl_days else None
    scopes_json = json.dumps(scopes or ["read"])
    conn = db()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO api_keys(key_id, hash, created_at, expires_at, status, scopes)
        VALUES (?,?,?,?,?,?)
    """, (key_id, h, now, exp, "active", scopes_json))
    conn.commit()
    conn.close()

def list_api_keys() -> List[sqlite3.Row]:
    conn = db(); cur = conn.cursor()
    cur.execute("SELECT key_id, created_at, expires_at, status, scopes FROM api_keys ORDER BY created_at DESC")
    rows = cur.fetchall()
    conn.close()
    return rows

def set_api_key_status(key_id: str, status: str) -> bool:
    conn = db(); cur = conn.cursor()
    cur.execute("UPDATE api_keys SET status=? WHERE key_id=?", (status, key_id))
    ok = cur.rowcount > 0
    conn.commit(); conn.close()
    return ok

def delete_api_key(key_id: str) -> bool:
    conn = db(); cur = conn.cursor()
    cur.execute("DELETE FROM api_keys WHERE key_id=?", (key_id,))
    ok = cur.rowcount > 0
    conn.commit(); conn.close()
    return ok

def get_key_allowlist(key_id: str) -> List[str]:
    conn = db(); cur = conn.cursor()
    cur.execute("SELECT cidr FROM api_key_allowlist WHERE key_id=?", (key_id,))
    rows = [r["cidr"] for r in cur.fetchall()]
    conn.close()
    return rows

def add_allowlist_cidrs(key_id: str, cidrs: List[str]) -> None:
    conn = db(); cur = conn.cursor()
    for c in cidrs:
        try:
            ipaddress.ip_network(c, strict=False)
        except ValueError:
            continue
        cur.execute("INSERT OR IGNORE INTO api_key_allowlist(key_id, cidr) VALUES (?,?)", (key_id, c))
    conn.commit(); conn.close()

def remove_allowlist_cidrs(key_id: str, cidrs: List[str]) -> None:
    conn = db(); cur = conn.cursor()
    for c in cidrs:
        cur.execute("DELETE FROM api_key_allowlist WHERE key_id=? AND cidr=?", (key_id, c))
    conn.commit(); conn.close()

def verify_api_key(key_id: str, token: str, required_scope: Optional[str] = None) -> bool:
    conn = db(); cur = conn.cursor()
    cur.execute("SELECT hash, status, expires_at, scopes FROM api_keys WHERE key_id=?", (key_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return False
    if row["status"] != "active":
        return False
    if row["expires_at"] and now_epoch() > int(row["expires_at"]):
        return False
    try:
        ok = pbkdf2_sha256.verify(token, row["hash"])
    except Exception:
        return False
    if not ok:
        return False
    if required_scope:
        try:
            scopes = json.loads(row["scopes"] or "[]")
        except Exception:
            scopes = []
        if required_scope not in scopes:
            return False
    return True

# ------------------------- Allowlist / client IP helpers -------------------------
def parse_cidrs(csv: Optional[str]) -> List[ipaddress._BaseNetwork]:
    if not csv:
        return []
    nets = []
    for s in [x.strip() for x in csv.split(",") if x.strip()]:
        try:
            nets.append(ipaddress.ip_network(s, strict=False))
        except ValueError:
            pass
    return nets

GLOBAL_ALLOW = parse_cidrs(settings.APP_GLOBAL_ALLOWLIST)

def request_ip(request: Request, xff: Optional[str]) -> str:
    if xff:
        ip = xff.split(",")[0].strip()
    else:
        ip = request.client.host if request.client else "0.0.0.0"

    try:
        addr = ipaddress.ip_address(ip)
        # if it’s a v4-mapped IPv6 (e.g. ::ffff:192.168.1.5), convert back to IPv4
        if addr.version == 6 and addr.ipv4_mapped:
            return str(addr.ipv4_mapped)
        return str(addr)
    except ValueError:
        return "0.0.0.0"

def is_ip_allowed(ip_str: str, per_key_cidrs: List[str]) -> bool:
    ip = ipaddress.ip_address(ip_str)
    per_key_nets = []
    for c in per_key_cidrs:
        try:
            per_key_nets.append(ipaddress.ip_network(c, strict=False))
        except ValueError:
            continue
    if per_key_nets:
        return any(ip in n for n in per_key_nets)
    if GLOBAL_ALLOW:
        return any(ip in n for n in GLOBAL_ALLOW)
    return True

# ------------------------- Auth deps -------------------------
api_key_id_header = APIKeyHeader(name="X-API-Key-Id", auto_error=False)
api_key_token_header = APIKeyHeader(name="X-API-Key", auto_error=False)
xff_header = APIKeyHeader(name="X-Forwarded-For", auto_error=False)

def require_api_key(
    request: Request,
    key_id: Optional[str] = Depends(api_key_id_header),
    token: Optional[str] = Depends(api_key_token_header),
    xff: Optional[str] = Depends(xff_header),
):
    if not key_id or not token:
        raise HTTPException(status_code=401, detail="Unauthorized")
    if not verify_api_key(key_id, token, required_scope="read"):
        raise HTTPException(status_code=403, detail="Forbidden")
    rip = request_ip(request, xff)
    if not is_ip_allowed(rip, get_key_allowlist(key_id)):
        raise HTTPException(status_code=403, detail="IP not allowed")
    return True

def require_admin_key(
    request: Request,
    key_id: Optional[str] = Depends(api_key_id_header),
    token: Optional[str] = Depends(api_key_token_header),
    xff: Optional[str] = Depends(xff_header),
):
    if not key_id or not token:
        raise HTTPException(status_code=401, detail="Unauthorized")
    if not verify_api_key(key_id, token, required_scope="admin"):
        raise HTTPException(status_code=403, detail="Forbidden")
    rip = request_ip(request, xff)
    if not is_ip_allowed(rip, get_key_allowlist(key_id)):
        raise HTTPException(status_code=403, detail="IP not allowed")
    return True

# ------------------------- NetBox Client -------------------------
class NetBoxClient:
    def __init__(self, base_url: str, token: str):
        self.base = base_url.rstrip("/")
        verify_opt = settings.NETBOX_CA_BUNDLE or settings.NETBOX_VERIFY_SSL
        self.client = httpx.Client(
            timeout=20.0,
            headers={"Authorization": f"Token {token}"},
            verify=verify_opt,
        )

    def _ui_device_url(self, device_id: int) -> str:
        return f"{self.base}/dcim/devices/{device_id}/"

    def _strip_ip(self, ip_cidr: str) -> str:
        return str(ipaddress.ip_interface(ip_cidr).ip)

    def list_active_with_primary_ipv4(self) -> List[Dict[str, Any]]:
        url = f"{self.base}/api/dcim/devices/"
        params = {"has_primary_ip": "true", "limit": 200}
        results: List[Dict[str, Any]] = []
        while url:
            r = self.client.get(url, params=params if "?" not in url else None)
            try:
                r.raise_for_status()
            except httpx.HTTPError as e:
                print(f"[netbox] devices list error: {e}")
                break
            data = r.json()
            for dev in data.get("results", []):
                pp = dev.get("primary_ip4")
                if not pp:
                    continue
                ip = self._strip_ip(pp["address"])
                tags = [t["name"] if isinstance(t, dict) and "name" in t else t for t in dev.get("tags", [])]
                cf = dev.get("custom_fields") or {}
                results.append({
                    "ip": ip,
                    "hostname": dev.get("name"),
                    "status": (dev.get("status", {}) or {}).get("value") or dev.get("status"),
                    "device_url": self._ui_device_url(dev["id"]),
                    "site": (dev.get("site") or {}).get("name"),
                    "location": (dev.get("location") or {}).get("name"),
                    "role": (dev.get("role") or {}).get("name"),
                    "type": (dev.get("device_type") or {}).get("model"),
                    "tags": tags,
                    "device_criticality": (cf.get("device_criticality") if isinstance(cf, dict) else None),
                })
            url = data.get("next")
        return results

    def lookup_by_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        # IP -> IPAM -> assigned device id -> device
        try:
            r = self.client.get(f"{self.base}/api/ipam/ip-addresses/", params={"address": ip, "limit": 1})
            if r.status_code in (401, 403):
                print(f"[netbox] permission issue on IPAM lookup for {ip}: {r.status_code}")
                return None
            r.raise_for_status()
        except httpx.HTTPError as e:
            print(f"[netbox] IPAM lookup error for {ip}: {e}")
            return None

        data = r.json()
        if not data.get("results"):
            return None

        ip_obj = data["results"][0]
        assigned = ip_obj.get("assigned_object")
        if not assigned:
            return None

        dev_id = None
        if assigned.get("device") and assigned["device"].get("id"):
            dev_id = assigned["device"]["id"]
        else:
            parent = assigned.get("parent")
            dev_id = (parent or {}).get("device", {}).get("id")

        if not dev_id:
            return None

        try:
            r2 = self.client.get(f"{self.base}/api/dcim/devices/{dev_id}/")
            if r2.status_code in (401, 403):
                print(f"[netbox] permission issue on device fetch for {ip} (dev {dev_id}): {r2.status_code}")
                return None
            r2.raise_for_status()
        except httpx.HTTPError as e:
            print(f"[netbox] device fetch error for {ip} (dev {dev_id}): {e}")
            return None

        dev = r2.json()
        tags = [t["name"] if isinstance(t, dict) and "name" in t else t for t in dev.get("tags", [])]
        cf = dev.get("custom_fields") or {}
        return {
            "ip": ip,
            "hostname": dev.get("name"),
            "status": (dev.get("status", {}) or {}).get("value") or dev.get("status"),
            "device_url": f"{self.base}/dcim/devices/{dev['id']}/",
            "site": (dev.get("site") or {}).get("name"),
            "location": (dev.get("location") or {}).get("name"),
            "role": (dev.get("role") or {}).get("name"),
            "type": (dev.get("device_type") or {}).get("model"),
            "tags": tags,
            "device_criticality": (cf.get("device_criticality") if isinstance(cf, dict) else None),
        }

def get_nb() -> NetBoxClient:
    return NetBoxClient(settings.NETBOX_BASE_URL, get_netbox_token())

# ------------------------- Cache & Stats -------------------------
def _today() -> str:
    return date.today().isoformat()

def _now_epoch() -> int:
    return int(time.time())

def record_hit(ip: str, miss: bool = False):
    conn = db(); cur = conn.cursor()
    table = "misses" if miss else "hits"
    d = _today()
    cur.execute(f"SELECT count FROM {table} WHERE ip=? AND day=?", (ip, d))
    row = cur.fetchone()
    if row:
        cur.execute(f"UPDATE {table} SET count=? WHERE ip=? AND day=?", (row["count"] + 1, ip, d))
    else:
        cur.execute(f"INSERT INTO {table}(ip, day, count) VALUES (?,?,?)", (ip, d, 1))
    conn.commit(); conn.close()

def prune_old_metrics():
    cutoff = (date.today() - timedelta(days=settings.RETENTION_DAYS)).isoformat()
    conn = db(); cur = conn.cursor()
    cur.execute("DELETE FROM hits WHERE day < ?", (cutoff,))
    cur.execute("DELETE FROM misses WHERE day < ?", (cutoff,))
    conn.commit(); conn.close()

def cache_full_refresh(nb: NetBoxClient):
    devices = nb.list_active_with_primary_ipv4()
    now = _now_epoch()
    conn = db(); cur = conn.cursor()
    for d in devices:
        cur.execute("""
        INSERT INTO devices(ip, hostname, status, device_url, site, location, role, type, tags_json, device_criticality, last_refreshed, source)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(ip) DO UPDATE SET
          hostname=excluded.hostname,
          status=excluded.status,
          device_url=excluded.device_url,
          site=excluded.site,
          location=excluded.location,
          role=excluded.role,
          type=excluded.type,
          tags_json=excluded.tags_json,
          device_criticality=excluded.device_criticality,
          last_refreshed=excluded.last_refreshed,
          source='full_refresh'
        """, (
            d["ip"], d["hostname"], d["status"], d["device_url"],
            d["site"], d["location"], d["role"], d["type"],
            json.dumps(d["tags"]), d["device_criticality"], now, "full_refresh"
        ))
    conn.commit(); conn.close()

def _row_to_device(row: sqlite3.Row) -> Dict[str, Any]:
    return {
        "status": row["status"] or "",
        "hostname": row["hostname"] or "",
        "device_url": row["device_url"] or "",
        "site": row["site"] or "",
        "location": row["location"] or "",
        "role": row["role"] or "",
        "type": row["type"] or "",
        "tags": json.loads(row["tags_json"]) if row["tags_json"] else [],
        "device_criticality": row["device_criticality"] or "",
    }


def cache_lookup_or_netbox(ip: str, nb: NetBoxClient, ttl_hours: int) -> Optional[Dict[str, Any]]:
    now = _now_epoch()
    ttl_until = now + ttl_hours * 3600

    # cache first
    conn = db(); cur = conn.cursor()
    cur.execute("SELECT * FROM devices WHERE ip=?", (ip,))
    row = cur.fetchone()
    if row:
        conn.close()
        return _row_to_device(row)

    # respect miss TTL
    cur.execute("SELECT ttl_until FROM not_found WHERE ip=?", (ip,))
    nf = cur.fetchone()
    if nf and nf["ttl_until"] > now:
        conn.close()
        return None

    # on-demand lookup (optional)
    dev = None
    if settings.NETBOX_ONDEMAND_LOOKUP:
        dev = nb.lookup_by_ip(ip)

    if dev:
        cur.execute("""
        INSERT INTO devices(ip, hostname, status, device_url, site, location, role, type, tags_json, device_criticality, last_refreshed, source)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(ip) DO UPDATE SET
          hostname=excluded.hostname,
          status=excluded.status,
          device_url=excluded.device_url,
          site=excluded.site,
          location=excluded.location,
          role=excluded.role,
          type=excluded.type,
          tags_json=excluded.tags_json,
          device_criticality=excluded.device_criticality,
          last_refreshed=excluded.last_refreshed,
          source='on_demand'
        """, (
            ip, dev["hostname"], dev["status"], dev["device_url"],
            dev["site"], dev["location"], dev["role"], dev["type"],
            json.dumps(dev["tags"]), dev["device_criticality"], now, "on_demand"
        ))
        conn.commit(); conn.close()
        return dev

    # record miss with TTL
    if nf:
        cur.execute("UPDATE not_found SET last_seen=?, ttl_until=? WHERE ip=?", (now, ttl_until, ip))
    else:
        cur.execute("INSERT INTO not_found(ip, first_seen, last_seen, ttl_until) VALUES (?,?,?,?)",
                    (ip, now, now, ttl_until))
    conn.commit(); conn.close()
    return None

# ------------------------- Email report -------------------------
def send_daily_email():
    top_n = settings.EMAIL_TOP_N
    conn = db(); cur = conn.cursor()
    day = _today()
    cur.execute("SELECT ip, count FROM hits WHERE day=? ORDER BY count DESC LIMIT ?", (day, top_n))
    top_hits = cur.fetchall()
    cur.execute("SELECT ip, count FROM misses WHERE day=? ORDER BY count DESC", (day,))
    misses = cur.fetchall()

    hit_rows = []
    for r in top_hits:
        ip = r["ip"]; count = r["count"]
        cur.execute("SELECT hostname FROM devices WHERE ip=?", (ip,))
        d = cur.fetchone()
        hit_rows.append({"ip": ip, "hostname": d["hostname"] if d else "", "count": count})

    def table(rows, headers):
        th = "".join(f"<th>{h}</th>" for h in headers)
        trs = []
        for r in rows:
            tds = "".join(f"<td>{r.get(h,'')}</td>" for h in headers)
            trs.append(f"<tr>{tds}</tr>")
        return f"<table border='1' cellpadding='6' cellspacing='0'><thead><tr>{th}</tr></thead><tbody>{''.join(trs)}</tbody></table>"

    html = f"""
    <html><body>
      <h2>NetBox Enrichment Daily Report — {day}</h2>
      <h3>Top {top_n} Hosts (by enrichment hits)</h3>
      {table(hit_rows, ['ip','hostname','count'])}
      <h3>Misses (no NetBox match)</h3>
      {table([{{'ip': m['ip'], 'count': m['count']}} for m in misses], ['ip','count'])}
    </body></html>
    """

    if settings.APP_ENV.lower() == "production":
        ses = get_ses_client_assumed()
        ses.send_email(
            Source=settings.SES_FROM,
            Destination={"ToAddresses": [e.strip() for e in settings.SES_TO.split(",") if e.strip()]},
            Message={"Subject": {"Data": f"NetBox Enrichment Report — {day}"}, "Body": {"Html": {"Data": html}}}
        )
    else:
        report_path = f"./daily_report_{day}.html"
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"[dev] Daily report written to {report_path}")


# ------------------------- Scheduler -------------------------
scheduler = BackgroundScheduler()

@scheduler.scheduled_job("cron", hour=settings.REFRESH_CRON_HOUR, minute=5)
def scheduled_refresh():
    try:
        nb = get_nb()
        cache_full_refresh(nb)
        prune_old_metrics()
    except Exception as e:
        print(f"[refresh] error: {e}")

@scheduler.scheduled_job("cron", hour=settings.REPORT_CRON_HOUR, minute=10)
def scheduled_report():
    try:
        send_daily_email()
    except Exception as e:
        print(f"[report] error: {e}")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # startup
    scheduler.start()
    try:
        yield
    finally:
        # shutdown
        scheduler.shutdown()


# ------------------------- FastAPI -------------------------
app = FastAPI(title="NetBox Enrichment Service", lifespan=lifespan)
router = APIRouter(prefix="/enrich")
templates = Jinja2Templates(directory="templates")

class EnrichResponse(BaseModel):
    status: Optional[str] = ""
    hostname: Optional[str] = ""
    device_url: Optional[str] = ""
    site: Optional[str] = ""
    location: Optional[str] = ""
    role: Optional[str] = ""
    type: Optional[str] = ""
    tags: List[str] = Field(default_factory=list)
    custom_fields: Dict[str, Any] = Field(default_factory=dict)

def normalize_ip(ip: str) -> str:
    try:
        return str(ipaddress.ip_address(ip))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid IP")

@router.get("/healthz", response_class=PlainTextResponse)
def healthz():
    return "ok"

@router.get("", response_model=EnrichResponse)
def enrich(ip: str = Query(...), authorized: bool = Depends(require_api_key)):
    nip = normalize_ip(ip)
    nb = get_nb()
    dev = cache_lookup_or_netbox(nip, nb, settings.CACHE_TTL_HOURS)

    if dev:
        record_hit(nip, miss=False)
        dc = (dev.get("device_criticality") or "")  # may be None
        cf = {"device_criticality": {"code": dc or "", "label": {"01":"Critical","02":"High","03":"Medium","04":"Low"}.get(dc, "")}}
        return EnrichResponse(
            status=(dev.get("status") or ""),
            hostname=(dev.get("hostname") or ""),
            device_url=(dev.get("device_url") or ""),
            site=(dev.get("site") or ""),
            location=(dev.get("location") or ""),
            role=(dev.get("role") or ""),
            type=(dev.get("type") or ""),
            tags=(dev.get("tags") or []),
            custom_fields=cf,
        )

    # miss: cache miss recorded elsewhere; return blanks
    record_hit(nip, miss=True)
    return EnrichResponse(
        status="",
        hostname="",
        device_url="",
        site="",
        location="",
        role="",
        type="",
        tags=[],
        custom_fields={"device_criticality": {"code": "", "label": ""}},
    )

@router.get("/", include_in_schema=False)        # /enrich/
def enrich_with_slash(request: Request, authorized: bool = Depends(require_api_key), ip: str = Query(...)):
    # just call the main handler
    return enrich(ip=ip, authorized=authorized)

@router.get("/admin/config", response_class=JSONResponse)
def admin_config(authorized: bool = Depends(require_admin_key)):
    return {
        "environment": settings.APP_ENV,
        "netbox_token_source": ("env" if settings.APP_ENV.lower()=="development" else {"secrets_manager_secret_name": settings.NETBOX_API_TOKEN__SECRET_NAME}),
        "ses_role_source": ("env" if settings.APP_ENV.lower()=="development" else {"ssm_param_name": settings.SES_ROLE_ARN__PARAM_NAME}),
        "global_allowlist": settings.APP_GLOBAL_ALLOWLIST.split(",") if settings.APP_GLOBAL_ALLOWLIST else [],
        "cache": {"ttl_hours": settings.CACHE_TTL_HOURS, "retention_days": settings.RETENTION_DAYS},
        "schedules": {"refresh_hour": settings.REFRESH_CRON_HOUR, "report_hour": settings.REPORT_CRON_HOUR},
        "email": {"from": settings.SES_FROM, "to_count": len([e for e in settings.SES_TO.split(',') if e.strip()])},
        "netbox": {"verify_ssl": settings.NETBOX_VERIFY_SSL, "ca_bundle": settings.NETBOX_CA_BUNDLE, "ondemand_lookup": settings.NETBOX_ONDEMAND_LOOKUP},
    }

@router.get("/admin/stats.json", response_class=JSONResponse)
def admin_stats_json(days: int = Query(7, ge=1), authorized: bool = Depends(require_admin_key)):
    days = min(days, settings.RETENTION_DAYS)
    since = (date.today() - timedelta(days=days-1)).isoformat()
    conn = db(); cur = conn.cursor()
    cur.execute("SELECT ip, SUM(count) as total FROM hits WHERE day >= ? GROUP BY ip ORDER BY total DESC", (since,))
    hits = [{"ip": r["ip"], "total": r["total"]} for r in cur.fetchall()]
    cur.execute("SELECT ip, SUM(count) as total FROM misses WHERE day >= ? GROUP BY ip ORDER BY total DESC", (since,))
    misses = [{"ip": r["ip"], "total": r["total"]} for r in cur.fetchall()]
    for row in hits:
        cur.execute("SELECT hostname, device_url FROM devices WHERE ip=?", (row["ip"],))
        d = cur.fetchone()
        row["hostname"] = d["hostname"] if d else None
        row["device_url"] = d["device_url"] if d else None
    conn.close()
    return {"hits": hits, "misses": misses}

@router.get("/admin", response_class=HTMLResponse)
def admin_central(request: Request, authorized: bool = Depends(require_admin_key)):
    return templates.TemplateResponse(
        "admin_central.html",
        {"request": request, "base_path": "/enrich"}  # pass base for template
    )

@router.post("/admin/refresh")
def admin_refresh(authorized: bool = Depends(require_admin_key)):
    nb = get_nb()
    cache_full_refresh(nb)
    prune_old_metrics()
    return JSONResponse({"ok": True, "refreshed": True})

@router.get("/admin/netbox-diagnose", response_class=JSONResponse)
def netbox_diagnose(authorized: bool = Depends(require_admin_key)):
    nb = get_nb()
    def probe(path):
        try:
            r = nb.client.get(f"{settings.NETBOX_BASE_URL.rstrip('/')}{path}", params={"limit": 1})
            return {"status": r.status_code, "ok": 200 <= r.status_code < 300}
        except Exception as e:
            return {"status": None, "error": str(e)}
    return {
        "base": probe("/api/"),
        "ipam_ip_addresses": probe("/api/ipam/ip-addresses/"),
        "dcim_devices": probe("/api/dcim/devices/"),
        "verify": settings.NETBOX_CA_BUNDLE or settings.NETBOX_VERIFY_SSL,
    }

# Mount the router
app.include_router(router)


# ------------------------- CLI (api key + allowlists) -------------------------
def _random_token(nbytes: int = 32) -> str:
    return "ak_live_" + base64.urlsafe_b64encode(secrets.token_bytes(nbytes)).rstrip(b"=").decode()

def cli():
    parser = argparse.ArgumentParser(description="NetBox Enrichment — API Key Manager")
    sub = parser.add_subparsers(dest="cmd", required=True)

    ccreate = sub.add_parser("create", help="Create a new API key")
    ccreate.add_argument("--key-id", required=True)
    ccreate.add_argument("--token")
    ccreate.add_argument("--ttl-days", type=int)
    ccreate.add_argument("--scopes", default="read")

    clist = sub.add_parser("list", help="List API keys")

    cdisable = sub.add_parser("disable", help="Disable an API key"); cdisable.add_argument("--key-id", required=True)
    cenable  = sub.add_parser("enable",  help="Enable an API key");  cenable.add_argument("--key-id", required=True)
    cdelete  = sub.add_parser("delete",  help="Delete an API key");  cdelete.add_argument("--key-id", required=True)

    call_add = sub.add_parser("allowlist-add", help="Add CIDR(s) to a key's allowlist")
    call_add.add_argument("--key-id", required=True); call_add.add_argument("--cidrs", required=True)

    call_remove = sub.add_parser("allowlist-remove", help="Remove CIDR(s) from a key's allowlist")
    call_remove.add_argument("--key-id", required=True); call_remove.add_argument("--cidrs", required=True)

    call_list = sub.add_parser("allowlist-list", help="List CIDRs on a key's allowlist")
    call_list.add_argument("--key-id", required=True)

    args = parser.parse_args()

    if args.cmd == "create":
        token = args.token or _random_token()
        scopes = [s.strip() for s in args.scopes.split(",") if s.strip()]
        create_api_key_record(args.key_id, token, args.ttl_days, scopes)
        print("== API Key Created ==")
        print(f" Key ID : {args.key_id}")
        print(f" Scopes : {','.join(scopes)}")
        if args.ttl_days: print(f" Expires: in {args.ttl_days} days")
        print(" IMPORTANT: This is the ONLY time you'll see the token. Store it securely.")
        print(f" Token  : {token}")
        print("\nUse headers:\n  X-API-Key-Id: <Key ID>\n  X-API-Key:   <Token>")

    elif args.cmd == "list":
        rows = list_api_keys()
        if not rows:
            print("No keys found."); return
        print(f"{'KEY_ID':<20} {'STATUS':<10} {'CREATED_AT':<20} {'EXPIRES_AT':<20} SCOPES")
        for r in rows:
            ca = datetime.fromtimestamp(r["created_at"]).isoformat(sep=" ", timespec="seconds")
            ea = "-" if r["expires_at"] is None else datetime.fromtimestamp(r["expires_at"]).isoformat(sep=" ", timespec="seconds")
            print(f"{r['key_id']:<20} {r['status']:<10} {ca:<20} {ea:<20} {r['scopes']}")

    elif args.cmd == "disable":
        print("Disabled." if set_api_key_status(args.key_id, "disabled") else "Key not found.")

    elif args.cmd == "enable":
        print("Enabled." if set_api_key_status(args.key_id, "active") else "Key not found.")

    elif args.cmd == "delete":
        print("Deleted." if delete_api_key(args.key_id) else "Key not found.")

    elif args.cmd == "allowlist-add":
        cidrs = [c.strip() for c in args.cidrs.split(",") if c.strip()]
        add_allowlist_cidrs(args.key_id, cidrs)
        print("Added.")

    elif args.cmd == "allowlist-remove":
        cidrs = [c.strip() for c in args.cidrs.split(",") if c.strip()]
        remove_allowlist_cidrs(args.key_id, cidrs)
        print("Removed.")

    elif args.cmd == "allowlist-list":
        cidrs = get_key_allowlist(args.key_id)
        if not cidrs:
            print("(no CIDRs configured for this key)")
        else:
            for c in cidrs:
                print(c)

if __name__ == "__main__":
    # CLI usage: python app.py <subcommand>
    # App is served via: uvicorn app:app
    cli()
