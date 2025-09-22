# NetBox Enrichment Service
This service was built to enrich syslog data (originally for Graylog, but usable by any system that can query by IP address).
Early versions queried NetBox directly for every lookup, but that approach collapsed under higher syslog volumes.
To fix that, the app now maintains a 24-hour cache of device details and refreshes it automatically outside business hours, keeping NetBox API load to a minimum.

FastAPI microservice that enriches syslog events by IP using NetBox as source of truth.
- Caches **devices with primary IPv4** daily, with **on-demand lookups** for unseen IPs once per day.
- Returns: `status, hostname, device_url, site, location, role, type, tags, custom_fields.device_criticality`.
- **Hashed API keys** (no plaintext in DB) with **scopes** (`read`, `admin`).
- **Per-key CIDR allowlists** and optional **global allowlist**.
- **Dev vs Prod** via dotenv:
  - **Dev**: secrets from `.env`; daily report written to disk.
  - **Prod**: NetBox token from **AWS Secrets Manager** (`TOKEN:<value>`), SES AssumeRole ARN from **SSM Parameter Store**; daily report emailed via SES.
- Admin dashboard and config view.

---

## Architecture quick map

```
syslog pipeline -> [Nginx] -> FastAPI (/enrich/) -> SQLite (cache, stats, api_keys)
                                   |             -> NetBox (daily refresh + on-demand lookup)
                                   |-> SES (daily email in prod)
                                   |-> Admin: /admin/stats, /admin/config, /admin/refresh
```

---

## Requirements

- Python 3.11+ recommended
- Linux host (Amazon Linux 2/2023 or Ubuntu 22.04+)
- NetBox API reachable from EC2
- AWS IAM:
  - **Prod**: `secretsmanager:GetSecretValue`, `ssm:GetParameter`, `sts:AssumeRole` on the SES sender role
- Nginx or ALB as reverse proxy (optional but recommended)

---

## Setup (development)

```bash
# 1) Unpack
cd /opt
git clone https://github.com/uck9/netbox-enrichment

# 2) Virtualenv
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 3) Configure environment
cp .env.example .env
# Edit .env:
#   APP_ENV=development
#   NETBOX_BASE_URL=...
#   NETBOX_API_TOKEN=...            # direct token in dev
#   SES_ROLE_ARN=...                # direct role ARN in dev if you want to test SES (optional)

# 4) Run
uvicorn app:app --host 0.0.0.0 --port 8000
```

### Create API keys
```bash
# read-only key used by your ingestion pipeline
python app.py create --key-id pipeline-01 --scopes read

# admin key for you
python app.py create --key-id admin --scopes read,admin --ttl-days 365

# allowlist (per key)
python app.py allowlist-add --key-id pipeline-01 --cidrs 10.20.0.0/16,10.21.0.0/16
python app.py allowlist-list --key-id pipeline-01
```

### Call the API
```bash
curl -s "http://localhost:8000/enrich?ip=10.1.2.3"   -H "X-API-Key-Id: pipeline-01"   -H "X-API-Key: <token from create>"
```

### Admin endpoints (require `admin` scope)
- `/enrich/admin` — HTML dashboard (hits & misses) and config
- `/enrich/admin/stats?days=7` — HTML dashboard (hits & misses)
- `/enrich/admin/config` — JSON, shows environment & sources (no secrets)
- `POST /enrich/admin/refresh` — force full cache refresh

Headers:
```
X-API-Key-Id: admin
X-API-Key:   <admin token>
```

---

## Setup (production, systemd + nginx on EC2)

> This assumes your app lives in `/opt/netbox-enrichment` and runs as `netbox`. Adjust paths/users as needed.

### 1) Install code & venv
```bash
sudo mkdir -p /opt/netbox-enrich && sudo chown -R netbox:netbox /opt/netbox-enrichment
unzip netbox-enrich-full.zip -d /opt/netbox-enrich
cd /opt/netbox-enrich
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2) Configure `.env` for production
```bash
cp .env.example .env
vi .env
# Set:
#   APP_ENV=production
#   REGION=ap-southeast-2
#   NETBOX_BASE_URL=https://netbox.example.com
#   NETBOX_API_TOKEN__SECRET_NAME=prod/netbox/api_token   # Secrets Manager secret; value must be TOKEN:<actual_token>
#   SES_ROLE_ARN__PARAM_NAME=/prod/ses/assume_role_arn    # SSM Parameter Store name containing the role ARN
#   SES_FROM=netbox-enrich@example.com
#   SES_TO=netops@example.com,secops@example.com
# Optional:
#   APP_GLOBAL_ALLOWLIST=10.0.0.0/8,192.168.0.0/16
```

### 3) AWS pieces
- **Secrets Manager** secret `/prod/netbox/api_token` (string):
  ```
  TOKEN:nbx_long_real_token_here
  ```
- **SSM Parameter Store** param `/prod/ses/assume_role_arn` (String):
  ```
  arn:aws:iam::<ACCOUNT>:role/ses-sender-role
  ```
- EC2 instance role (or attached credentials) needs:
  - `secretsmanager:GetSecretValue` on the secret
  - `ssm:GetParameter` on the parameter
  - `sts:AssumeRole` on the SES role
- SES identity/domain must be verified in your region.

### 4) Systemd service
We ship a sample unit in `deploy/netbox-enrich.service`. Install it:

```bash
sudo cp deploy/netbox-enrichment.service /etc/systemd/system/netbox-enrichment.service
# Edit user/paths if needed:
#   WorkingDirectory=/opt/netbox-enrich
#   ExecStart=/opt/netbox-enrich/venv/bin/uvicorn app:app --host 0.0.0.0 --port 8000

sudo systemctl daemon-reload
sudo systemctl enable netbox-enrichment
sudo systemctl start netbox-enrichment
sudo systemctl status netbox-enrichment --no-pager
# Logs:
journalctl -u netbox-enrichment -f
```

### 5) Nginx reverse proxy (optional but recommended)
We include `deploy/nginx.example.conf`. Install & tweak:
```bash
sudo cp deploy/nginx.example.conf /etc/nginx/conf.d/netbox-enrichment.conf
sudo nginx -t && sudo systemctl reload nginx
```

The config forwards `X-Forwarded-For` so the app can enforce per-key CIDR allowlists.

---

## Endpoints

- `GET /enrich/healthz` — simple health probe
- `GET /enrich/?ip=<IPv4>` — returns enrichment JSON for the primary IPv4 device
- `GET /enrich/admin/stats?days=<1..90>` — admin HTML dashboard
- `GET /enrich/admin/config` — admin JSON, shows env/config sources (no secret values)
- `POST /enrich/admin/refresh` — admin only, clears & repopulates cache

### Auth headers
```
X-API-Key-Id: <key-id>
X-API-Key:    <token>
```

### Response shape (example)
```json
{
  "status": "active",
  "hostname": "edge-sw-01",
  "device_url": "https://netbox/dcim/devices/123/",
  "site": "DC1",
  "location": "ROW3",
  "role": "switch",
  "type": "N9K-C93180YC-FX",
  "tags": ["prod", "leaf"],
  "custom_fields": {
    "device_criticality": { "code": "02", "label": "High" }
  }
}
```

---

## Cache behavior

- **Nightly full refresh** (cron via APScheduler) grabs all `status=active` devices with a **primary IPv4** and updates SQLite.
- `/enrich` path:
  1. Try cache.
  2. If miss and **no recent miss** record, do a one-shot NetBox lookup for that IP and cache result.
  3. If still missing, store a **miss TTL** to avoid repeated NetBox hits for that IP for `CACHE_TTL_HOURS`.
- **Metrics retention**: `RETENTION_DAYS` (default 90).

---

## API key management (CLI)

```bash
# Create
python app.py create --key-id pipeline-01 --scopes read
python app.py create --key-id admin --scopes read,admin --ttl-days 365

# List
python app.py list

# Enable/disable
python app.py disable --key-id pipeline-01
python app.py enable  --key-id pipeline-01

# Delete
python app.py delete --key-id pipeline-01

# Allowlist CIDRs per key
python app.py allowlist-add    --key-id pipeline-01 --cidrs 10.20.0.0/16,10.21.0.0/16
python app.py allowlist-remove --key-id pipeline-01 --cidrs 10.21.0.0/16
python app.py allowlist-list   --key-id pipeline-01
```

**Notes**
- Tokens are long, random, and shown **once** at creation. Only **bcrypt hashes** are stored.
- Scopes:
  - `read` → `/enrich`
  - `admin` → `/enrich/admin/*`
- IP allowlists:
  - If a key has CIDRs, requests **must** match.
  - If key has no CIDRs and `APP_GLOBAL_ALLOWLIST` is set, it applies.
  - If neither is set, allow by default (change to deny-by-default if you want).

---

## Daily reporting

- **Prod**: HTML email via SES (assume role retrieved from SSM).
- **Dev**: Writes `./daily_report_YYYY-MM-DD.html` next to the app.
- Email includes: Top N hosts by hits, and miss list for the day.

---

## Security tips

- Put the app behind Nginx/ALB, consider **mTLS** if your pipeline supports it.
- Rotate API keys periodically; use allowlists.
- Back up `enrichment.db` or mount on persistent storage if you care about stats.
- Ensure your instance role has **least privilege** on Secrets/SSM/STS/SES.

---

## Troubleshooting

- **403 "IP not allowed"**: check `X-Forwarded-For` and allowlists.
- **403 "Forbidden"**: wrong scopes, disabled key, or expired key.
- **NetBox lookups failing**: validate `NETBOX_BASE_URL` and token *source* (env var vs secret name).
- **Email not sending in prod**: verify SES identity and STS role permissions.

---

## License

MIT
