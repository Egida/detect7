# Detect7 Full SaaS Transformation Plan

**Overview:** Transform Detect7 from a decoupled detection engine + stub SaaS into a fully integrated DDoS detection and active mitigation SaaS, powered by Cloudflare integration, API-key-authenticated syslog ingestion, real-time analytics on PostgreSQL + TimescaleDB, and flat-tier billing.

## Todos

- **Phase 1a:** Migrate from MySQL to PostgreSQL + TimescaleDB, add Alembic, create initial migration
- **Phase 1b:** Add Plan, Subscription, ApiKey, DomainLog (hypertable), DomainStats (continuous aggregate), DetectionEvent, CloudflareIntegration, DomainOriginIP, WhitelistedIP, FirewallCommand models; extend User and Domain
- **Phase 2a:** Add API-key-in-syslog-tag authentication to syslog server with host/subdomain validation and multi-IP source binding
- **Phase 2b:** Syslog -> RabbitMQ -> Log Writer Worker -> domain_logs; ML worker -> RabbitMQ -> Detection Consumer -> detection_events
- **Phase 2c:** Rewrite dashboard.py to query real domain_logs (24h) and detection_events; use TimescaleDB continuous aggregates for stats
- **Phase 3a:** Per-domain setup wizard with two tracks: CF (5 steps: token, zone, verify IPs + firewall, enable mitigation, log forwarding) and non-CF (TXT verify, manual IPs, notification-only)
- **Phase 3b:** Active mitigation -- CF Sync Worker manages two CF IP Lists (blocklist + whitelist) per domain, auto-expire blocked IPs
- **Phase 3c:** Post-wizard domain settings panel -- status icons with hover hints, blocklist/whitelist tabs, mitigation controls, key rotation with grace period
- **Phase 3d:** Firewall Worker -- consumes RabbitMQ queue, executes CSF commands to allow/deny origin IPs on ingestor server
- **Phase 4:** Billing with Stripe -- plan seeding, billing router, webhook handler, checkout flow, plan limit enforcement (POSTPONE)
- **Phase 5:** Auth hardening -- email verification, password reset, API key management router, rate limiting, CORS tightening
- **Phase 6:** Frontend -- billing page, API keys page, password reset pages, dashboard improvements, panel navigation
- **Phase 7:** DevOps -- unified docker-compose, consolidated env vars, expanded health checks, structured logging

---

## Current State

The codebase has two disconnected halves:

- **Detection engine** (`app/`): syslog -> Redis -> LightGBM ML -> Graylog pipeline. Works, but is domain/user-unaware.
- **SaaS layer** (`backend/` + `frontend/`): FastAPI + Vue 3 with auth, domain management, and a dashboard that returns **synthetic data**.

The core task is to wire these together, add Cloudflare-powered active mitigation, billing, hardened auth, and make the syslog pipeline multi-tenant via API keys.

---

## Phase 1: Database Foundation

**Why first:** Every subsequent phase depends on new DB tables, the time-series engine, and safe schema migrations.

### 1a. Migrate to PostgreSQL + TimescaleDB

- Replace `pymysql` with `psycopg2-binary` in `backend/requirements.txt`
- Update `DATABASE_URL` format: `postgresql+psycopg2://user:pass@host:5432/detect7`
- Add TimescaleDB extension (`CREATE EXTENSION IF NOT EXISTS timescaledb`) in initial migration
- Install `alembic` in `backend/requirements.txt`
- Initialize Alembic inside `backend/`, generate initial migration from existing `User` and `Domain` models
- Remove `Base.metadata.create_all()` from `backend/app/main.py` startup
- Docker: add `timescale/timescaledb:latest-pg16` to `docker-compose.saas.yml`

### 1b. New models in `backend/app/models.py`

```python
class Plan(Base):
    __tablename__ = "plans"
    id: int (PK)
    name: str            # "Free", "Pro", "Enterprise"
    max_domains: int
    max_rps: int         # per-domain RPS cap
    retention_days: int  # detection event retention
    price_cents: int     # monthly price in cents (0 for free)
    stripe_price_id: str # nullable, for paid plans
    is_active: bool

class Subscription(Base):
    __tablename__ = "subscriptions"
    id: int (PK)
    user_id: FK -> users
    plan_id: FK -> plans
    stripe_subscription_id: str (nullable)
    status: str          # "active", "canceled", "past_due"
    current_period_start: datetime
    current_period_end: datetime

class ApiKey(Base):
    __tablename__ = "api_keys"
    id: int (PK)
    user_id: FK -> users
    domain_id: FK -> domains
    key_prefix: str      # "dk7_" + first 8 chars for display
    key_enc: str         # Fernet-encrypted full key (reversible, for Redis cache rebuild)
    key_sha256: str      # SHA-256 hash of the full key (for DB lookups on cache miss)
    name: str
    created_at: datetime
    last_used_at: datetime (nullable)
    is_active: bool
    # On rotation: old key kept with is_active=True and expires_at set to now()+15min
    expires_at: datetime (nullable)  # for grace period during rotation

class DomainLog(Base):
    __tablename__ = "domain_logs"  # TimescaleDB hypertable, partitioned by timestamp (1h chunks)
    # NOT a regular PK -- hypertables use (timestamp, domain_id) as composite
    timestamp: datetime (partition key)
    domain_id: FK -> domains
    source_ip: str
    method: str
    path: str
    status_code: int
    bytes_sent: int
    request_time: float
    country: str (nullable)
    city: str (nullable)
    # 24h retention policy via TimescaleDB: SELECT add_retention_policy('domain_logs', INTERVAL '24 hours')

# DomainStats -- TimescaleDB continuous aggregate (auto-computed, no application code)
# Materialized view over domain_logs, refreshed every 5 minutes:
#   - Per domain, per 5-min bucket:
#     total_requests, total_bytes, avg_request_time,
#     unique_ips, top_paths (mode), top_countries (mode),
#     error_count (status >= 400), rps (count / 300)
# Retention: kept indefinitely (small rows, ~288/day/domain)

class DetectionEvent(Base):
    __tablename__ = "detection_events"  # TimescaleDB hypertable, partitioned by started_at
    started_at: datetime (partition key)
    id: int (PK)
    domain_id: FK -> domains
    detected_ip: str
    threat_score: float
    country: str (nullable)
    city: str (nullable)
    ptr: str (nullable)           # reverse DNS hostname
    request_count: int
    peak_rps: float
    request_rate: float
    error_rate: float
    ip_data_preview: jsonb        # sample nginx logs from ML worker (already in detection output)
    last_feature: jsonb           # full ML feature vector
    ended_at: datetime (nullable)
    cf_pushed_at: datetime (nullable)
    cf_expires_at: datetime (nullable)
    # Retention: per plan retention_days via TimescaleDB policy

class DomainOriginIP(Base):
    __tablename__ = "domain_origin_ips"
    id: int (PK)
    domain_id: FK -> domains
    ip_address: str (unique per domain)
    label: str (nullable)         # e.g. "www1", "www2", "main"
    verified: bool (default False)
    firewall_whitelisted: bool (default False)
    created_at: datetime

class CloudflareIntegration(Base):
    __tablename__ = "cloudflare_integrations"
    id: int (PK)
    user_id: FK -> users
    domain_id: FK -> domains (unique)
    cf_api_token_enc: str       # Fernet-encrypted CF API token
    cf_zone_id: str
    cf_blocklist_id: str (nullable)
    cf_whitelist_id: str (nullable)
    cf_waf_rule_id: str (nullable)
    sync_interval_sec: int (default 60)
    block_duration_sec: int (default 3600)
    mitigation_enabled: bool (default False)
    created_at: datetime
    updated_at: datetime

class WhitelistedIP(Base):
    __tablename__ = "whitelisted_ips"
    id: int (PK)
    domain_id: FK -> domains
    ip_address: str
    description: str (nullable)
    added_by: FK -> users
    cf_synced: bool (default False)
    created_at: datetime

class FirewallCommand(Base):
    __tablename__ = "firewall_commands"
    id: int (PK)
    domain_id: FK -> domains
    action: str          # "allow" or "deny"
    ip_address: str
    description: str
    status: str          # "pending", "executed", "failed"
    error_message: str (nullable)
    executed_at: datetime (nullable)
    created_at: datetime
```

Extend existing `User` model: add `plan_id` (FK, nullable), `email_verified` (bool, default False), `email_verify_token` (str, nullable).

Extend existing `Domain` model: add `cf_verified` (bool, default False), `is_verified` (existing), `setup_step` (int, nullable, 1-6, null = complete or not started), `strip_subdomains` (bool, default False), `verification_method` (str: "cloudflare" or "txt", nullable).

**Key design decisions:**

- **API key hashing**: SHA-256 for fast DB lookups on cache miss. Fernet encryption for reversible storage (enables Redis cache rebuild on restart). bcrypt is NOT used for API keys (too slow for high-frequency validation). bcrypt stays for user passwords only.
- **Redis cache rebuild on startup**: Log Writer Worker and Syslog Server query `api_keys` table on startup, decrypt keys via Fernet, rebuild `plaintext_key -> {domain_id, user_id, origin_ips, plan, host, strip_subdomains}` cache in Redis.
- **DomainLog as TimescaleDB hypertable**: automatic 1-hour chunk partitioning, built-in 24h retention policy (`add_retention_policy`), no custom cleanup worker needed.
- **DomainStats as continuous aggregate**: auto-computed 5-min rollups over domain_logs. Used for dashboard historical data. Kept indefinitely (tiny rows).
- **DetectionEvent retention**: TimescaleDB retention policy set per plan's `retention_days`. Cleanup is automatic.
- **Multiple origin IPs**: Separate `DomainOriginIP` table instead of single `origin_ip` field. Supports load-balanced and multi-node domains.

---

## Phase 2: Bridge Detection Pipeline to SaaS

**Why:** This is the core value -- real data flowing from log ingestion through ML into per-domain dashboards.

### Full architecture

```mermaid
flowchart LR
    subgraph ingestion [Log Ingestion]
        Nginx["User Nginx"] -->|"UDP 514, tag=dk7_KEY"| SyslogServer["Syslog Server"]
    end

    subgraph validation [Syslog Validation]
        SyslogServer -->|extract tag| KeyLookup["API Key Lookup (Redis)"]
        KeyLookup -->|invalid key| Drop1["Drop"]
        KeyLookup -->|"valid"| HostCheck["Host matches domain? (subdomain strip)"]
        HostCheck -->|mismatch| Drop2["Drop"]
        HostCheck -->|match| IPCheck["Source IP in origin_ips?"]
        IPCheck -->|mismatch| Drop3["Drop"]
        IPCheck -->|match| Accept["Accept"]
    end

    subgraph queues [RabbitMQ Queues]
        Accept --> LogQueue["domain_logs queue"]
        Accept --> RedisTS["Redis TimeSeries"]
        RedisTS --> MLWorker["ML Worker"]
        MLWorker -->|"threat > 0.7"| DetectQueue["detections queue"]
    end

    subgraph writers [DB Writer Workers]
        LogQueue --> LogWriter["Log Writer Worker"]
        LogWriter --> DomainLogs["domain_logs hypertable"]
        DetectQueue --> DetectWriter["Detection Consumer"]
        DetectWriter --> DetectionEvents["detection_events hypertable"]
    end

    subgraph timescale [TimescaleDB Auto]
        DomainLogs -->|"continuous aggregate"| DomainStats["domain_stats (5min rollups)"]
        DomainLogs -->|"retention policy"| Cleanup1["Auto-delete > 24h"]
        DetectionEvents -->|"retention policy"| Cleanup2["Auto-delete > retention_days"]
    end

    subgraph saas [SaaS Dashboard]
        DashboardAPI["GET /dashboard"] --> DomainLogs
        DashboardAPI --> DomainStats
        DashboardAPI --> DetectionEvents
        FrontendVue["Vue Frontend"] --> DashboardAPI
    end
```

### 2a. API-key-in-syslog-tag authentication with validation

The customer's Nginx config stays a one-liner:

```nginx
access_log syslog:server=detect7.example.com:514,tag=dk7_a1b2c3d4 json_detect7;
```

The key (`dk7_a1b2c3d4`) is generated per-domain when the user adds a domain in the panel. The `log_format` stays universal.

Modify `app/syslog_server.py` -- validation chain on every incoming log:

1. **Extract API key** from the syslog tag
2. **Key lookup** in Redis cache (`plaintext_key -> {user_id, domain_id, origin_ips[], host, strip_subdomains, plan}`)
3. **Host field validation** -- the `domain` field in the JSON log payload must match the registered domain. If `strip_subdomains` is enabled, strip subdomains from incoming `domain` field before comparison (e.g. `www1.example.com` -> `example.com`). This supports multi-node setups where `www1.domain.com`, `www2.domain.com` all map to parent `domain.com`.
4. **Source IP binding** -- the UDP source address must match ANY of the `origin_ips[]` stored for the domain. Supports multiple origin servers (load balancers, multi-node).
5. **RPS rate limiting** -- enforce plan RPS cap per key via Redis counter.
6. On accept: tag Redis TS entries with `domain_id`, publish to RabbitMQ `domain_logs` queue (NOT direct DB write -- syslog server stays decoupled from SaaS DB).
7. On reject: drop silently (log for monitoring).

**Redis cache rebuild on startup:** On syslog server boot (or Redis flush), query `api_keys` + `domains` + `domain_origin_ips` tables, decrypt keys via Fernet, rebuild the full Redis cache. This runs once on startup and is fast (iterate all active keys).

Update `backend/app/routers/domains.py`:

- When a domain is created, auto-generate an API key (`dk7_` + 12 random alphanumeric chars)
- Store SHA-256 hash + Fernet-encrypted key in `api_keys` table
- Cache `plaintext_key -> {domain_id, ...}` in Redis immediately
- Return the key in the domain creation response
- On domain deletion or key revocation, invalidate Redis cache

**Key rotation with grace period:**
- `POST /api-keys/{id}/rotate` generates a new key, marks the old key with `expires_at = now() + 15 minutes`
- Both old and new keys resolve to the same domain during the grace period
- After expiry, a cleanup job (or the cache rebuild) removes the old key
- Frontend shows warning: "Old key expires in X minutes. Update your Nginx config now."

Update log forwarding instructions (`/domains/instructions/log-forwarding`):

- Personalize the syslog line with the domain's unique API key
- Example: `access_log syslog:server=detect7.example.com:514,tag=dk7_a1b2c3d4 json_detect7;`

### 2b. RabbitMQ-based DB writers (decoupled from syslog)

The syslog server does NOT write to the SaaS DB directly. Instead:

**Log Writer Worker** (`backend/app/workers/log_writer.py`):
- Consumes from RabbitMQ `domain_logs` queue
- Batch-inserts into `domain_logs` hypertable (bulk insert every 1-5 seconds or every N messages)
- TimescaleDB handles the rest: auto-partitioning, 24h retention, continuous aggregate refresh

**Detection Consumer** (`backend/app/workers/detection_consumer.py`):
- Consumes from RabbitMQ `detections` queue (published by ML worker)
- Writes `DetectionEvent` rows to the hypertable, including `ip_data_preview` and `last_feature` from the ML output
- If domain has `mitigation_enabled = True`, signals the CF Sync Worker (or the sync worker picks it up on its next loop)

### 2c. Replace synthetic dashboard with real queries

Rewrite `backend/app/routers/dashboard.py`:

**Real-time data (from `domain_logs`, last 24h):**
- Current overall RPS (count in last 60s / 60)
- Requests over time (5-min buckets from continuous aggregate `domain_stats`)
- Top visited endpoints (GROUP BY path, last 24h)
- Top countries (GROUP BY country, last 24h)

**Detection data (from `detection_events`, per retention_days):**
- Suspicious events count and timeline
- Attack RPS (from detection events `peak_rps`)
- Recent detections feed (last N events with IP, country, threat score)
- Blocked IPs count (where `cf_pushed_at IS NOT NULL` and not expired)

**Historical data (from `domain_stats` continuous aggregate):**
- Longer-term trends beyond 24h (hourly/daily aggregated totals)
- These persist indefinitely even after raw logs are purged

- Add time range filter parameter (last 5m, 30m, 1h, 6h, 12h, 24h, 7d)
- Keep the same `DashboardSummary` response schema so the frontend doesn't break

---

## Phase 3: Cloudflare Integration and Active Mitigation

**Why:** This is the key differentiator -- turning detection into automatic attack mitigation via Cloudflare's edge network.

### 3a. Domain setup wizard (per-domain, triggered after domain is added)

The wizard appears for each domain after the user adds it to the panel. It offers **two tracks** depending on whether the user uses Cloudflare.

**Wizard steps (frontend component: `DomainSetupWizard.vue`):**

**Step 1 -- Choose verification method**

Two options:
- **"I use Cloudflare"** -> proceeds to CF track (Steps 2-6)
- **"I don't use Cloudflare"** -> proceeds to non-CF track (Steps 2b-4b)

---

#### CF Track (full feature set)

**Step 2 -- Create CF API Token**

Guide the user to create a **per-zone** scoped token with minimal permissions:

| Permission | Access | Why |
|------------|--------|-----|
| Zone > DNS | Read | Resolve origin server IP from A record |
| Account > Account Filter Lists | Edit | Create and manage the detect7 IP blocklist |
| Zone > Zone WAF | Edit | Auto-create WAF rule referencing the blocklist |

Instructions shown inline:
1. Go to [Cloudflare Dashboard > API Tokens](https://dash.cloudflare.com/profile/api-tokens) > Create Token
2. Choose "Create Custom Token"
3. Add the three permissions above
4. Under "Zone Resources", select "Specific zone" and pick the domain
5. Create token, copy it

Token input field with "Validate" button. Backend tests each permission and shows green checkmark or red X per scope with a specific error message (e.g. "Missing: Account Filter Lists > Edit").

Each token is scoped to one zone (domain). For multiple domains, the user creates one token per zone through each domain's wizard.

**Step 3 -- Select Zone**

- Backend lists zones available under the token (`GET /zones`)
- If only one zone matches the domain name, auto-select it
- User confirms the zone

**Step 4 -- Verify Domain and Select Origin IPs**

- Backend calls CF API `GET /zones/{zone_id}/dns_records?type=A` to resolve ALL A records
- Displays all resolved IPs in a checklist for the user to select/confirm which are origin servers
- User can add labels (e.g. "www1", "www2", "main") to each IP
- User can add additional IPs manually (for servers not in DNS A records)
- Stores selected IPs in `domain_origin_ips` table
- **Subdomain stripping option**: checkbox "My domain uses subdomains for different nodes (e.g. www1.domain.com, www2.domain.com)" -- if checked, sets `strip_subdomains = True` on the domain. This means the syslog server will strip subdomains from the incoming `domain` field before validation.
- Marks domain as `cf_verified = True`, sets `verification_method = "cloudflare"`
- **Firewall whitelisting**: for each selected IP, publishes a message to the `firewall_commands` RabbitMQ queue. The Firewall Worker (see 3d) executes `csf -a <ip>` on the ingestor server.
- On origin IP added/removed later: queue corresponding CSF commands
- On domain deletion: queue `csf -d` for all origin IPs

**Step 5 -- Enable Mitigation (optional, can skip)**

- Toggle: "Enable automatic attack mitigation?"
- If yes: creates **two** CF IP Lists and a WAF rule via API:
  - `detect7-block-{domain_name}` -- for detected attack IPs (auto-managed by CF Sync Worker)
  - `detect7-allow-{domain_name}` -- for user-managed whitelist (IPs that should never be blocked)
  - CF WAF custom rule logic: `if source IP in blocklist AND NOT in whitelist -> Block/JS Challenge`
- Configure block duration (1h / 6h / 12h / 24h dropdown, default 1h)
- User can skip and enable later from the domain settings

**Step 6 -- Start Forwarding Logs**

- Shows the personalized Nginx syslog one-liner with the domain's API key:
  `access_log syslog:server=detect7.example.com:514,tag=dk7_a1b2c3d4 json_detect7;`
- If `strip_subdomains` is enabled, shows the line for each node:
  "Add this line to **each** Nginx server (www1, www2, etc.) -- all use the same key."
- Copy button
- "Done" button completes the wizard

---

#### Non-CF Track (notification-only, no active mitigation)

**Step 2b -- Verify Domain via TXT File**

- Same as current implementation: generate a TXT file token, user places it on their web root
- Backend fetches `https://domain.com/detect7-verify-{id}.txt` to confirm
- Marks domain as verified, sets `verification_method = "txt"`

**Step 3b -- Enter Origin Server IPs**

- User manually enters their origin server IP(s) (no CF API to resolve from)
- Same multi-IP support and subdomain stripping option as CF Step 4
- Stores in `domain_origin_ips`, queues firewall allow commands

**Step 4b -- Log Forwarding + Limitation Notice**

- Shows the Nginx syslog one-liner with API key
- **Clear notice**: "Without Cloudflare integration, Detect7 operates in **notification mode only**. You will receive detection alerts and dashboard analytics, but automatic attack mitigation (IP blocking via Cloudflare WAF) is not available. Active mitigation for non-Cloudflare setups is under development."
- "Done" button completes the wizard

---

The wizard state is saved per step via `setup_step` column on the Domain model (1-6 for CF track, 1-4 for non-CF track, null = complete). If the user closes mid-wizard, they resume where they left off. Each domain in the domains table shows its wizard progress.

### 3a backend. CF router endpoints

New router `backend/app/routers/cloudflare.py`:

- `POST /domains/{domain_id}/cf/connect` -- validate and store scoped CF API token
  - Validate token against CF API (`GET /user/tokens/verify`)
  - Test each required permission, return per-scope pass/fail
  - Fernet-encrypt and store token in `cloudflare_integrations` table
- `GET /domains/{domain_id}/cf/zones` -- list zones available under the token
- `POST /domains/{domain_id}/cf/link-zone` -- link zone, resolve all A record IPs
  - Stores `cf_zone_id` in `cloudflare_integrations`
  - Returns list of A record IPs for user to select in Step 4
- `POST /domains/{domain_id}/cf/verify` -- confirm selected origin IPs, mark verified
  - Stores selected IPs in `domain_origin_ips`
  - Marks domain `cf_verified = True`
  - Publishes firewall allow commands for each IP
- `POST /domains/{domain_id}/cf/enable-mitigation` -- create two IP Lists + WAF rule
  - Creates `detect7-block-{domain_name}` (blocklist) and `detect7-allow-{domain_name}` (whitelist) via CF API
  - Creates CF WAF custom rule: "if source IP in blocklist AND NOT in whitelist -> Block"
  - Stores `cf_blocklist_id`, `cf_whitelist_id`, `cf_waf_rule_id`
  - Sets `mitigation_enabled = True`
- `POST /domains/{domain_id}/cf/disable-mitigation` -- toggle off (keeps lists, stops syncing)
- `PUT /domains/{domain_id}/cf/settings` -- update sync interval, block duration
- `POST /domains/{domain_id}/cf/refresh-origin-ips` -- re-resolve A records from CF DNS, show diff, queue firewall updates
- `GET /domains/{domain_id}/cf/status` -- CF integration state (wizard step, mitigation status, last sync, list counts)
- **Origin IP management:**
  - `GET /domains/{domain_id}/origin-ips` -- list origin IPs with labels and firewall status
  - `POST /domains/{domain_id}/origin-ips` -- add an origin IP (+ queue firewall allow)
  - `DELETE /domains/{domain_id}/origin-ips/{ip_id}` -- remove an origin IP (+ queue firewall deny)
- **Whitelist management (proxied CF operations):**
  - `GET /domains/{domain_id}/cf/whitelist` -- list whitelisted IPs (from local DB, synced to CF)
  - `POST /domains/{domain_id}/cf/whitelist` -- add IP to whitelist (stores in DB + pushes to CF whitelist)
  - `DELETE /domains/{domain_id}/cf/whitelist/{ip_id}` -- remove IP from whitelist (DB + CF)
- **Blocklist management (read + manual override):**
  - `GET /domains/{domain_id}/cf/blocklist` -- list currently blocked IPs (with TTL, threat score, country)
  - `DELETE /domains/{domain_id}/cf/blocklist/{ip}` -- manually unblock an IP (remove from CF blocklist)
  - `POST /domains/{domain_id}/cf/blocklist` -- manually block an IP (add to CF blocklist with custom duration)

### 3b. Active mitigation runtime (CF Sync Worker)

New worker `backend/app/workers/cf_sync_worker.py`:

- Runs on a loop (every `sync_interval_sec`, default 60s)
- For each domain with `mitigation_enabled = True`:
  - **Blocklist sync:**
    - Queries `detection_events` where `cf_pushed_at IS NULL` and threat is recent
    - Checks IP is not in the domain's whitelist (never block whitelisted IPs)
    - Pushes new IPs to CF blocklist via `POST /accounts/{account_id}/rules/lists/{list_id}/items`
    - Sets `cf_pushed_at = now()` and `cf_expires_at = now() + block_duration_sec`
    - Queries for expired entries (`cf_expires_at < now()`)
    - Removes expired IPs from CF blocklist
    - Clears `cf_pushed_at` and `cf_expires_at` on expired entries
  - **Whitelist sync:**
    - Queries `whitelisted_ips` where `cf_synced = False`
    - Pushes to CF whitelist, marks `cf_synced = True`

### 3c. Domain settings panel and status indicators

**Domains table -- per-domain status icons with hover hints:**

Each domain row in the domains table shows a series of small status icons/badges. On hover, each icon shows a tooltip explaining the current state.

| Icon | States | Hover hints |
|------|--------|-------------|
| Verification | green / yellow / grey | "Verified via CF" or "Verified via TXT" / "Verification in progress" / "Not verified -- complete setup wizard" |
| Firewall | green / yellow / red / grey | "All origin IPs whitelisted" / "Firewall command pending" / "Firewall command failed -- contact support" / "Not configured" |
| Log Forwarding | green / grey | "Receiving logs" / "No logs received yet -- check Nginx config" (green if logs received in last 5 min, checked via domain_logs) |
| Mitigation | green / orange / grey / blue | "Active -- blocking threats via CF" / "Enabled but no threats detected" / "Mitigation disabled" / "Non-CF: notification mode only" |

**Expanded domain settings (post-wizard):**

After the wizard is complete, the domain's row expands or links to a settings view showing:

- All status indicators above in full detail (not just icons)
- CF connection status (connected/token valid) with reconnect button, or "Non-CF mode" label
- **Origin IPs tab:** list of all origin IPs with labels, firewall status, add/remove buttons, refresh from CF DNS button
- Subdomain stripping toggle
- Firewall status per IP with timestamp of last successful CSF command
- Mitigation toggle (enable/disable) -- only for CF domains
- Block duration and sync interval controls -- only for CF domains
- **Blocklist tab:** currently blocked IPs with threat score, country, remaining TTL, manual unblock button, manual block input -- only for CF domains
- **Whitelist tab:** user-managed whitelist with add/remove, description field, sync status indicator -- only for CF domains
- **Key rotation button**: regenerate syslog API key (shows grace period warning: "Old key valid for 15 more minutes")

### 3d. Firewall Worker (ingestor server access control)

New worker `app/firewall_worker.py` (runs on the ingestor server alongside the syslog server):

- Consumes from RabbitMQ queue `firewall_commands`
- Message format: `{"action": "allow"|"deny", "ip": "1.2.3.4", "description": "detect7 domain:example.com user:42"}`
- On `allow`: executes `csf -a <ip> "<description>"` to whitelist the origin server's IP on the ingestor's firewall
- On `deny`: executes `csf -d <ip>` to revoke access
- Updates `firewall_commands` table status to `executed` or `failed` (with error message)
- Logs all commands for audit

**Lifecycle:**
- Domain verified (wizard Step 4 or 3b): `allow` command queued for each selected origin IP
- Origin IP added: `allow` command queued
- Origin IP removed: `deny` command queued
- Origin IP refreshed (CF DNS re-resolve): `deny` old IPs not in new set, `allow` new IPs not in old set
- Domain deleted: `deny` command queued for all origin IPs
- Only verified origin IPs can reach UDP 514 -- unauthorized senders are dropped at the firewall level

---

## Phase 4: Billing with Stripe (POSTPONE)

### 4a. Plan seeding

Create a management command or startup hook to seed default plans:

| Plan | Domains | RPS Cap | Detection Retention | CF Mitigation | Price |
|------|---------|---------|---------------------|---------------|-------|
| Free | 1 | 100 | 7 days | No | $0 |
| Pro | 10 | 1,000+ | 30 days | Yes | $10/mo |
| Enterprise | Unlimited | 5,000+ | 90 days | Yes + custom rules | $100/mo |

Raw nginx logs are always kept 24h regardless of plan (TimescaleDB retention policy). Detection events follow plan's `retention_days`.

### 4b. Stripe integration (POSTPONE)

- Add `stripe` to `backend/requirements.txt`
- New router `backend/app/routers/billing.py`:
  - `GET /billing/plans` -- list available plans
  - `POST /billing/checkout` -- create Stripe Checkout session, return URL
  - `GET /billing/subscription` -- current subscription status
  - `POST /billing/portal` -- create Stripe Customer Portal session
  - `POST /billing/webhook` -- Stripe webhook handler
- New env vars: `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `STRIPE_PUBLISHABLE_KEY`

### 4c. Enforce plan limits

- Create `backend/app/deps.py` dependency `enforce_plan_limits` that checks:
  - Domain count vs `plan.max_domains` on domain creation
  - RPS vs `plan.max_rps` on ingestion
  - CF mitigation allowed by plan
  - Returns `HTTP 402` or `HTTP 429` when exceeded

### 4d. Frontend billing page

- New Vue view `BillingPage.vue` at route `/app/billing`
- Shows current plan, usage stats, upgrade/downgrade buttons
- Redirects to Stripe Checkout for payment

---

## Phase 5: Auth Hardening

### 5a. Email verification

- On registration, set `email_verified = False`, generate `email_verify_token`
- Send verification email (SMTP or SendGrid/Mailgun)
- New endpoint `GET /auth/verify-email?token=...` to verify
- Block domain creation until email is verified
- Frontend: show banner "Please verify your email" in panel

### 5b. Password reset

- `POST /auth/forgot-password` -- sends reset email with JWT (short-lived, 1h)
- `POST /auth/reset-password` -- accepts token + new password
- Frontend: new `ForgotPasswordPage.vue` and `ResetPasswordPage.vue`

### 5c. API key management

- New router `backend/app/routers/apikeys.py`:
  - `GET /api-keys` -- list keys (show prefix + name, never full key)
  - `POST /api-keys` -- create key (return full key ONCE)
  - `POST /api-keys/{id}/rotate` -- regenerate key, old key valid for 15-min grace period
  - `DELETE /api-keys/{id}` -- revoke key immediately
- SHA-256 hash for DB lookups, Fernet encryption for reversible storage (cache rebuild)
- On create/rotate/revoke: update Redis cache immediately
- Frontend: API Keys section in panel with create/rotate/revoke UI, grace period countdown on rotation

### 5d. Rate limiting

- Add `slowapi` to `backend/requirements.txt`
- Apply limits: auth endpoints (5/min), API endpoints (60/min), syslog (plan-based)
- Return `Retry-After` header on 429

### 5e. CORS tightening

- In `backend/app/main.py`, replace `allow_origins=["*"]` with env-configurable `ALLOWED_ORIGINS`

---

## Phase 6: Frontend Enhancements

### 6a. New pages/routes

| Route | Component | Purpose |
|-------|-----------|---------|
| `/app` (domains table) | `DomainSetupWizard.vue` | Per-domain setup wizard (CF or non-CF track) |
| `/app` (domains table) | `DomainSettingsPanel.vue` | Post-wizard domain settings (IPs, CF, mitigation, key) |
| `/app/billing` | `BillingPage.vue` | Plan management |
| `/app/api-keys` | `ApiKeysPage.vue` | API key CRUD + rotation with grace period |
| `/forgot-password` | `ForgotPasswordPage.vue` | Password reset request |
| `/reset-password` | `ResetPasswordPage.vue` | Set new password |
| `/verify-email` | `VerifyEmailPage.vue` | Email confirmation landing |

### 6b. Dashboard improvements

- Add time range selector (5m, 30m, 1h, 6h, 24h, 7d) to `DashboardAnalytics.vue`
- Real-time stats: current RPS, attack RPS (from recent domain_logs + detection_events)
- Historical trends beyond 24h from `domain_stats` continuous aggregate
- Add real-time threat feed (polling or WebSocket for active detections)
- Add IP blocklist viewer with CF sync status (pushed/pending/expired)
- Show mitigation status indicator (CF active / notification-only)

### 6c. Panel navigation

- Expand `PanelNavbar.vue` with sidebar or tab navigation: Dashboard, Domains, API Keys, Billing, Settings
- CF integration lives inside each domain (wizard + settings), not as a separate nav item

---

## Phase 7: DevOps and Production Hardening

### 7a. Unified Docker Compose

- Merge or link `docker-compose.yml` and `docker-compose.saas.yml` so a single `docker compose up` starts everything
- Add services: Log Writer Worker, Detection Consumer, CF Sync Worker, Firewall Worker
- Replace MySQL/MariaDB with `timescale/timescaledb:latest-pg16`

### 7b. Environment and secrets

- Consolidate env vars into a single `.env.example` at project root
- Add `STRIPE_*`, `SMTP_*`, `ALLOWED_ORIGINS`, `FERNET_KEY` (for API key + CF token encryption) vars
- Remove MySQL-specific vars, add PostgreSQL `DATABASE_URL`

### 7c. Health and monitoring

- Expand `/health` to check DB (PostgreSQL), Redis, RabbitMQ, and CF API connectivity
- Add structured logging (JSON) for production
- Add CF sync health metrics (last sync time, items in list, sync errors)
- Monitor TimescaleDB chunk sizes and retention policy execution

---

## Implementation Order

Phases are ordered by dependency:

1. **Phase 1** (DB foundation + PostgreSQL/TimescaleDB) -- everything else depends on new models and time-series engine
2. **Phase 2** (Bridge pipeline) -- core product value, makes dashboard real
3. **Phase 3** (Cloudflare integration + non-CF track) -- key differentiator, active mitigation
4. **Phase 4** (Billing) -- monetization, POSTPONED until core features work
5. **Phase 5** (Auth hardening) -- security, can partially parallel with Phase 3
6. **Phase 6** (Frontend) -- incremental, done alongside each backend phase
7. **Phase 7** (DevOps) -- can be done incrementally throughout

Estimated scope: ~35-45 files modified/created across backend, frontend, and detection engine.
