# n8n Workflow Automation — Docker Setup & Security Guide

# n8n Docker Deployment + Hardening Guide

## Environment

| Component | Value |
|-----------|-------|
| macOS version | 15.7.7 (Sequoia) |
| Docker Desktop | 29.6.1 |
| n8n version | 2.28.6 (latest as of 2026-07-05) |
| Database | PostgreSQL 16 (Alpine) in companion container |
| Shared filesystem | `/Users/nb-dk-0552/PlayGround/n8n-shared` → `/data/shared` in container |
| n8n data volume | `n8n_data` Docker volume → `/home/node/.n8n` inside container |
| Instance URL | `http://localhost:5678` |

## Purpose

Local n8n deployment for:
- **Workflow automation testing** — develop and test automation workflows locally
- **Security auditing** — pentest target for MCP OAuth, SSRF, and auth bypass research
- **Node development** — test custom community nodes without affecting production
- **Vulnerability research** — validate findings from static analysis (scode) against a live instance

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                      Docker Host                        │
│  ┌──────────────────────┐   ┌─────────────────────────┐ │
│  │    n8n (5678)        │   │  PostgreSQL 16 (5432)   │ │
│  │  docker.n8n.io/n8nio │   │  postgres:16-alpine     │ │
│  │                      │   │                         │ │
│  │  /home/node/.n8n     │   │  /var/lib/postgresql/   │ │
│  │    (n8n_data vol)    │   │  data (postgres_data)   │ │
│  │                      │   │                         │ │
│  │  /data/shared ← bind │   │  healthcheck:pg_isready │ │
│  └──────────┬───────────┘   └─────────────┬───────────┘ │
│             │                              │             │
│             └────────── n8n-net ───────────┘             │
└─────────────────────────────────────────────────────────┘
```

---

## Prerequisites

- Docker Desktop 4.x+ installed (`/Applications/Docker.app`)
- 2 GB free disk space (Docker images + volumes)
- Port 5678 available (check with `lsof -i :5678`)
- `openssl` installed (macOS built-in)

---

## Step 1: Directory Structure

```bash
mkdir -p /opt/n8n/docker-setup
mkdir -p /Users/nb-dk-0552/PlayGround/n8n-shared
```

All deployment files live in `/opt/n8n/docker-setup/`. The shared directory is at `~/n8n-shared`.

**macOS constraint:** Docker Desktop bind mounts must be under `/Users/`, `/tmp/`, or `/Volumes/`. System paths like `/opt/` or `/etc/` won't work for bind mounts — that's why the shared directory lives in the home directory.

---

## Step 2: Environment Configuration

**File:** `/opt/n8n/docker-setup/.env`

```bash
# Database credentials
POSTGRES_DB=n8n
POSTGRES_USER=n8n
POSTGRES_PASSWORD=<generate a strong random password>

# Encryption key for n8n credential storage
N8N_ENCRYPTION_KEY=<generate with openssl>
```

Generate secrets:

```bash
openssl rand -hex 32   # ← output is your N8N_ENCRYPTION_KEY
openssl rand -base64 32   # ← output is your POSTGRES_PASSWORD
```

**Critical security notes:**
- The encryption key encrypts ALL stored credentials (API keys, database passwords, OAuth tokens). Loss of this key = permanent loss of all credentials.
- The Postgres password is used at initialization. Changing it later requires manual DB migration.
- Keep `.env` out of version control. A `.env.example` file is provided for sharing the structure without secrets.

---

## Step 3: Docker Compose

**File:** `/opt/n8n/docker-setup/docker-compose.yml`

```yaml
services:
  n8n:
    image: docker.n8n.io/n8nio/n8n:latest
    container_name: n8n
    restart: unless-stopped
    ports:
      - "5678:5678"
    environment:
      # ── Database ──
      - DB_TYPE=postgresdb
      - DB_POSTGRESDB_HOST=db
      - DB_POSTGRESDB_PORT=5432
      - DB_POSTGRESDB_DATABASE=${POSTGRES_DB:-n8n}
      - DB_POSTGRESDB_USER=${POSTGRES_USER:-n8n}
      - DB_POSTGRESDB_PASSWORD=${POSTGRES_PASSWORD}

      # ── Security: enable all nodes (including Execute Command) ──
      - NODES_EXCLUDE=[]

      # ── Encryption key ──
      - N8N_ENCRYPTION_KEY=${N8N_ENCRYPTION_KEY}

      # ── Cookie / auth (HTTP, not HTTPS) ──
      - N8N_SECURE_COOKIE=false

      # ── Webhook URL ──
      - WEBHOOK_URL=http://localhost:5678/

      # ── Python support in Code node ──
      - N8N_PYTHON_ENABLED=true

      # ── Logging ──
      - N8N_LOG_LEVEL=info
      - N8N_LOG_OUTPUT=console

      # ── Binary data: filesystem mode ──
      - N8N_DEFAULT_BINARY_DATA_MODE=filesystem

      # ── SSRF: allow reaching host services ──
      - N8N_SSRF_ALLOWED_IP_RANGES=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8

      # ── Timezone ──
      - GENERIC_TIMEZONE=Asia/Seoul
    volumes:
      - n8n_data:/home/node/.n8n
      - /Users/nb-dk-0552/PlayGround/n8n-shared:/data/shared
    depends_on:
      db:
        condition: service_healthy
    networks:
      - n8n-net

  db:
    image: postgres:16-alpine
    container_name: n8n-db
    restart: unless-stopped
    environment:
      - POSTGRES_DB=${POSTGRES_DB:-n8n}
      - POSTGRES_USER=${POSTGRES_USER:-n8n}
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER:-n8n} -d ${POSTGRES_DB:-n8n}"]
      interval: 5s
      timeout: 5s
      retries: 5
    networks:
      - n8n-net

volumes:
  n8n_data:
    driver: local
  postgres_data:
    driver: local

networks:
  n8n-net:
    driver: bridge
```

### Key Configuration Decisions

| Setting | Value | Rationale |
|---------|-------|-----------|
| `DB_TYPE=postgresdb` | PostgreSQL | Production-grade, not SQLite. Enables concurrent workflow execution |
| `NODES_EXCLUDE=[]` | Empty array | **All nodes enabled** including `ExecuteCommand` (RCE risk for pentests but required for exploitation research) |
| `N8N_SECURE_COOKIE=false` | Disabled | Required for plain HTTP (no TLS). In production behind reverse proxy, set to `true` |
| `N8N_SSRF_ALLOWED_IP_RANGES` | Private+loopback | **SSRF protection is disabled by default** in n8n. These ranges are for the allowlist, but the feature must be enabled with `N8N_SSRF_PROTECTION_ENABLED=true` |
| `WEBHOOK_URL` | localhost:5678 | Change to public domain if exposing n8n externally |
| `N8N_PYTHON_ENABLED=true` | Enabled | Allows Python code execution in Code node |

---

## Step 4: Deployment

```bash
cd /opt/n8n/docker-setup
docker compose up -d
```

Expected output:

```
[+] Running 3/3
 ✔ Network n8n-net  Created
 ✔ Container n8n-db  Healthy
 ✔ Container n8n    Started
```

Verify:

```bash
docker compose ps
```

Expected:

```
NAME      IMAGE                              STATUS          PORTS
n8n       docker.n8n.io/n8nio/n8n:latest     Up (healthy)    0.0.0.0:5678->5678/tcp
n8n-db    postgres:16-alpine                 Up (healthy)    5432/tcp
```

Check logs:

```bash
docker compose logs n8n --tail 20
```

Expected output includes migration logs (n8n auto-migrates the database schema on startup):

```
Starting migration CreateUserManagement1646992772331
Finished migration CreateUserManagement1646992772331
...
Server is now listening on port 5678
```

---

## Step 5: First-Time Setup

1. Open `http://localhost:5678` in a browser
2. Complete the owner account setup wizard:
   - Email (used for login)
   - Full name
   - Password (min 8 characters)
3. Skip optional steps (email verification, templates)
4. You're now logged into the n8n Editor UI

**To check setup status programmatically:**

```bash
curl -s http://localhost:5678/rest/settings | python3 -m json.tool
```

Look for `"showSetupOnFirstLoad": false` — this confirms setup is complete.

---

## Step 6: Verifying the Instance

### Health Check (no auth required)

```bash
curl http://localhost:5678/healthz
# → {"status":"ok"}
```

### Instance Configuration (no auth required)

```bash
curl http://localhost:5678/rest/settings | python3 -m json.tool
```

Reveals: auth method, password policy, SSO config, community nodes status, enterprise licensing.

### Login (requires credentials)

```bash
curl -c cookies.txt http://localhost:5678/rest/login \
  -H "Content-Type: application/json" \
  -d '{"emailOrLdapLoginId":"your@email.com","password":"yourpassword"}'
# → 200 with session cookie in cookies.txt
```

### Authenticated — List Users

```bash
curl -b cookies.txt http://localhost:5678/rest/users
# → 200 with user list (owner only initially)
```

### Database State

```bash
docker exec n8n-db psql -U n8n -d n8n -c 'SELECT email, "roleSlug" FROM public."user";'
```

---

## Step 7: Security Observations (v2.28.6 Defaults)

### Unauthenticated Endpoints (discovered during pentest)

| Endpoint | HTTP | Returns | Risk |
|----------|------|---------|------|
| `/healthz` | 200 | `{"status":"ok"}` | Info |
| `/rest/settings` | 200 | Auth config, SSO, feature flags | Medium |
| `/.well-known/oauth-authorization-server` | 200 | OAuth metadata, registration endpoint | Medium |
| `/mcp-oauth/register` | 201 | OAuth client registration (unauth) | **Critical** |
| `/api/v1/docs/` | 200 | Swagger UI (empty spec) | Low |

### Security Headers Present

```
X-Frame-Options: SAMEORIGIN
X-Content-Type-Options: nosniff
Cross-Origin-Opener-Policy: same-origin-allow-popups
Cross-Origin-Resource-Policy: same-origin
Referrer-Policy: no-referrer
X-XSS-Protection: 0
```

### Security Headers Missing

| Header | Recommendation |
|--------|---------------|
| `Content-Security-Policy` | Add via `N8N_CONTENT_SECURITY_POLICY` env var |
| `Strict-Transport-Security` | Configure at reverse proxy level (not n8n) |

### Authenticated Endpoints (all return 401 without session)

| Endpoint | Description |
|----------|-------------|
| `/rest/users` | List users |
| `/rest/workflows` | List workflows |
| `/rest/credentials` | List credentials (read-only) |
| `/rest/executions` | Execution history |
| `/api/v1/workflows` | API access (requires X-N8N-API-KEY) |
| `/api/v1/credentials` | API access (405 — read only) |

---

## Appendix: Handy Commands

### Container Management

```bash
# Start
docker compose -f /opt/n8n/docker-setup/docker-compose.yml up -d

# Stop
docker compose -f /opt/n8n/docker-setup/docker-compose.yml down

# View logs
docker compose -f /opt/n8n/docker-setup/docker-compose.yml logs -f n8n

# Restart n8n only (not DB)
docker compose -f /opt/n8n/docker-setup/docker-compose.yml restart n8n

# Shell into n8n container
docker exec -it n8n sh
```

### Database Access

```bash
# Interactive psql REPL
docker exec -it n8n-db psql -U n8n -d n8n

# One-shot query
docker exec n8n-db psql -U n8n -d n8n -c 'SELECT count(*) FROM public."user";'

# List all tables
docker exec n8n-db psql -U n8n -d n8n -c '\dt'

# Schema for a table
docker exec n8n-db psql -U n8n -d n8n -c '\d "user"'
```

### n8n CLI (inside container)

```bash
# Export all workflows
docker exec n8n n8n export:workflow --all --output=/data/shared/backup.json

# Export all credentials (encrypted)
docker exec n8n n8n export:credentials --all --output=/data/shared/creds.json

# Import workflows
docker exec n8n n8n import:workflow --input=/data/shared/backup.json

# List installed packages
docker exec n8n n8n execute --help
```

### Data Backup

```bash
# Export all data via n8n CLI
docker exec n8n n8n export:workflow --all --output=/data/shared/workflows-$(date +%Y%m%d).json
docker exec n8n n8n export:credentials --all --output=/data/shared/credentials-$(date +%Y%m%d).json

# Postgres dump
docker exec n8n-db pg_dump -U n8n -d n8n > /tmp/n8n-db-$(date +%Y%m%d).sql
```

### Pentest-Specific

```bash
# Test MCP OAuth scope escalation
curl -s -X POST http://localhost:5678/mcp-oauth/register \
  -H "Content-Type: application/json" \
  -d '{"client_name":"test","redirect_uris":["http://localhost:9999/cb"],
       "token_endpoint_auth_method":"none",
       "scope":"admin:all tool:executeWorkflow tool:listWorkflows"}'

# Check version embedded in JS bundle
curl -s http://localhost:5678/assets/index-*.js | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | sort -u

# Check webhook paths
for w in slack alert deploy github jira payment callback; do
  curl -s -o /dev/null -w "%{http_code}\n" "http://localhost:5678/webhook/$w"
done
```

---

## Appendix: Security Hardening for Production

| Setting | Production Value | Rationale |
|---------|-----------------|-----------|
| `N8N_SSRF_PROTECTION_ENABLED` | `true` | Blocks access to private IP ranges from HTTP Request node |
| `N8N_CONTENT_SECURITY_POLICY` | `{"frame-ancestors":["'self'"],"base-uri":["'self'"]}` | Prevents XSS and clickjacking |
| `N8N_SECURE_COOKIE` | `true` | Requires HTTPS |
| `NODES_EXCLUDE` | Add `executeCommand`, `localFileTrigger`, `readBinaryFiles`, `writeBinaryFile` | Removes dangerous nodes from workflow palette |
| `N8N_ENCRYPTION_KEY` | 32-byte hex (64 chars) | Store in a vault / secrets manager |
| Reverse proxy | Add nginx with HSTS + CSP | First line of defense |
| Database | Dedicated Postgres instance, not Docker | Better backup, monitoring, security |

---

## Troubleshooting

### Container fails to start — "Database is not ready!"

Postgres takes ~10 seconds on first boot. Docker Compose healthcheck handles this automatically, but on first run watch for:

```bash
docker compose logs -f
```

Wait for: `database system is ready to accept connections` in db logs, then n8n starts.

### Port 5678 already in use

```bash
lsof -i :5678
# Kill the process or change port in docker-compose.yml
```

### Permissions on shared directory

The n8n container runs as `node` user (UID 1000). If bind mount files have wrong ownership:

```bash
# Fix inside container
docker exec n8n sh -c "chown -R 1000:1000 /data/shared"
```

### Reset everything (clean slate)

```bash
cd /opt/n8n/docker-setup
docker compose down -v   # -v removes volumes too
docker compose up -d     # Fresh start
```

This deletes ALL data including workflows, credentials, and the owner account.

---

## References

- [n8n Docker documentation](https://docs.n8n.io/hosting/installation/docker/)
- [n8n environment variables](https://docs.n8n.io/hosting/configuration/environment-variables/)
- [n8n security documentation](https://docs.n8n.io/hosting/security/)
- [Model Context Protocol OAuth](https://modelcontextprotocol.io/)
