# Mythic C2 + ngrok Setup Guide

## Red Team C2 Infrastructure on macOS (Apple Silicon)

### Environment

- MacBook Pro M4, macOS 15.7.7
- Docker Desktop 29.6.1
- Mythic v3.4.36
- ngrok (free tier)
- Agent: apfell (macOS JavaScript agent)
- C2 Profile: HTTP

### Purpose

Lab environment for:
- **Mythic** — cross-platform post-exploit red teaming framework
- **apfell** — macOS/JavaScript implant for adversary simulation
- **ngrok** — public tunnel to expose C2 callback endpoint without a VPS

### Architecture

```
┌──────────┐     ┌──────────────────┐     ┌──────────────────────┐
│  Target  │────▶│  ngrok tunnel    │────▶│  Nginx (localhost)   │
│  Agent   │◀────│  (public URL)    │◀────│  :7443               │
└──────────┘     └──────────────────┘     └──────────┬───────────┘
                                                      │
                                           ┌──────────▼───────────┐
                                           │  Mythic Server       │
                                           │  (GoLang :17443)     │
                                           └──────────┬───────────┘
                                                      │ RabbitMQ
                                           ┌──────────▼───────────┐
                                           │  HTTP C2 Profile     │
                                           │  (message routing)   │
                                           └──────────┬───────────┘
                                                      │
                                           ┌──────────▼───────────┐
                                           │  Postgres + Hasura   │
                                           │  (data/graph)        │
                                           └──────────────────────┘
```

### Mythic Docker Containers

| Container              | Purpose                      | Port        | Bound Locally |
|------------------------|------------------------------|-------------|---------------|
| mythic_nginx           | Reverse proxy / TLS          | 7443        | No (0.0.0.0)  |
| mythic_server          | Core backend (GoLang)        | 17443       | Yes           |
| mythic_postgres        | Database                     | 5432        | Yes           |
| mythic_rabbitmq        | Message broker               | 5672        | Yes           |
| mythic_graphql         | Hasura GraphQL engine        | 8080        | Yes           |
| mythic_react           | React UI (dev server)        | 3000        | Yes           |
| mythic_jupyter         | Jupyter notebooks            | 8888        | Yes           |
| mythic_documentation   | Internal docs site           | 8090        | Yes           |
| http                   | HTTP C2 profile              | (internal)  | N/A           |
| apfell                 | Agent build container        | (internal)  | N/A           |

---

## Prerequisites

- Docker Desktop installed and running (includes Docker Compose)
- Homebrew installed
- ngrok account (free): https://dashboard.ngrok.com/signup

> **Note:** Go is NOT required. `make macos` extracts a prebuilt binary from
> a Docker image. Go is only needed if building from source with `make local`.

---

## Step 1 — Install ngrok

```bash
brew install ngrok
```

Register and get your auth token from: https://dashboard.ngrok.com/get-started/your-authtoken

```bash
ngrok config add-authtoken YOUR_TOKEN_HERE
```

Verify:

```bash
ngrok version
```

---

## Step 2 — Clone Mythic

```bash
cd ~
git clone https://github.com/its-a-feature/Mythic.git
cd Mythic
```

> **Important:** Clone to `~/` (home directory). Docker Desktop on macOS only
> shares directories under `/Users/` by default. Cloning to `/opt/` or other
> paths will cause mount permission errors when containers start.

---

## Step 3 — Build mythic-cli

```bash
make macos
```

This extracts the macOS binary from the official Docker image. Verify:

```bash
file mythic-cli
# Expected: Mach-O 64-bit executable arm64
```

> **Note:** `make` (default) builds a Linux binary. Use `make macos` on macOS.

---

## Step 4 — Start Mythic

```bash
./mythic-cli start
```

First run will:
- Generate a `docker-compose.yml`
- Generate a `.env` with random passwords
- Pull all Docker images (takes a few minutes)
- Start 8 core containers

Verify all containers are healthy:

```bash
./mythic-cli status
```

Expected output — all containers should show `running` and `healthy`:

```
mythic_postgres     running    Up X minutes (healthy)
mythic_rabbitmq     running    Up X minutes (healthy)
mythic_server       running    Up X minutes (healthy)
mythic_nginx        running    Up X minutes (healthy)
...
```

Access the web UI:

```
https://127.0.0.1:7443/new/login
```

Default credentials (from source: `mythic_admin` / `mythic_password`):
- Username: `mythic_admin`
- Password: randomly generated on first run

To check your actual credentials:
```bash
grep MYTHIC_ADMIN ~/Mythic/.env
```

> **Troubleshooting:** If nginx fails with SSL permission errors:
> ```bash
> sudo chmod 644 ~/Mythic/nginx-docker/ssl/mythic-ssl.key
> ./mythic-cli restart mythic_nginx
> ```

---

## Step 5 — Install HTTP C2 Profile

The C2 profile is the transport layer between agents and the Mythic server.

```bash
./mythic-cli install github https://github.com/MythicC2Profiles/http
```

This will:
- Clone the HTTP C2 profile repo
- Add it to docker-compose.yml
- Pull the C2 Docker image
- Start the container and sync with Mythic via RabbitMQ

Verify:

```bash
./mythic-cli status
```

You should see `http` under "Installed Services" with state `running`.

---

## Step 6 — Install an Agent (apfell)

```bash
./mythic-cli install github https://github.com/MythicAgents/apfell
```

apfell is a macOS/JavaScript agent. Other popular agents:

| Agent    | Language   | Platforms               |
|----------|------------|-------------------------|
| apfell   | JavaScript | macOS                   |
| apollo   | C#         | Windows                 |
| merlin   | Go         | Windows, Linux, macOS   |
| poseidon | Go         | macOS, Linux            |

Verify:

```bash
./mythic-cli status
```

You should see both `http` and `apfell` under "Installed Services".

---

## Step 7 — Start ngrok Tunnel

The HTTP C2 profile listens on port 80 inside Docker. Agent traffic is routed
through nginx (port 7443) to the Mythic server, which forwards messages to
the C2 profile via RabbitMQ.

Start the tunnel:

```bash
ngrok http https://localhost:7443
```

> **Important:** Use `https://localhost:7443` (not just `7443`). Mythic's
> nginx listens on port 7443 with SSL enabled. Using plain `ngrok http 7443`
> will result in a `400 Bad Request: plain HTTP request sent to HTTPS port`.

ngrok will display:

```
Forwarding  https://XXXX-XXX-XXX-XXX-XX.ngrok-free.app → https://localhost:7443
```

Copy the `https://XXXX.ngrok-free.app` URL — this is your **callback host**.

Verify the tunnel works:

```bash
curl -sk https://XXXX.ngrok-free.app/new/login | head -1
# Expected: <!doctype html><html lang="en">...
```

---

## Step 8 — Build a Payload

1. Open the Mythic UI: `https://127.0.0.1:7443/new/login`

2. **Create an Operation:**
   - Click the operation dropdown (top-left)
   - Create a new operation (name it anything, e.g. "lab-test")
   - Select yourself as the operator

3. **Build Payload:**
   - Navigate to **Payloads** (left sidebar)
   - Click **Create** → select **apfell**
   - Set C2 profile parameters:
     - `callback_host` = `https://XXXX.ngrok-free.app` (your ngrok URL)
     - `callback_port` = `443`
   - Select target OS: **macOS**
   - Select architecture: **arm64** or **x86_64** (match your target)
   - Click **Build**

4. **Download Payload:**
   - Once built, download the payload file from the Payloads page

5. **Execute on Target:**
   ```bash
   chmod +x payload_file
   ./payload_file
   ```

6. **Check for Callback:**
   - Go to **Callbacks** in the Mythic UI
   - Your agent should appear within a few seconds
   - Click on it to interact (run commands, etc.)

---

## Step 9 — Interact with the Agent

Once a callback appears in the UI:

1. Click on the callback row
2. Type commands in the tasking bar at the bottom
3. Try basic commands:
   - `whoami` — current user
   - `ls` — list files
   - `screenshot` — capture screen
   - `shell whoami` — run native shell command

---

## Operations

### Start Mythic

```bash
cd ~/Mythic
./mythic-cli start
```

### Stop Mythic

```bash
cd ~/Mythic
./mythic-cli stop
```

### Restart a Specific Container

```bash
./mythic-cli restart mythic_nginx
./mythic-cli restart http
```

### View Container Logs

```bash
docker logs mythic_server --tail 50
docker logs http --tail 50
```

### Start ngrok (after Mythic is running)

```bash
ngrok http https://localhost:7443
```

> **Note:** On the free tier, ngrok generates a new URL on each restart.
> You'll need to rebuild payloads with the new `callback_host` each time.
> Paid ngrok plans support stable custom subdomains.

---

## Troubleshooting

### Containers stuck in "Created" state

Usually a Docker file sharing issue. Make sure Mythic is cloned under `~/`:

```bash
# Wrong: /opt/Mythic, /tmp/Mythic
# Right: ~/Mythic
```

### nginx fails with SSL permission denied

```bash
sudo chmod 644 ~/Mythic/nginx-docker/ssl/mythic-ssl.key
./mythic-cli restart mythic_nginx
```

### mythic_server unhealthy / won't start

Check logs:

```bash
docker logs mythic_server --tail 50
```

Common cause: port conflict. Check if something else is using port 17443:

```bash
lsof -i :17443
```

### Agent doesn't call back

1. Verify ngrok is running: `curl -sk https://YOUR_NGROK_URL/new/login`
2. Check the C2 profile is running: `./mythic-cli status`
3. Verify `callback_host` matches your current ngrok URL exactly
4. Check ngrok inspection UI: `http://127.0.0.1:4040` — shows all traffic
5. Check agent container logs: `docker logs http --tail 20`

### ngrok URL changed

Free tier ngrok URLs change on restart. After restarting ngrok:

1. Copy the new URL from ngrok output
2. Rebuild the payload with the new `callback_host`
3. Deploy the new payload to the target

---

## Security Notes

- **Lab use only.** ngrok domains (*.ngrok-free.app) are well-known and
  flagged by corporate EDR/proxy products.
- Mythic binds internal services to `127.0.0.1` by default — good.
- The nginx port (7443) binds to `0.0.0.0` — accessible from your network.
  Change with: `./mythic-cli config set nginx_bind_localhost_only true`
- ngrok terminates TLS at their edge. Application-layer encryption
  (Mythic's key exchange) still protects agent messages in transit.
- For real engagements, use a VPS redirector with a clean domain instead
  of ngrok.

---

## References

- Mythic Docs: https://docs.mythic-c2.net
- Mythic GitHub: https://github.com/its-a-feature/Mythic
- Agent Downloads: https://github.com/MythicAgents
- C2 Profiles: https://github.com/MythicC2Profiles
- ngrok Docs: https://ngrok.com/docs
