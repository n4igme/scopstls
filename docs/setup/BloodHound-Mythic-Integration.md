# BloodHound CE + Mythic C2 Integration Guide

## AI-Driven AD Attack Path Analysis on macOS (Apple Silicon)

### Environment

- MacBook Pro M4, macOS 15.7.7
- Docker Desktop 29.6.1
- Mythic v3.4.36 (C2 framework)
- BloodHound CE v9.3.0 (AD attack path visualization)
- Hermes Agent with MCP integration
- Neo4j 4.4.42 (graph database)
- PostgreSQL 16 (BloodHound backend)

### Purpose

End-to-end Active Directory attack path analysis:
- **Mythic** — deploy agents on Windows targets, execute SharpHound
- **BloodHound** — visualize AD relationships, find attack paths
- **Hermes MCP** — AI-driven automation: run SharpHound, import data, query graph

### Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        YOUR MAC (Hermes Agent)                       │
│                                                                      │
│  ┌─────────────┐     MCP (stdio)     ┌──────────────────┐           │
│  │ Hermes      │◄───────────────────►│ Mythic MCP       │           │
│  │ Agent       │                     │ (~/Mythic/MCP)   │           │
│  └──────┬──────┘                     └────────┬─────────┘           │
│         │                                     │                     │
│         │ MCP tools                           │ Mythic Python SDK   │
│         │                                     │                     │
│  ┌──────▼──────────────┐             ┌────────▼─────────┐           │
│  │ Neo4j MCP           │             │ Mythic Server     │           │
│  │ (Cypher queries)    │             │ (localhost:7443)  │           │
│  └──────┬──────────────┘             └────────┬─────────┘           │
│         │                                     │                     │
│  ┌──────▼──────────────┐             ┌────────▼─────────┐           │
│  │ BloodHound CE       │             │ HTTP C2 Profile   │           │
│  │ (localhost:8880)    │             │ (message routing) │           │
│  │ ┌────────────────┐  │             └────────┬─────────┘           │
│  │ │ Neo4j (7687)   │  │                      │ RabbitMQ            │
│  │ │ PostgreSQL      │  │             ┌────────▼─────────┐           │
│  │ └────────────────┘  │             │ Agent on Target   │           │
│  └─────────────────────┘             │ (Windows/AD)     │           │
│                                      └──────────────────┘           │
│                                                                      │
│  DATA FLOW:                                                          │
│  Agent → SharpHound → .zip → BloodHound API → Neo4j Graph          │
│  Hermes → Cypher query → Neo4j → Attack paths                       │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Prerequisites

- Docker Desktop installed and running
- Mythic C2 installed and running (see [Mythic-C2-Setup.md](./Mythic-C2-Setup.md))
- Homebrew installed
- uv installed (`brew install uv`)

---

## Step 1 — Install BloodHound CE

### Create project directory

```bash
mkdir -p ~/Project/scopstls/config/BloodHound
cd ~/Project/scopstls/config/BloodHound
```

### Create docker-compose.yml

```yaml
services:
  app-db:
    image: postgres:16
    container_name: bloodhound-postgres
    restart: unless-stopped
    environment:
      - PGUSER=bloodhound
      - POSTGRES_USER=bloodhound
      - POSTGRES_PASSWORD=bloodhoundcommunityedition
      - POSTGRES_DB=bloodhound
    ports:
      - "127.0.0.1:5433:5432"
    volumes:
      - postgres_data:/var/lib/postgresql
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U bloodhound -d bloodhound -h 127.0.0.1 -p 5432"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 30s

  graph-db:
    image: neo4j:4.4.42
    container_name: bloodhound-neo4j
    restart: unless-stopped
    environment:
      - NEO4J_AUTH=neo4j/bloodhoundcommunityedition
      - NEO4J_dbms_allow__upgrade=true
    ports:
      - "127.0.0.1:7687:7687"
      - "127.0.0.1:7474:7474"
    volumes:
      - neo4j_data:/data
    healthcheck:
      test: ["CMD-SHELL", "wget -O /dev/null -q http://localhost:7474 || exit 1"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 30s

  bloodhound:
    image: specterops/bloodhound:latest
    container_name: bloodhound
    restart: unless-stopped
    environment:
      - bhe_disable_cypher_complexity_limit=false
      - bhe_enable_cypher_mutations=true
      - bhe_graph_query_memory_limit=2
      - bhe_database_connection=user=bloodhound password=bloodhoundcommunityedition dbname=bloodhound host=app-db
      - bhe_neo4j_connection=neo4j://neo4j:bloodhoundcommunityedition@graph-db:7687/
      - bhe_recreate_default_admin=false
      - bhe_graph_driver=neo4j
    ports:
      - "127.0.0.1:8880:8080"
    depends_on:
      app-db:
        condition: service_healthy
      graph-db:
        condition: service_healthy

volumes:
  neo4j_data:
  postgres_data:
```

> **Note:** Port 8880 is used instead of 8080 to avoid conflict with Mythic's Hasura GraphQL engine.

### Start BloodHound

```bash
cd ~/Project/scopstls/config/BloodHound
docker compose up -d
```

Wait for all containers to become healthy:

```bash
docker ps --format "table {{.Names}}\t{{.Status}}" | grep blood
```

Expected output:

```
bloodhound             Up X seconds
bloodhound-postgres    Up X seconds (healthy)
bloodhound-neo4j       Up X seconds (healthy)
```

### Get initial admin password

```bash
docker logs bloodhound 2>&1 | grep "Initial Password"
```

Output:

```
# Initial Password Set To:    XXXXXXXXXXXXXXXXXXXXXXXXXX    #
```

### Access BloodHound UI

Open: `http://127.0.0.1:8880/ui/login`

- Username: `admin`
- Password: (from the log above)

You will be prompted to change the password on first login.

---

## Step 2 — Install Mythic MCP Dependencies

The Mythic MCP server allows Hermes Agent to control Mythic agents via natural language.

```bash
cd ~/Mythic/MCP
uv venv
uv pip install -e .
```

Verify connection:

```bash
cd ~/Mythic/MCP
.venv/bin/python -c "
import asyncio
from lib.mythic_api import MythicAPI
async def test():
    api = MythicAPI('mythic_admin', 'YOUR_PASSWORD', 'localhost', '7443')
    await api.connect()
    agents = await api.get_all_agents()
    print(f'Connected! Found {len(agents)} active agents')
asyncio.run(test())
"
```

> Replace `YOUR_PASSWORD` with: `grep MYTHIC_ADMIN ~/Mythic/.env`

---

## Step 3 — Configure Hermes Agent MCP Servers

Add the following to `~/.hermes/config.yaml` under `mcp_servers:`:

### Neo4j MCP (direct Cypher queries to BloodHound's graph)

```yaml
  neo4j:
    command: /Users/<your-user>/.local/bin/mcp-neo4j-cypher
    args:
      - --db-url
      - bolt://127.0.0.1:7687
      - --username
      - neo4j
      - --password
      - bloodhoundcommunityedition
      - --read-only
    timeout: 60
    enabled: true
```

### Mythic MCP (agent control + BloodHound integration)

```yaml
  mythic:
    command: uv
    args:
      - --directory
      - /Users/<your-user>/Mythic/MCP
      - run
      - main.py
      - mythic_admin
      - YOUR_PASSWORD
      - localhost
      - "7443"
    timeout: 120
```

> Replace `<your-user>` and `YOUR_PASSWORD` with your actual values.

Restart Hermes to load the new MCP servers.

---

## Step 4 — Verify Integration

After restarting Hermes, verify all tools are available:

### Neo4j MCP Tools

| Tool                  | Description                                    |
|-----------------------|------------------------------------------------|
| mcp_neo4j_get_neo4j_schema  | Explore graph structure (nodes, relationships) |
| mcp_neo4j_read_neo4j_cypher | Execute read-only Cypher queries              |

### Mythic MCP Tools (BloodHound-related)

| Tool                              | Description                              |
|-----------------------------------|------------------------------------------|
| mcp_mythic_import_to_bloodhound   | Import SharpHound .zip into BloodHound   |
| mcp_mythic_bloodhound_query       | Cypher queries via BloodHound API        |
| mcp_mythic_run_sharphound_and_import | Full pipeline: collect → import      |

### Test Neo4j Connection

Ask Hermes: "What's in the BloodHound graph database?"

Hermes will call `mcp_neo4j_get_neo4j_schema` and report the current graph state (empty on fresh install).

---

## Step 5 — Collect AD Data with SharpHound

### Option A: Full Pipeline (Recommended)

Ask Hermes: "Run SharpHound on agent 1 and import into BloodHound"

This will:
1. Execute SharpHound.exe on the Windows target via Mythic agent
2. Download the .zip collection file
3. Upload it to BloodHound via API
4. BloodHound automatically processes and ingests the data

### Option B: Manual Workflow

1. **Run SharpHound via Mythic:**
   ```
   Ask Hermes: "Run SharpHound on agent 1"
   ```

2. **Download the .zip from Mythic UI:**
   - Go to `https://127.0.0.1:7443` → Files → Download the SharpHound .zip

3. **Import into BloodHound:**
   - Go to `http://127.0.0.1:8880/ui` → Administration → File Ingest
   - Upload the .zip file

### Option C: Standalone SharpHound

If you have SharpHound.exe on a Windows machine outside Mythic:

```powershell
# On the Windows target
SharpHound.exe -c All --stealth --outputdirectory C:\Temp
```

Copy the .zip to your Mac and import via BloodHound UI or API.

---

## Step 6 — Query Attack Paths

Once data is imported, ask Hermes to analyze it:

### Find Domain Admins

```
Ask: "Show me all domain admins from BloodHound"
```

Hermes executes:
```cypher
MATCH (g:Group {name:'DOMAIN ADMINS@DOMAIN.LOCAL'})-[:MemberOf*0..]->(n)
RETURN n
```

### Shortest Path to Domain Admin

```
Ask: "What's the shortest path to Domain Admin in BloodHound?"
```

Hermes executes:
```cypher
MATCH p=shortestPath(
  (u:User)-[*1..]->(g:Group {name:'DOMAIN ADMINS@DOMAIN.LOCAL'})
)
RETURN p
```

### Kerberoastable Users

```
Ask: "Find kerberoastable users in BloodHound"
```

Hermes executes:
```cypher
MATCH (u:User {hasspn:true})
RETURN u.name, u.serviceprincipalnames
```

### All Computers

```
Ask: "List all computers in the BloodHound graph"
```

### Custom Queries

```
Ask: "Run this Cypher query against BloodHound: MATCH (c:Computer) RETURN c.name, c.operatingsystem"
```

---

## Operations

### Start BloodHound

```bash
cd ~/Project/scopstls/config/BloodHound
docker compose up -d
```

### Stop BloodHound

```bash
cd ~/Project/scopstls/config/BloodHound
docker compose down
```

### View Logs

```bash
docker logs bloodhound --tail 50
docker logs bloodhound-neo4j --tail 50
docker logs bloodhound-postgres --tail 50
```

### Reset BloodHound (Delete All Data)

```bash
cd ~/Project/scopstls/config/BloodHound
docker compose down -v
docker compose up -d
```

> **Warning:** This deletes all imported data and resets the admin password.

### Restart Neo4j Only

```bash
docker restart bloodhound-neo4j
```

---

## MCP Tools Reference

### Neo4j MCP (direct graph access)

| Tool                  | Example Prompt                                      |
|-----------------------|-----------------------------------------------------|
| get_neo4j_schema      | "What's the structure of the BloodHound graph?"     |
| read_neo4j_cypher     | "Run this Cypher: MATCH (n) RETURN count(n)"        |

### Mythic MCP (BloodHound integration)

| Tool                          | Example Prompt                                          |
|-------------------------------|---------------------------------------------------------|
| import_to_bloodhound          | "Import this SharpHound zip into BloodHound"            |
| bloodhound_query              | "Query BloodHound for domain admins"                    |
| run_sharphound_and_import     | "Run SharpHound on agent 1 and import into BloodHound"  |
| run_sharphound                | "Run SharpHound on agent 1"                             |
| ad_recon                      | "Run AD recon on agent 1"                               |
| enum_domain_users             | "Enumerate domain users on agent 1"                     |
| run_kerberoast                | "Run Kerberoasting on agent 1"                          |
| execute_mimikatz              | "Dump credentials on agent 1"                           |

---

## Port Reference

| Port | Service              | Bound To    | Purpose                    |
|------|----------------------|-------------|----------------------------|
| 8880 | BloodHound CE        | 127.0.0.1   | Web UI                     |
| 7687 | Neo4j Bolt           | 127.0.0.1   | Graph database (Cypher)    |
| 7474 | Neo4j Browser        | 127.0.0.1   | Neo4j web console          |
| 5433 | PostgreSQL           | 127.0.0.1   | BloodHound backend DB      |
| 7443 | Mythic Nginx         | 0.0.0.0     | Mythic web UI + API        |
| 17443| Mythic Server        | 127.0.0.1   | Mythic backend             |
| 5672 | RabbitMQ             | 127.0.0.1   | Mythic message broker      |

---

## Troubleshooting

### BloodHound container won't start

Check logs:
```bash
docker logs bloodhound 2>&1 | tail -20
```

Common cause: port conflict. Check what's using port 8880:
```bash
lsof -i :8880
```

### Neo4j health check fails

If you previously ran neo4j:5, stale volumes may conflict:
```bash
cd ~/Project/scopstls/config/BloodHound
docker compose down -v
docker compose up -d
```

### BloodHound can't connect to Neo4j

Verify Neo4j is healthy:
```bash
docker ps | grep bloodhound-neo4j
curl -sk http://127.0.0.1:7474
```

### MCP tools not appearing in Hermes

1. Verify config: `grep -A10 "neo4j:" ~/.hermes/config.yaml`
2. Test connection: `hermes mcp test neo4j`
3. Restart Hermes

### SharpHound produces no output

- Ensure the agent is running on a domain-joined Windows machine
- Check agent has sufficient privileges (domain user minimum)
- Try without stealth mode: "Run SharpHound on agent 1 without stealth"

### BloodHound import fails

Check the upload job status:
```bash
TOKEN=$(curl -sk -X POST http://127.0.0.1:8880/api/v2/login \
  -H "Content-Type: application/json" \
  -d '{"login_method":"secret","username":"admin","secret":"YOUR_PASS"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['session_token'])")

curl -sk "http://127.0.0.1:8880/api/v2/file-upload" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

---

## Security Notes

- **Lab use only.** All services bound to `127.0.0.1` except Mythic nginx (0.0.0.0).
- Default credentials are used throughout — change for any non-lab deployment.
- Neo4j MCP is configured as **read-only** to prevent accidental data modification.
- BloodHound API credentials are stored in the Mythic MCP source (`~/Mythic/MCP/main.py`).
- SharpHound collection requires domain credentials — ensure you have authorization.
- For real engagements, use dedicated infrastructure with proper network segmentation.

---

## References

- BloodHound CE Docs: https://support.bloodhoundenterprise.io
- BloodHound GitHub: https://github.com/SpecterOps/bloodhound
- BloodHound API Reference: https://bloodhound.specterops.io/resources/api-reference
- Neo4j Cypher Cheat Sheet: https://neo4j.com/docs/cypher-cheat-sheet/
- Mythic Docs: https://docs.mythic-c2.net
- Mythic MCP: `~/Mythic/MCP/README.md`
- SharpHound: https://github.com/BloodHoundAD/SharpHound
