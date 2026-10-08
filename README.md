# Pygenic Arc — AI Agent Security & Reliability MVP

Pygenic Arc is a runtime security layer for agentic AI. The MVP sits between an AI agent and its tools/data and makes a policy-driven decision before execution.

## Product flow
`Agent → Pygenic Arc → Normalize/Decode → Pattern & Policy Checks → Risk Score → ALLOW / REVIEW / BLOCK → Audit Evidence`

## Included capabilities
- Runtime action authorization
- Configurable transfer policy
- Prompt-injection detection
- SQL injection detection
- Command injection detection
- XSS detection
- Path traversal detection
- Suspicious URL detection
- API key / JWT / private-key / credential pattern detection
- Base64, URL and HTML-entity decoding before inspection
- Invisible Unicode / hidden-content detection
- Explainable risk score and decision
- Evidence hash for every decision
- PostgreSQL-ready audit storage
- One-click Attack Lab
- Web dashboard + Action Gate + Content Inspector + Policy Center + Audit Evidence

## Run locally
```bash
python -m venv .venv
.venv\\Scripts\\activate
pip install -r requirements.txt
uvicorn backend.main:app --reload --port 8000
```
Open `http://localhost:8000`.
Default local API key: `arc_demo_change_me` (change it before any real deployment).

## Docker

Create a local environment file and replace the example values with unique random values:

```bash
cp .env.example .env
docker compose up --build
```

The web app is available at `http://localhost:8000`. PostgreSQL data is stored in the `pgdata` volume.

## Deploy with Coolify

1. Create a Docker Compose application from this repository and select `docker-compose.yml` as the Compose file.
2. Coolify will generate the `SERVICE_USER_POSTGRES`, `SERVICE_PASSWORD_64_POSTGRES`, `SERVICE_BASE64_64_ARCAPIKEY`, and `SERVICE_REALBASE64_64_OTPPER` values referenced by the Compose file. Keep these values private.
3. Add a domain for the `api` service on internal port `8000`. The frontend and API are served by the same service; do not expose the `db` service publicly.
4. Deploy and verify the domain's `/api/health` endpoint returns `{"status":"ok"}`. The API health check also verifies its PostgreSQL connection.

The Compose definition includes persistent PostgreSQL storage and health checks for both services. Configure regular backups for the `pgdata` volume in Coolify or your hosting environment.

## Important production boundary
This is a strong working MVP/foundation, not a claim of complete enterprise security certification. Before internet exposure, add HTTPS/TLS termination, production secrets, SSO/RBAC, rate limiting/WAF, centralized logs, backups, monitoring, high availability, privacy controls, formal security testing and organization-specific policies.
