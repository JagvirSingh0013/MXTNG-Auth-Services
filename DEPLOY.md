# Deploying MXTNG Auth Service on EC2 (subdomain)

A step-by-step runbook to run the service independently at `https://auth.mxtng.com`
(substitute your own subdomain), fronted by nginx + HTTPS, so the ATS frontend and
backend federate to it (ADR-0005).

```
app.mxtng.com (frontend) ─┐
                          ├─►  https://auth.mxtng.com   ← this service (EC2)
api.mxtng.com (backend)  ─┘        Postgres + stable RS256 key
                                   publishes /.well-known/jwks.json
```

Prerequisites: an AWS account, a registered domain you control DNS for, and an SSH
key pair.

---

## Step 1 — Launch an EC2 instance
- Ubuntu 22.04 LTS, t3.small or larger.
- Allocate an **Elastic IP** and associate it (so the IP survives restarts).
- **Security group** inbound rules:
  - 22 (SSH) — your IP only
  - 80 (HTTP) — 0.0.0.0/0
  - 443 (HTTPS) — 0.0.0.0/0
  - **Do NOT open 8100** — the app stays private behind nginx.

## Step 2 — Point the subdomain at it
In your DNS provider, add an **A record**:
```
auth.mxtng.com   A   <your Elastic IP>
```
Verify: `dig +short auth.mxtng.com` returns your IP.

## Step 3 — SSH in and install Docker
```bash
ssh ubuntu@auth.mxtng.com
sudo apt update && sudo apt -y upgrade
sudo apt -y install docker.io git nginx
sudo systemctl enable --now docker
sudo usermod -aG docker ubuntu    # log out/in so `docker` works without sudo
```

## Step 4 — Provision Postgres
Either an **RDS Postgres** instance (recommended), or a container on the box:
```bash
docker run -d --name auth-db --restart unless-stopped \
  -e POSTGRES_USER=auth_user -e POSTGRES_PASSWORD=strongpass -e POSTGRES_DB=mxtng_auth \
  -v auth_pgdata:/var/lib/postgresql/data -p 127.0.0.1:5432:5432 postgres:16
```
Your `DATABASE_URL` will be:
```
postgresql+asyncpg://auth_user:strongpass@<db-host>:5432/mxtng_auth
# on-box container: <db-host> = 172.17.0.1 (docker bridge) or use --network
```

## Step 5 — Get the code
```bash
sudo mkdir -p /opt/mxtng-auth && sudo chown ubuntu:ubuntu /opt/mxtng-auth
git clone https://github.com/JagvirSingh0013/MXTNG-Auth-Services.git /opt/mxtng-auth
cd /opt/mxtng-auth
```

## Step 6 — Generate a STABLE signing key
Do this ONCE. A per-restart key would rotate the JWKS and break every issued token.
```bash
openssl genrsa -out /opt/mxtng-auth/signing_key.pem 2048
chmod 600 /opt/mxtng-auth/signing_key.pem
```
For real production, store this in a secret manager and inject it as `PRIVATE_KEY_PEM`
instead of a file on disk.

## Step 7 — Write the production `.env`
`/opt/mxtng-auth/.env`:
```ini
ENVIRONMENT=production
ISSUER=https://auth.mxtng.com                 # MUST equal the public URL (token `iss`)
DEFAULT_AUDIENCE=ats
ALLOWED_AUDIENCES=["ats","vms"]
DATABASE_URL=postgresql+asyncpg://auth_user:strongpass@<db-host>:5432/mxtng_auth
PRIVATE_KEY_PATH=/app/signing_key.pem         # mounted in Step 8
CORS_ORIGINS=["https://app.mxtng.com"]        # your frontend origin(s)
REFRESH_COOKIE_SECURE=true
REFRESH_COOKIE_DOMAIN=.mxtng.com              # cookie works across *.mxtng.com
WEBHOOK_SECRET=<openssl rand -hex 32>
ADMIN_API_KEY=<openssl rand -hex 32>
# Optional Google login:
# GOOGLE_CLIENT_ID=...
# GOOGLE_CLIENT_SECRET=...
# GOOGLE_REDIRECT_URI=https://auth.mxtng.com/v1/google/callback
# GOOGLE_POST_LOGIN_REDIRECT=https://app.mxtng.com/login/google/callback
```
`ENVIRONMENT=production` deliberately skips the dev `create_all`; the schema is owned
by Alembic (Step 10).

## Step 8 — Build and run the container
```bash
cd /opt/mxtng-auth
docker build -t mxtng-auth .
docker run -d --name mxtng-auth --restart unless-stopped \
  --env-file .env \
  -v /opt/mxtng-auth/signing_key.pem:/app/signing_key.pem:ro \
  -p 127.0.0.1:8100:8100 \
  mxtng-auth
```
Binding to `127.0.0.1` keeps it off the public internet — nginx will proxy to it.

## Step 9 — Smoke-test locally on the box
```bash
curl -s http://127.0.0.1:8100/health              # {"status":"ok"}
curl -s http://127.0.0.1:8100/.well-known/jwks.json
```

## Step 10 — Run migrations
```bash
docker exec mxtng-auth alembic upgrade head
```

## Step 11 — nginx reverse proxy
`/etc/nginx/sites-available/auth.mxtng.com`:
```nginx
server {
    listen 80;
    server_name auth.mxtng.com;
    location / {
        proxy_pass http://127.0.0.1:8100;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```
```bash
sudo ln -s /etc/nginx/sites-available/auth.mxtng.com /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

## Step 12 — HTTPS with Let's Encrypt
```bash
sudo apt -y install certbot python3-certbot-nginx
sudo certbot --nginx -d auth.mxtng.com     # obtains cert, rewrites nginx to 443, auto-renews
```
Verify from your laptop:
```bash
curl https://auth.mxtng.com/health
curl https://auth.mxtng.com/.well-known/jwks.json
```

## Step 13 — Wire the frontend and backend
ATS **backend** `.env` (redeploy after):
```ini
AUTH_ISSUER=https://auth.mxtng.com
AUTH_JWKS_URL=https://auth.mxtng.com/.well-known/jwks.json
AUTH_AUDIENCE=ats
```
ATS **frontend** `.env` (rebuild after):
```ini
NEXT_PUBLIC_AUTH_BASE_URL=https://auth.mxtng.com
```
`ISSUER` (service) and `AUTH_ISSUER` (backend) must match byte-for-byte.

## Step 14 — End-to-end verification
```bash
# 1) create a credential
curl -X POST https://auth.mxtng.com/v1/credentials \
  -H 'content-type: application/json' -H 'Idempotency-Key: test-1' \
  -d '{"email":"you@company.com","password":"correcthorse"}'

# 2) log in -> access token
TOKEN=$(curl -s -X POST https://auth.mxtng.com/v1/login \
  -H 'content-type: application/json' \
  -d '{"email":"you@company.com","password":"correcthorse"}' | jq -r .access_token)

# 3) call the backend with it -> JIT-provisioned user, not 401
curl https://api.mxtng.com/api/v1/users/me -H "Authorization: Bearer $TOKEN"
```

---

## Operations

```bash
docker logs -f mxtng-auth                 # tail logs
docker restart mxtng-auth                 # restart

# Deploy a new version:
cd /opt/mxtng-auth && git pull
docker build -t mxtng-auth .
docker rm -f mxtng-auth
docker run -d --name mxtng-auth --restart unless-stopped --env-file .env \
  -v /opt/mxtng-auth/signing_key.pem:/app/signing_key.pem:ro -p 127.0.0.1:8100:8100 mxtng-auth
docker exec mxtng-auth alembic upgrade head
```

## Security checklist
- [ ] 8100 is NOT in the security group (private behind nginx).
- [ ] `signing_key.pem` is `chmod 600`, backed up, and identical across any future instances.
- [ ] `ADMIN_API_KEY` and `WEBHOOK_SECRET` are random 32-byte hex, not defaults.
- [ ] `REFRESH_COOKIE_SECURE=true` and HTTPS enforced.
- [ ] `CORS_ORIGINS` lists only your real frontend origin(s).
- [ ] DB is not publicly reachable; strong password / RDS security group.
- [ ] certbot auto-renew is active (`systemctl status certbot.timer`).

## Scaling to multiple instances
Put an ALB in front of several EC2 instances. Every instance MUST load the **same**
`PRIVATE_KEY_PEM` (so JWKS is identical) and point at the same Postgres. Run
`alembic upgrade head` once per deploy, not per instance.
