# OmniAudit — Oracle Cloud (OCI) Deployment Guide

## Quick Start

```bash
chmod +x deploy.sh
# Edit the 4 variables at the top of deploy.sh, then:
./deploy.sh
```

---

## Architecture on OCI

```
Internet
  │
  ▼
OCI Load Balancer (HTTPS :443)
  │
  ▼
OCI Container Instance  ←──────────────────────────────┐
  [omniaudit API :8080]                                 │
  │                                                     │
  ├── GET  /health          (LB health probe)           │
  ├── GET  /payment-info                                │
  ├── POST /audit           ($0.25 USDC)                │
  ├── POST /audit/deep      ($1.00 USDC)                │
  ├── GET  /audit/{id}                                  │
  └── POST /patrol/trigger  ← OCI Scheduler (hourly) ──┘
        │
        ▼
  OCI PostgreSQL Service   (private endpoint, VCN-only)
```

---

## Required Environment Variables

| Variable | Where to set | Description |
|---|---|---|
| `WALLET_ADDRESS` | OCI Vault | Your USDC wallet address on Base |
| `SOVEREIGN_KEY_HEX` | OCI Vault | Ed25519 private key (64 hex chars) |
| `ADMIN_TOKEN` | OCI Vault | Secret token for admin bypass |
| `ANTHROPIC_API_KEY` | OCI Vault | Anthropic API key (sk-ant-...) |
| `DATABASE_URL` | OCI Vault | `postgresql+asyncpg://user:pass@host:5432/omniaudit` |
| `DB_SSL` | Plaintext | `require` for OCI Autonomous DB; `disable` for private VCN |
| `PYTHONPATH` | Plaintext | `/app/src` |
| `PORT` | Plaintext | `8080` |
| `WORKERS` | Plaintext | `1` (increase for larger shapes) |
| `FACILITATOR_URL` | Plaintext | `https://x402.coinbase.com/facilitate` |

---

## Step-by-Step Deployment

### 1. OCI Container Registry (OCIR)

1. OCI Console → **Developer Services → Container Registry**
2. Create a repository: `omniaudit` (set visibility to Private)
3. Create an Auth Token: **Identity → Users → Your User → Auth Tokens**
4. Run `deploy.sh` to build & push the image

### 2. OCI Vault (Secrets)

1. OCI Console → **Identity & Security → Vault**
2. Create a Vault + Master Encryption Key
3. Add these secrets: `WALLET_ADDRESS`, `SOVEREIGN_KEY_HEX`, `ADMIN_TOKEN`, `ANTHROPIC_API_KEY`, `DATABASE_URL`
4. Note each secret's OCID for step 3

### 3. OCI Container Instance (API)

1. OCI Console → **Developer Services → Container Instances → Create**
2. Shape: `CI.Standard.E4.Flex` | 1 OCPU | 2 GB RAM
3. Image: `<region>.ocir.io/<namespace>/omniaudit:latest`
4. Port: `8080`
5. Environment variables:
   - Add plaintext vars (PORT, PYTHONPATH, WORKERS, etc.)
   - Add vault secrets by OCID (for sensitive vars)
6. VCN/Subnet: choose a subnet with NAT gateway (needs outbound internet for OSV + Coinbase facilitator)

### 4. OCI PostgreSQL Service

1. OCI Console → **Databases → PostgreSQL → Create DB System**
2. Shape: `PostgreSQL.VM.Standard.E4.Flex.2.32GB` (or smaller for dev)
3. Set initial database name: `omniaudit`
4. Enable Private Endpoint (VCN-only access recommended)
5. Set `DB_SSL=require` and use the TLS connection string in `DATABASE_URL`
6. The app auto-creates the `audits` table on first start

### 5. OCI Load Balancer

1. OCI Console → **Networking → Load Balancers → Create**
2. Add Backend Set pointing to Container Instance port 8080
3. Health Check: `GET /health` → expects HTTP 200
4. Add HTTPS listener (port 443) with your certificate

### 6. OCI Scheduler (Patrol Cron)

1. OCI Console → **Developer Services → Scheduler → Create Schedule**
2. Schedule Type: CRON | Expression: `0 * * * *` | Timezone: UTC
3. Action Type: HTTP
4. URL: `https://<your-load-balancer-hostname>/patrol/trigger`
5. Method: POST
6. Headers: `X-Admin-Token: <your-admin-token>`

---

## Generating a Sovereign Key

```python
from cryptography.hazmat.primitives.asymmetric import ed25519
key = ed25519.Ed25519PrivateKey.generate()
raw = key.private_bytes_raw()
print(raw.hex())  # paste this as SOVEREIGN_KEY_HEX
```

---

## OCI Free Tier Notes

OCI Always Free includes:
- **2x** Ampere A1 Compute instances (4 OCPUs, 24 GB RAM total) — use instead of Container Instances
- **Autonomous Database** (20 GB) — supports PostgreSQL wire protocol
- **Container Registry** storage (500 GB)

To use Always Free: replace Container Instance with a Compute VM running Docker, and use Autonomous DB for PostgreSQL.
