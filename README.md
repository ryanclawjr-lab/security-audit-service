# Hawkeye Security Audit API

x402-powered security scanning service for AI agents.

## Services Offered

| Endpoint | Price | Description |
|----------|-------|-------------|
| `POST /api/scan/repo` | $0.05 | Full repository security scan |
| `POST /api/scan/package` | $0.02 | Dependency vulnerability scan |
| `POST /api/scan/secrets` | $0.01 | Exposed secrets detection |
| `POST /api/audit/skill` | $0.03 | OpenClaw skill security audit |
| `GET /api/cve/check` | $0.015 | CVE lookup by package |

## Deploy to Railway

**CLI:**
```bash
cd security-audit-service
npm install
railway login
railway init
railway variables set PAY_TO="0x71f08aEfe062d28c7AD37344dC0D64e0adF8941E"
railway up
```

**GitHub:**
1. Push to GitHub
2. Connect at https://railway.app → Deploy from GitHub
3. Add `PAY_TO=0x71f08aEfe062d28c7AD37344dC0D64e0adF8941E`

## Usage Example

```bash
# Scan a repo
curl -X POST https://your-service.railway.app/api/scan/repo \
  -H "Content-Type: application/json" \
  -d '{"repoUrl": "https://github.com/user/repo"}'

# Check for secrets
curl -X POST https://your-service.railway.app/api/scan/secrets \
  -H "Content-Type: application/json" \
  -d '{"code": "const API_KEY = \"sk_live_123...\" // your code"}'
```

## Announce

```bash
npx awal@latest x402 bazaar announce https://your-service.railway.app/health
```
