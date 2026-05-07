# UniFi External Captive Portal

External captive portal for UniFi Controller / UniFi OS Server using Docker, Nginx and Node.js.

Supports:
- UniFi External Portal Authentication
- Dynamic captive portal banner
- Branch-specific banner by AP MAC
- Branch-specific redirect URL
- Default fallback banner
- Docker deployment
- HTTPS with custom certificate

---

# Features

## Captive Portal Authentication

Authenticate UniFi guest clients using external portal flow.

Supports:
- UniFi Controller
- UniFi OS Server
- Multiple UniFi sites
- Shared external portal endpoint

---

## Branch-specific Banner

Portal can dynamically display different banners based on AP MAC address.

Example:

| AP MAC | Branch | Banner |
|---|---|---|
| 9c:05:d6:7c:00:e9 | D051 Thao Dien HCM | khaitruong.jpg |
| Any other AP | Default | bg.jpg |

---

# Architecture

```text
Client
   ↓
UniFi Guest Portal Redirect
   ↓
Nginx (portal-web)
   ↓
Node.js API (portal-api)
   ↓
UniFi API Authorize Client
```

---

# Project Structure

```text
.
├── api
│   ├── Dockerfile
│   ├── package.json
│   └── server.js
│
├── config
│   └── branch-map.json
│
├── html
│   ├── index.html
│   ├── bg.jpg
│   └── assets
│       └── branches
│           └── D051-ThaoDien-HCM
│               └── khaitruong.jpg
│
├── nginx
│   └── default.conf
│
├── certs
│
├── docker-compose.yml
└── .env
```

---

# Environment Variables

Create `.env`

```env
UNIFI_BASE=https://unifi-controller:11443
UNIFI_API_KEY=your_api_key
UNIFI_SITE=default
PORT=3000
AUTH_MINUTES=1440
```

---

# Branch Mapping

File:

```text
config/branch-map.json
```

Example:

```json
{
  "default": {
    "key": "default",
    "name": "Default",
    "bannerUrl": "/bg.jpg",
    "redirectUrl": "http://diag.vn/default",
    "minutes": 1440
  },
  "branches": [
    {
      "key": "D051-ThaoDien-HCM",
      "name": "D051 ThaoDien HCM",
      "apNames": ["D051-ThaoDien-HCM"],
      "apMacs": ["9c:05:d6:7c:00:e9"],
      "bannerUrl": "/assets/branches/D051-ThaoDien-HCM/khaitruong.jpg",
      "redirectUrl": "http://diag.vn/campaign",
      "minutes": 1440
    }
  ]
}
```

---

# Banner Matching Logic

Priority:

```text
1. Match AP MAC
2. Match AP Name
3. Fallback to default banner
```

Supports:
- Multiple UniFi sites
- Shared external portal endpoint
- Unique AP-based campaign targeting

---

# Deployment

## Build

```bash
docker compose build --no-cache
```

## Start

```bash
docker compose up -d
```

## Stop

```bash
docker compose down
```

---

# Verify API

## Test branch banner

```bash
curl -sS "http://127.0.0.1/api/portal-context?site=default&ap=9c:05:d6:7c:00:e9" | jq .
```

## Test default banner

```bash
curl -sS "http://127.0.0.1/api/portal-context?site=default&ap=11:22:33:44:55:66" | jq .
```

---

# Verify Banner Asset

```bash
curl -I "http://127.0.0.1/assets/branches/D051-ThaoDien-HCM/khaitruong.jpg"
```

---

# Logs

## View all logs

```bash
docker compose logs -f
```

## View portal-web logs

```bash
docker compose logs -f portal-web
```

## View portal-api logs

```bash
docker compose logs -f portal-api
```

---

# Production Rollback

Backup:

```bash
cp -r /root/mktwifi-portal /root/mktwifi-portal-backup-$(date +%F-%H%M)
```

Rollback:

```bash
docker compose down

rm -rf /root/mktwifi-portal

cp -r /root/mktwifi-portal-backup-YYYY-MM-DD-HHMM /root/mktwifi-portal

cd /root/mktwifi-portal

docker compose up -d
```

---

# Version

## v1.0.1

Features:
- Branch-specific captive portal banner
- AP MAC based matching
- Default fallback banner
- Multi-site support
- Dynamic redirect URL

---

# Notes

- AP MAC is the primary matching method.
- AP Name is fallback only.
- Multiple UniFi sites can share the same external portal.
- HTTPS certificates must exist in `certs/`.
- Banner assets are served directly by Nginx.

---
# Author
Việt Nguyễn
# License
Internal Use Only
DIAG VN IT
