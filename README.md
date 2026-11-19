# TraefikShaper (forwardAuth edition)

> **Based on [l4rm4nd/TraefikShaper](https://github.com/l4rm4nd/TraefikShaper)** by l4rm4nd,
> which came up with the idea of knock-and-approve IP allowlisting for Traefik through
> Apprise notifications. All credit for the concept goes to the original project. This
> version is a security-hardened rework of it.

### What's improved over the original

| Area | Original | This version |
|---|---|---|
| **Traefik integration** | Writes a dynamic config file loaded by Traefik's file provider. That file can define *any* router, so whoever controls the container controls your edge routing. | Uses a [`forwardAuth`](https://doc.traefik.io/traefik/middlewares/http/forwardauth/) middleware. The container writes no Traefik config and mounts nothing. |
| **IPv6** | Approved IPv6 addresses got `/32`, which allows a whole provider network | Exact-address matching for IPv4 and IPv6 |
| **Approve link** | A plain GET, so chat link previews could approve requests | GET shows a confirm page; only a POST button click approves |
| **Revoking** | Not possible | The same link shows a **Revoke access** button until the approval expires |
| **Link tampering** | Expiry could be edited in the URL; tokens never expired; non-constant-time comparison | Expiry fixed server-side; tokens are 256-bit random, single-use, expire after `PENDING_TTL`, and compared in constant time |
| **Client IP** | Took the left-most `X-Forwarded-For` entry (client-controlled) without validation; unencoded in the approval link | Picks the IP the same way Traefik's ipStrategy does, validates it, URL-encodes links |
| **Proxy/gateway bypass** | Docs suggested allowing private ranges, which can let every IPv6 or proxied visitor through | Knocks from non-public IPs are refused; broad private ranges are discouraged |
| **Flooding** | Per-IP limit only (with IPv6, unlimited addresses); memory grew without bound | Rate limit per IP / IPv6 /64, a global hourly notification cap, and periodic cleanup |
| **Race conditions** | Unlocked read-modify-write of the config file could put expired IPs back | In-memory state under a lock, no file |
| **Server's own IP** | Not available | Optional (`ALLOW_SERVER_IP`), with fallback IP services that must agree with each other |
| **Runtime** | Stale Python base, Flask development server, published port 5000 in the example | `python:3.13-slim`, pinned packages, waitress, non-root, read-only filesystem, healthcheck, internal port only |

---

Knock-to-access IP allowlisting for services behind [Traefik](https://traefik.io/).

A visitor opens a secret "knock" URL. The admin gets a notification (Telegram or any
other [Apprise](https://github.com/caronc/apprise) target) with an approval link. Once
the admin approves, the visitor's IP may reach the protected services for a limited time.

Traefik asks TraefikShaper about every request to a protected router through a
`forwardAuth` middleware. Because TraefikShaper never writes Traefik configuration, a
compromise of this container cannot change Traefik routing.

---

## How it works

```
                 ┌──────────── every request to a protected router ────────────┐
                 │                                                             ▼
Visitor ──► Traefik ──forwardAuth──► TraefikShaper /auth ──► 200 allowed / 403 denied
                 │
                 └── /UNIQUEURL (knock) ──► TraefikShaper ──► Apprise ──► Admin
                                                                            │
Admin opens approval link ──► confirm page ──► [Approve] (POST) ──► IP allowed
Admin opens same link again ──► [Revoke access] (POST) ──► IP removed
```

An IP is allowed if it is:

1. `127.0.0.1`, or in `WHITELISTED_IPS` (or in the private ranges if
   `DEFAULT_PRIVATE_CLASS_SOURCE_RANGE=True`),
2. the server's own public IP (if `ALLOW_SERVER_IP=True`), or
3. approved and not yet expired.

All state is in memory. **Restarting the container clears all approvals** and
invalidates all approval links that were already sent.

### Approval flow

1. The visitor opens `https://DOMAIN/UNIQUEURL` and sees a validation code (e.g. `amber-falcon`).
2. The admin receives a message with the visitor's IP, the same code and an approval link.
3. Opening the link shows a **confirm page**. Nothing is approved until the admin clicks
   **Approve**, so link previews in chat apps can't approve anyone.
4. After approving, the page shows a **Revoke access** button. The same link keeps working
   until the approval expires, and opening it again shows the revoke button.
5. When the approval expires or is revoked, the admin is notified and the link stops working.

---

## Files

| File | Purpose |
|---|---|
| `update_whitelist.py` | The application (Flask, served by waitress) |
| `Dockerfile`, `requirements.txt`, `.dockerignore` | Builds the image (`python:3.13-slim`, pinned packages, non-root) |
| `docker-compose.yml` | Compose service definition, standalone or to merge into your stack |
| `traefik-forwardauth.yml` | Traefik dynamic config defining the `dynamic-ipwhitelist` middleware (file provider setup only; with Docker labels it isn't needed) |
| `.github/workflows/docker-publish.yml` | Builds the image and publishes it to GitHub Container Registry |
| `.github/dependabot.yml` | Automatic update PRs for Actions, the base image and pip packages |

---

## Setup

### 1. Image

**Prebuilt (recommended):** multi-arch images (`linux/amd64`, `linux/arm64`) are published
to GitHub Container Registry:

```
ghcr.io/kkawkk/traefikshaper:latest
```

| Tag | Meaning |
|---|---|
| `latest` | Current `main` branch, rebuilt weekly with the newest base image |
| `1.2.3`, `1.2`, `1` | Released versions (from git tags `v1.2.3`) |
| `sha-abc1234` | A specific commit |

**Build it yourself:** clone this repository and in `docker-compose.yml` replace the
`image:` line with `build: .`.

### 2. Compose service

Use `docker-compose.yml` from this repository, or merge its `traefikshaper` service into
your existing compose file. Fill in `APPURL`, `GRANT_HTTP_ENDPOINT` and
`APPRISE_NOTIFICATION_URL`.

- TraefikShaper must be on the **same Docker network as Traefik**, so that `traefikshaper:5000` resolves.
- Use `expose:` only. **Never publish port 5000** with `ports:`.

Optional: make Traefik wait for TraefikShaper when the whole stack starts:

```yaml
  traefik:
    depends_on:
      traefikshaper:
        condition: service_healthy
```

### 3. Traefik configuration

Traefik needs two things:

- the **`dynamic-ipwhitelist` middleware**, which points to `http://traefikshaper:5000/auth`
- a **router for TraefikShaper itself**, so visitors can knock and you can approve

Choose **one** of the two ways below. Both work the same way.

The rules are the same either way:

- **Protected services** reference the middleware.
- **TraefikShaper's own router** must **not** use the middleware, otherwise nobody could
  knock. It should route only the knock path and `/approve`, never `/auth`.
- **Adjust to your setup:** replace `DOMAIN` and `UNIQUEURL`, and the entrypoint name
  (`websecure`) and certificate resolver (`letsencrypt`), with what your Traefik uses.

#### Option A: Docker labels (Docker provider)

Requires Traefik's Docker provider (`--providers.docker=true`). Add labels to the
`traefikshaper` service in your compose file:

```yaml
services:
  traefikshaper:
    # ... everything from docker-compose.yml ...
    labels:
      - traefik.enable=true
      # Middleware used by protected services
      - traefik.http.middlewares.dynamic-ipwhitelist.forwardauth.address=http://traefikshaper:5000/auth
      - traefik.http.middlewares.dynamic-ipwhitelist.forwardauth.trustForwardHeader=false
      # TraefikShaper's own router: knock path and /approve only, no middleware
      - traefik.http.routers.traefikshaper.rule=Host(`DOMAIN`) && (Path(`/UNIQUEURL`) || Path(`/approve`))
      - traefik.http.routers.traefikshaper.entrypoints=websecure
      - traefik.http.routers.traefikshaper.tls.certresolver=letsencrypt
      - traefik.http.services.traefikshaper.loadbalancer.server.port=5000
      # Only needed if the container is attached to more than one network:
      # - traefik.docker.network=proxy
```

Protected services reference the middleware in their labels:

```yaml
services:
  myapp:
    image: myapp
    labels:
      - traefik.enable=true
      - traefik.http.routers.myapp.rule=Host(`app.example.com`)
      - traefik.http.routers.myapp.entrypoints=websecure
      - traefik.http.routers.myapp.tls.certresolver=letsencrypt
      - traefik.http.routers.myapp.middlewares=dynamic-ipwhitelist@docker
```

Notes:

- Use the **`@docker`** suffix when the middleware is defined with labels. Inside the same
  provider the suffix is optional, but routers defined in files must use
  `dynamic-ipwhitelist@docker`.
- If the router already has other middlewares, separate them with commas:
  `middlewares=dynamic-ipwhitelist@docker,other@docker`.
- The labels live on the TraefikShaper container. If that container is stopped or removed,
  Traefik drops the middleware and the routers that use it stop working (fail closed).
- Labels are set by Docker Compose, not by the container, so a compromised container can't
  change them.

#### Option B: File provider (dynamic configuration files)

Requires Traefik's file provider (e.g. `--providers.file.directory=/etc/traefik/dynamic`).

**Middleware:** copy `traefik-forwardauth.yml` into the dynamic configuration directory.
If you are migrating from the original TraefikShaper, overwrite the old
`dynamic-whitelist.yml` with it. The middleware keeps the name `dynamic-ipwhitelist`, so
existing routers need no changes.

```yaml
http:
  middlewares:
    dynamic-ipwhitelist:
      forwardAuth:
        address: "http://traefikshaper:5000/auth"
        trustForwardHeader: false
```

This file belongs to Traefik only. Do **not** mount it into the TraefikShaper container.

**TraefikShaper router**, e.g. in `traefikshaper-router.yml` in the same directory:

```yaml
http:
  routers:
    traefikshaper:
      rule: "Host(`DOMAIN`) && (Path(`/UNIQUEURL`) || Path(`/approve`))"
      entryPoints: [websecure]
      tls:
        certResolver: letsencrypt
      service: traefikshaper
  services:
    traefikshaper:
      loadBalancer:
        servers:
          - url: "http://traefikshaper:5000"
```

**Protected services:**

```yaml
http:
  routers:
    myapp:
      rule: "Host(`app.example.com`)"
      entryPoints: [websecure]
      tls:
        certResolver: letsencrypt
      middlewares: [dynamic-ipwhitelist]
      service: myapp
```

Use the **`@file`** suffix (`dynamic-ipwhitelist@file`) to reference this middleware from
Docker labels.

#### Mixing both

Providers can be combined. For example, define the middleware in a file and use it from
labels:

```yaml
- traefik.http.routers.myapp.middlewares=dynamic-ipwhitelist@file
```

Define the middleware in **only one** place. Two definitions with the same name in
different providers are separate middlewares, which is confusing.

### 4. Start

```sh
docker compose up -d traefikshaper
```

Test it by knocking from a phone on mobile data (WiFi off). The notification should show
the phone's real public IP.

### Updating

Update regularly to pick up Python and package security fixes. The published `latest`
image is rebuilt every week.

```sh
# prebuilt image
docker compose pull traefikshaper && docker compose up -d traefikshaper

# self-built
docker compose build --pull traefikshaper && docker compose up -d traefikshaper
```

Updating restarts the container, which clears all current approvals.

---

## Building and publishing (for maintainers)

The workflow in `.github/workflows/docker-publish.yml` builds the image with GitHub
Actions and pushes it to `ghcr.io/<owner>/<repo>`.

| Trigger | Result |
|---|---|
| Push to `main` | `latest` and `sha-…` |
| Git tag `v1.2.3` | `1.2.3`, `1.2`, `1` and `sha-…`, plus a GitHub Release with generated notes |
| Every Monday 04:00 UTC | Rebuild of `main` with the newest base image, re-pushes `latest` |
| Pull request | Build only (nothing is pushed) |
| Manual (Actions tab, *Run workflow*) | Same as for the selected branch |

Images include an SBOM and signed build provenance. Verify them with:

```sh
gh attestation verify oci://ghcr.io/kkawkk/traefikshaper:latest --owner kkawkk
```

**First-time setup:**

1. No secrets are needed. The workflow uses the built-in `GITHUB_TOKEN`.
2. After the first successful run, open your GitHub profile → **Packages** →
   `traefikshaper` → **Package settings** and set visibility to **Public**. New GHCR
   packages are private by default.
3. In the same settings, check that the package is linked to the repository. It's linked
   automatically through the image's `org.opencontainers.image.source` label.
4. If you fork this repository, replace `kkawkk` in `docker-compose.yml` and this README
   with your own GitHub user or organization name, in lowercase.

To release a version (the tag must have three parts, `v1.0` is ignored):

```sh
git tag v1.0.0 && git push origin v1.0.0
```

---

## Configuration

All settings are environment variables. Boolean values accept `true`, `1` or `yes`
(any case).

### Basics

| Variable | Default | Description |
|---|---|---|
| `APPURL` | `http://localhost:5000` | Public base URL of TraefikShaper, used in approval links |
| `GRANT_HTTP_ENDPOINT` | `/knock-knock` | Secret knock path. Use something hard to guess. |
| `APPRISE_NOTIFICATION_URL` | *(unset)* | Apprise URL, e.g. `tgram://BOTTOKEN/CHATID`. If unset or failing, the approval link is written to the container log. |
| `EXPIRATION_TIME` | `300` | How long an approval lasts, in seconds |

### Allowed addresses

| Variable | Default | Description |
|---|---|---|
| `WHITELISTED_IPS` | *(none)* | Comma-separated IPs or CIDRs that are always allowed. Invalid entries are ignored and logged. |
| `DEFAULT_PRIVATE_CLASS_SOURCE_RANGE` | `False` | `True` always allows `10.0.0.0/8`, `172.16.0.0/12` and `192.168.0.0/16`. **Not recommended** (see Security notes). |
| `ALLOW_SERVER_IP` | `False` | Always allow the server's own public IP (useful with a dynamic IP, e.g. when accessing from the same LAN through the public domain) |
| `SERVER_IP_CHECK_URLS` | ipify, icanhazip, checkip.amazonaws.com, ipinfo.io | Comma-separated "what is my IP" services that return a plain-text IP, tried in order |
| `SERVER_IP_MIN_AGREE` | `2` | How many services must return the same IP before it is trusted. `1` accepts the first answer. |
| `SERVER_IP_CHECK_INTERVAL` | `60` | Seconds between server IP checks |
| `ALLOW_PRIVATE_APPROVALS` | `False` | Allow knocks from non-public IPs (private, loopback, link-local, CGNAT). Only enable if clients really arrive from such addresses (LAN/VPN). |

### Client IP detection

| Variable | Default | Description |
|---|---|---|
| `IPSTRATEGY_DEPTH` | `0` | `0`: the client is the address Traefik received the connection from. `N`: take the N-th entry from the right of the `X-Forwarded-For` header Traefik received (e.g. `1` behind Cloudflare). |
| `EXCLUDED_IPS` | *(none)* | Alternative to depth: the client is the right-most `X-Forwarded-For` entry not in these ranges |

If Traefik runs behind another proxy (Cloudflare, a load balancer, …):

1. On the Traefik entrypoint, set `forwardedHeaders.trustedIPs` to that proxy's addresses.
2. On the middleware, set `trustForwardHeader: true` (in `traefik-forwardauth.yml`, or the
   `...forwardauth.trustForwardHeader=true` label).
3. In TraefikShaper, set `IPSTRATEGY_DEPTH=1` (or `EXCLUDED_IPS`).

With the defaults (`trustForwardHeader: false`, depth `0`), forged `X-Forwarded-For`
headers from clients are ignored.

### Abuse limits

| Variable | Default | Description |
|---|---|---|
| `REQUEST_COOLDOWN` | `300` | Seconds before the same IP (IPv6: the same /64) can knock again |
| `MAX_NOTIFICATIONS_PER_HOUR` | `20` | Global cap on approval notifications. When reached, knocks get HTTP 429. |
| `PENDING_TTL` | `900` | Seconds an approval link stays valid before it is approved |

### GeoIP (optional)

Adds the visitor's country and network (ASN) to notifications and the approve/revoke
pages, e.g. `Access request from 8.8.8.8 (code: amber-falcon)` followed by
`🇺🇸 United States (US), AS15169 Google LLC`. Lookups are done locally; visitor IPs are never
sent anywhere.

**Automatic (recommended):** set `GEOIP_DOWNLOAD=True`. On startup TraefikShaper downloads
the free [DB-IP Lite](https://db-ip.com/db/lite.php) country and ASN databases (no account
needed, ~20 MB together) from `download.db-ip.com`, and checks once a day whether the next
monthly release is out. It keeps using the old file until the new one has been downloaded and
checked, so a failed download never removes GeoIP information. By default the files go to
`/tmp/geoip` (the container's tmpfs), so they're downloaded again after every restart.
To keep them, mount a volume writable by UID 1000 at `GEOIP_DIR`.

**Your own files:** set `GEOIP_COUNTRY_DB` and/or `GEOIP_ASN_DB` to `.mmdb` files you mount
(DB-IP Lite or MaxMind GeoLite2). A set path is used as-is and never downloaded to. Mount the
**directory** read-only (e.g. `./geoip:/geoip:ro`) rather than single files, and replace the
files by renaming the new one over the old one. TraefikShaper notices within ~10 seconds and
reloads without a restart.

| Variable | Default | Description |
|---|---|---|
| `GEOIP_DOWNLOAD` | `False` | `True` downloads and refreshes DB-IP Lite country + ASN databases (for any of the two paths below that is unset) |
| `GEOIP_DIR` | `/tmp/geoip` | Where downloaded databases are stored |
| `GEOIP_REFRESH_INTERVAL` | `86400` | Seconds between update checks (minimum 3600). Failed or not-yet-published updates are retried hourly. |
| `GEOIP_COUNTRY_DB` | *(unset)* | Path to your own country `.mmdb` (DB-IP or GeoLite2; City databases work too) |
| `GEOIP_ASN_DB` | *(unset)* | Path to your own ASN `.mmdb` (DB-IP or GeoLite2-ASN) |

A missing or unreadable database only logs a warning. Notifications are then sent without
that information.

#### Data licence and attribution

The DB-IP Lite databases are © [DB-IP.com](https://db-ip.com), licensed under
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). DB-IP asks web applications that
display results from the database to link back to DB-IP.com. TraefikShaper does this
automatically: when the approve/revoke page shows GeoIP information, it adds an
"IP Geolocation by DB-IP" link at the bottom. If you use your own MaxMind GeoLite2 files,
the page shows MaxMind's required notice instead. This repository doesn't contain or
redistribute any database. If you pass the data on in another form (e.g. share the downloaded
files or publish lookup results), the attribution requirement applies to you as well.

### Server

| Variable | Default | Description |
|---|---|---|
| `PORT` | `5000` | Listening port inside the container |
| `SERVER_THREADS` | `8` | waitress worker threads |

The app must run as a **single process** because all state is in memory. Don't put it
behind a multi-worker server.

---

## HTTP endpoints

| Path | Method | Reachable from | Purpose |
|---|---|---|---|
| `/auth` | any | Traefik only | forwardAuth check: `200` allowed, `403` denied |
| `GRANT_HTTP_ENDPOINT` | GET | public | Knock: request access for the caller's IP |
| `/approve` | GET | public | Confirm page (pending) or revoke page (approved). Never changes state. |
| `/approve` | POST | public | `action=approve` (default) or `action=revoke`. Requires the link's token. |
| `/healthz` | GET | container | Healthcheck |

---

## Security notes

- **No Traefik config access.** The container mounts nothing except timezone files (and,
  optionally, GeoIP databases). With `GEOIP_DOWNLOAD=True` it makes outbound requests to
  `download.db-ip.com` for the database files only. Downloads are size-capped and checked
  as valid DB-IP databases before they replace the current file. If it
  is compromised, an attacker can at most allow IPs through the `dynamic-ipwhitelist`
  middleware. They cannot add routers or expose other services.
- **Fails closed.** If TraefikShaper is down or restarting, Traefik answers `500` for
  protected routers. Nobody gets in, including whitelisted IPs and the server IP.
- **Exact-IP approvals.** Approvals match a single address, IPv4 or IPv6 (no `/32`
  applied to IPv6). IPv6 privacy addresses rotate, so IPv6 clients may need to knock again.
- **Non-public IPs can't be approved** (unless `ALLOW_PRIVATE_APPROVALS=True`). A private
  client IP usually means a proxy or Docker gateway is hiding the real client, and
  approving it would let in everyone behind it.
- **Avoid broad private ranges** in `WHITELISTED_IPS` or `DEFAULT_PRIVATE_CLASS_SOURCE_RANGE`.
  If any traffic reaches Traefik through a Docker gateway or proxy container (e.g. IPv6
  through Docker's userland proxy on an IPv4-only network, or a tunnel container), all of
  it would bypass the allowlist. Allow specific `/32` addresses instead.
- **Approval links**
  - are random 256-bit tokens, compared in constant time
  - only change state on a POST button click, so link previews can't approve or revoke
  - can approve only once and expire after `PENDING_TTL`
  - can revoke only the approval they created
  - always grant `EXPIRATION_TIME`; the expiry can't be changed through the URL
- **Server IP lookup** requires `SERVER_IP_MIN_AGREE` independent services to agree, so a
  single compromised service can't get an arbitrary IP allowed. If no services agree, the
  last known IP is kept.
- **Flood limits.** Rate limiting is per IP (IPv6: per /64), plus a global notification cap.
  A flood can use up the cap and block legitimate knocks for up to an hour. Already-allowed
  IPs are not affected.
- **Response headers.** `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, `noindex`
  and anti-framing headers keep tokens out of referrers and caches.

---

## Troubleshooting

**Traefik logs `Error calling http://traefikshaper:5000/auth ... connection refused` and protected sites return 500**
TraefikShaper isn't running or is still starting. The port opens about 0.3 s after the
process starts. Check `docker ps` and `docker logs traefikshaper`, and check that both
containers share a network.

**Knock returns "Access requests from this address are not allowed" and the log says `Refusing approval request from non-public IP 172.x.x.x`**
TraefikShaper isn't seeing the real client IP:

- If it's Traefik's own container IP, something is removing `X-Forwarded-For` between
  Traefik and the app.
- If it's another container or gateway, a proxy in front of Traefik hides the client. See
  *Client IP detection*.

**The server's own IP isn't allowed**
Check that `ALLOW_SERVER_IP=True` is set and that the log shows `Server public IP changed: None -> x.x.x.x`.
Requests from your LAN only match if they reach Traefik with the public IP as source (hairpin NAT).
If they arrive with a LAN address instead, add that address to `WHITELISTED_IPS`.

**Traefik logs `middleware "dynamic-ipwhitelist@..." does not exist` and the router returns 404**
The provider suffix doesn't match where the middleware is defined. Labels mean `@docker`,
files mean `@file`. With labels, also check that the TraefikShaper container is running and
has `traefik.enable=true`.

**No notification arrives**
The approval link is written to the container log (`docker logs traefikshaper`). Check
`APPRISE_NOTIFICATION_URL`.

**Approvals disappeared**
The container restarted. State is in memory only, so knock again.
