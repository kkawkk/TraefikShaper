"""
TraefikShaper (forwardAuth edition)

Traefik calls GET /auth (forwardAuth middleware) for every request to a
protected router. This app answers 200 if the client IP is allowed, 403
otherwise. Visitors request access via GRANT_HTTP_ENDPOINT; the admin
approves via a link sent through Apprise.

The app writes no Traefik configuration at all, so a compromise of this
container cannot change Traefik routing.
"""
import os
import time
import hmac
import secrets
import logging
import ipaddress
import threading
import zlib
from collections import deque
from urllib.parse import urlencode

import requests
import apprise
import maxminddb
from flask import Flask, request, render_template_string, redirect

app = Flask(__name__)
app.logger.setLevel(logging.INFO)   # Flask's default handler logs to stderr
app.logger.propagate = False        # avoid duplicate lines via the root logger

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

# How long an approved IP stays allowed (seconds)
EXPIRATION_TIME = int(os.getenv('EXPIRATION_TIME', 300))
# How long an approval link stays valid (seconds)
PENDING_TTL = int(os.getenv('PENDING_TTL', 900))
# Minimum time between two approval requests from the same IP (or IPv6 /64)
REQUEST_COOLDOWN = int(os.getenv('REQUEST_COOLDOWN', 300))
# Global cap on approval notifications per hour (anti-flood)
MAX_NOTIFICATIONS_PER_HOUR = int(os.getenv('MAX_NOTIFICATIONS_PER_HOUR', 20))

APPURL = os.getenv('APPURL', "http://localhost:5000").rstrip('/')
GRANT_HTTP_ENDPOINT = os.getenv('GRANT_HTTP_ENDPOINT', '/knock-knock')

# How to pick the client IP from X-Forwarded-For (same meaning as Traefik's
# ipStrategy). Depth > 0 or EXCLUDED_IPS require trustForwardHeader: true on
# the forwardAuth middleware and forwardedHeaders.trustedIPs on the entrypoint.
IPSTRATEGY_DEPTH = int(os.getenv('IPSTRATEGY_DEPTH', 0))
EXCLUDED_IPS = os.getenv('EXCLUDED_IPS', None)

# Always allow the server's own (dynamic) public IP
ALLOW_SERVER_IP = os.getenv('ALLOW_SERVER_IP', 'False').strip().lower() in ('true', '1', 'yes')
# Plain-text "what is my IP" services, tried in order
SERVER_IP_CHECK_URLS = [u.strip() for u in os.getenv(
    'SERVER_IP_CHECK_URLS',
    'https://api.ipify.org,https://ipv4.icanhazip.com,https://checkip.amazonaws.com,https://ipinfo.io/ip'
).split(',') if u.strip()]
# How many services must return the same IP before it is trusted. Guards against
# a single compromised/misbehaving service getting an arbitrary IP allowed.
SERVER_IP_MIN_AGREE = max(1, min(int(os.getenv('SERVER_IP_MIN_AGREE', 2)), len(SERVER_IP_CHECK_URLS) or 1))
SERVER_IP_CHECK_INTERVAL = int(os.getenv('SERVER_IP_CHECK_INTERVAL', 60))
SERVER_IP_CHECK_TIMEOUT = 5

# Refuse approval requests from non-public IPs (private, loopback, link-local,
# CGNAT...). Such an address usually means a proxy/Docker gateway is hiding the
# real client, and approving it would approve everyone behind it.
ALLOW_PRIVATE_APPROVALS = os.getenv('ALLOW_PRIVATE_APPROVALS', 'False').strip().lower() in ('true', '1', 'yes')

APPRISE_NOTIFICATION_URL = os.getenv('APPRISE_NOTIFICATION_URL', 'unset')

# Optional GeoIP lookup to show the visitor's country and ASN in notifications.
# GEOIP_DOWNLOAD=True downloads the free DB-IP Lite databases into GEOIP_DIR and
# keeps them current. GEOIP_COUNTRY_DB / GEOIP_ASN_DB point to your own .mmdb
# files instead (DB-IP or MaxMind GeoLite2); a set path is never downloaded to.
GEOIP_DOWNLOAD = os.getenv('GEOIP_DOWNLOAD', 'False').strip().lower() in ('true', '1', 'yes')
GEOIP_DIR = os.getenv('GEOIP_DIR', '/tmp/geoip')
GEOIP_REFRESH_INTERVAL = max(3600, int(os.getenv('GEOIP_REFRESH_INTERVAL', 86400)))
GEOIP_COUNTRY_DB = os.getenv('GEOIP_COUNTRY_DB', '').strip()
GEOIP_ASN_DB = os.getenv('GEOIP_ASN_DB', '').strip()
GEOIP_RETRY_INTERVAL = 3600
GEOIP_MAX_SIZE = 512 * 1024 * 1024   # decompressed; current Lite files are ~10 MB
DBIP_URL = 'https://download.db-ip.com/free/dbip-{kind}-lite-{month}.mmdb.gz'

LISTEN_PORT = int(os.getenv('PORT', 5000))
SERVER_THREADS = int(os.getenv('SERVER_THREADS', 8))

# --------------------------------------------------------------------------
# State (in memory only; cleared on restart)
# --------------------------------------------------------------------------

state_lock = threading.Lock()
approved = {}        # ip (canonical str) -> {'expiry', 'token'} (token allows revoking)
pending = {}         # ip -> {'token', 'created', 'code'}
last_request = {}    # rate-limit key -> timestamp
notify_times = deque()
server_ip = None     # canonical str or None
# Set once the first server IP check has finished (successfully or not)
server_ip_ready = threading.Event()
INITIAL_SERVER_IP_WAIT = 15  # max seconds a request waits for that first check

# --------------------------------------------------------------------------
# Notifications
# --------------------------------------------------------------------------

apobj = apprise.Apprise(asset=apprise.AppriseAsset(storage_mode=apprise.PersistentStoreMode.MEMORY))
if APPRISE_NOTIFICATION_URL != "unset":
    try:
        apobj.add(APPRISE_NOTIFICATION_URL)
    except Exception as e:
        app.logger.error(f"Failed to add Apprise notification url: {e}")


def send_notification(message):
    try:
        if APPRISE_NOTIFICATION_URL != "unset":
            return bool(apobj.notify(body=message))
        return False
    except Exception as e:
        app.logger.error(f"Failed to send notification: {e}")
        return False

# --------------------------------------------------------------------------
# GeoIP (optional)
# --------------------------------------------------------------------------


# (database_type prefix, text before link, link text, url). DB-IP's licence asks
# for a link back on pages showing results; MaxMind requires this notice.
ATTRIBUTIONS = (
    ('DBIP', '', 'IP Geolocation by DB-IP', 'https://db-ip.com/'),
    ('GeoLite2', 'This product includes GeoLite2 data created by MaxMind, available from ',
     'maxmind.com', 'https://www.maxmind.com'),
)


class MMDB:
    """
    A .mmdb file that is reopened when it changes on disk (e.g. a monthly
    update replacing the file). Missing files are retried.
    """

    def __init__(self, path, label, download_kind=None):
        self.path, self.label = path, label
        self.download_kind = download_kind   # 'country'/'asn' if we download it ourselves
        self.reader, self.attribution = None, None
        # False = missing file already reported; downloaded files appear later, don't warn
        self.mtime = False if download_kind else None
        self.lock = threading.Lock()
        self.reload_if_changed()

    def reload_if_changed(self):
        try:
            mtime = os.stat(self.path).st_mtime
        except OSError as e:
            if self.mtime is not False:   # log once until the file appears
                app.logger.warning(f"GeoIP {self.label} database {self.path} not available: {e}")
                self.mtime = False
            return
        if mtime == self.mtime:
            return
        try:
            reader = maxminddb.open_database(self.path)
        except Exception as e:
            app.logger.error(f"GeoIP {self.label} database {self.path} could not be opened: {e}")
            self.mtime = mtime   # don't retry until the file changes again
            return
        meta = reader.metadata()
        attribution = next((a[1:] for a in ATTRIBUTIONS if str(meta.database_type).startswith(a[0])), None)
        with self.lock:
            old, self.reader, self.mtime, self.attribution = self.reader, reader, mtime, attribution
        if old is not None:
            old.close()
        app.logger.info(f"GeoIP {self.label} database loaded: {self.path} "
                        f"({meta.database_type}, built {time.strftime('%Y-%m-%d', time.gmtime(meta.build_epoch))})")

    def get(self, ip):
        with self.lock:
            if self.reader is None:
                return None
            try:
                return self.reader.get(ip)
            except Exception as e:
                app.logger.warning(f"GeoIP {self.label} lookup for {ip} failed: {e}")
                return None


def make_db(path, label, kind):
    if path:
        return MMDB(path, label)
    if GEOIP_DOWNLOAD:
        return MMDB(os.path.join(GEOIP_DIR, f"dbip-{kind}-lite.mmdb"), label, download_kind=kind)
    return None


geo_country = make_db(GEOIP_COUNTRY_DB, 'country', 'country')
geo_asn = make_db(GEOIP_ASN_DB, 'ASN', 'asn')
GEO_DBS = [db for db in (geo_country, geo_asn) if db is not None]


def geo_attributions():
    """Attribution links for the databases in use (deduplicated, in order)."""
    result = []
    for db in GEO_DBS:
        if db.attribution and db.attribution not in result:
            result.append(db.attribution)
    return [{'prefix': p, 'text': t, 'url': u} for p, t, u in result]


def db_build_month(path):
    """'YYYY-MM' the .mmdb file was built, or None if missing/unreadable."""
    try:
        with maxminddb.open_database(path) as reader:
            return time.strftime('%Y-%m', time.gmtime(reader.metadata().build_epoch))
    except Exception:
        return None


def download_dbip(db):
    """
    Make sure db.path holds this month's DB-IP Lite file. DB-IP publishes once a
    month; early in the month the new file may not exist yet, in which case the
    existing file is kept (or last month's is fetched if there is none).
    Returns True if the file is current.
    """
    now = time.gmtime()
    month = time.strftime('%Y-%m', now)
    if db_build_month(db.path) == month:
        return True
    prev = f"{now.tm_year - 1}-12" if now.tm_mon == 1 else f"{now.tm_year}-{now.tm_mon - 1:02d}"

    for m in (month, prev):
        if m == prev and os.path.exists(db.path):
            return False   # keep the file we have, try the new month again later
        url = DBIP_URL.format(kind=db.download_kind, month=m)
        tmp = f"{db.path}.tmp"
        try:
            os.makedirs(os.path.dirname(db.path), exist_ok=True)
            with requests.get(url, stream=True, timeout=(10, 60),
                              headers={'User-Agent': 'TraefikShaper'}) as resp:
                if resp.status_code == 404:
                    continue
                resp.raise_for_status()
                inflate = zlib.decompressobj(16 + zlib.MAX_WBITS)   # gzip
                size = 0
                with open(tmp, 'wb') as f:
                    for chunk in resp.iter_content(1024 * 1024):
                        data = inflate.decompress(chunk)
                        size += len(data)
                        if size > GEOIP_MAX_SIZE:
                            raise ValueError("decompressed file too large")
                        f.write(data)
                    f.write(inflate.flush())
            expected = 'DBIP-Country' if db.download_kind == 'country' else 'DBIP-ASN'
            with maxminddb.open_database(tmp) as reader:
                db_type = str(reader.metadata().database_type)
            if not db_type.startswith(expected):
                raise ValueError(f"unexpected database type {db_type!r}")
            os.replace(tmp, db.path)
            app.logger.info(f"GeoIP: downloaded {url}")
            db.reload_if_changed()
            return m == month
        except Exception as e:
            app.logger.warning(f"GeoIP: download of {url} failed: {e}")
            return False
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)
    app.logger.warning(f"GeoIP: no DB-IP {db.download_kind} database published for {month} or {prev}")
    return False


def geoip_download_loop():
    """Background thread: download on startup, then check every GEOIP_REFRESH_INTERVAL."""
    dbs = [db for db in GEO_DBS if db.download_kind]
    if not dbs:
        return
    while True:
        current = True
        for db in dbs:
            try:
                current = download_dbip(db) and current
            except Exception as e:
                app.logger.error(f"GeoIP: update error: {e}")
                current = False
        time.sleep(GEOIP_REFRESH_INTERVAL if current else min(GEOIP_RETRY_INTERVAL, GEOIP_REFRESH_INTERVAL))


def flag_emoji(iso_code):
    if len(iso_code) != 2 or not iso_code.isascii() or not iso_code.isalpha():
        return ''
    return ''.join(chr(0x1F1E6 + ord(c) - ord('A')) for c in iso_code.upper())


def geo_lookup(ip):
    """Return e.g. '🇺🇸 United States (US), AS15169 Google LLC' (or '🇺🇸 US, ...' when the
    database has no country names), or '' if unknown/disabled."""
    parts = []

    rec = geo_country.get(ip) if geo_country else None
    if isinstance(rec, dict):
        # MaxMind/DB-IP layout: {'country': {'iso_code', 'names'}};
        # ip-location-db layout: {'country_code': 'US'}
        country = rec.get('country') or rec.get('registered_country') or {}
        if not isinstance(country, dict):
            country = {}
        iso = str(country.get('iso_code') or rec.get('country_code') or '')
        name = str((country.get('names') or {}).get('en') or '')
        if iso or name:
            label = f"{name} ({iso})" if name and iso else (name or iso)
            parts.append(f"{flag_emoji(iso)} {label}".strip())

    rec = geo_asn.get(ip) if geo_asn else None
    if isinstance(rec, dict):
        asn = rec.get('autonomous_system_number')
        org = str(rec.get('autonomous_system_organization') or '')
        if asn or org:
            parts.append(f"AS{asn} {org}".strip() if asn else org)

    return ', '.join(parts)


def describe_ip(ip, geo):
    return f"{ip} [{geo}]" if geo else ip

# --------------------------------------------------------------------------
# IP helpers
# --------------------------------------------------------------------------


def parse_ip(value):
    """Return canonical IP string, or None if value is not a single IP."""
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def rate_limit_key(ip):
    """IPv4: the address. IPv6: its /64, since one client controls a whole /64."""
    addr = ipaddress.ip_address(ip)
    if addr.version == 6:
        return str(ipaddress.ip_network(f"{addr}/64", strict=False))
    return str(addr)


def parse_networks(raw):
    """Parse a comma-separated list of IPs/CIDRs, skipping invalid entries."""
    result = []
    if not raw:
        return result
    for item in raw.split(','):
        item = item.strip()
        if not item:
            continue
        try:
            result.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            app.logger.error(f"Ignoring invalid IP/CIDR '{item}'")
    return result


def build_base_networks():
    if os.getenv('DEFAULT_PRIVATE_CLASS_SOURCE_RANGE') == "True":
        base = '127.0.0.1/32,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16'
    else:
        base = '127.0.0.1/32'
    return parse_networks(base) + parse_networks(os.getenv('WHITELISTED_IPS', None))


BASE_NETWORKS = build_base_networks()
EXCLUDED_NETWORKS = parse_networks(EXCLUDED_IPS)


def get_client_ip():
    """
    Determine the client IP from X-Forwarded-For.

    Both Traefik's reverse proxy (knock/approve requests) and its forwardAuth
    middleware (/auth requests) append the address of the TCP peer as the last
    X-Forwarded-For entry. The entries before it are the header Traefik
    received, which only exist if Traefik trusts them.
    """
    xff = request.headers.get('X-Forwarded-For')
    if not xff:
        # Behind Traefik the TCP peer is always Traefik itself, never the
        # client, so there is nothing safe to fall back to.
        app.logger.warning(f"Request from {request.remote_addr} without X-Forwarded-For; refusing")
        return None

    entries = [e.strip() for e in xff.split(',') if e.strip()]
    if not entries:
        return None
    received = entries[:-1]

    if EXCLUDED_NETWORKS:
        for entry in reversed(received):
            ip = parse_ip(entry)
            if ip is None:
                return None
            if not any(ipaddress.ip_address(ip) in n for n in EXCLUDED_NETWORKS):
                return ip
        return None

    if IPSTRATEGY_DEPTH > 0:
        if IPSTRATEGY_DEPTH > len(received):
            return None
        return parse_ip(received[-IPSTRATEGY_DEPTH])

    return parse_ip(entries[-1])


def wait_for_initial_server_ip():
    """
    Right after startup the server IP isn't known yet. Instead of wrongly
    denying it, hold the request until the first check is done (or times out).
    Must be called WITHOUT state_lock held.
    """
    if ALLOW_SERVER_IP and not server_ip_ready.is_set():
        server_ip_ready.wait(INITIAL_SERVER_IP_WAIT)


def is_approvable(ip):
    return ALLOW_PRIVATE_APPROVALS or ipaddress.ip_address(ip).is_global


def is_allowed(ip):
    """Must be called with state_lock held."""
    if ip in approved and approved[ip]['expiry'] >= time.time():
        return True
    if ip == server_ip:
        return True
    addr = ipaddress.ip_address(ip)
    return any(addr in n for n in BASE_NETWORKS)

# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------

PAGE_STYLE = """
<style>
    body { font-family: Arial, sans-serif; background-color: #f4f4f4; padding: 20px; }
    .container { max-width: 600px; margin: auto; background-color: #fff; border-radius: 5px;
                 padding: 20px; box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1); }
    h1 { color: #333; }
    p { color: #555; margin-bottom: 20px; }
    .highlight { background-color: #ffffcc; padding: 5px; font-weight: bold; }
    button { font-size: 1.1em; padding: 10px 20px; cursor: pointer; }
    button.danger { background-color: #c62828; color: #fff; border: none; border-radius: 4px; }
    .notice { background-color: #e8f5e9; color: #1b5e20; padding: 10px; border-radius: 4px; }
    .hint { font-size: 0.9em; color: #888; }
</style>
"""

REQUEST_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Approval Required</title>
""" + PAGE_STYLE + """
</head>
<body>
    <div class="container">
        <h1>Approval Required</h1>
        <p>Your request requires approval. Please wait while we process your request.</p>
        <p>Validation code: <span class="highlight">{{ code }}</span></p>
        <p>An administrator will review your request shortly.</p>
    </div>
</body>
</html>
"""

CONFIRM_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Confirm Approval</title>
""" + PAGE_STYLE + """
</head>
<body>
    <div class="container">
        <h1>Approve access?</h1>
        <p>IP address: <span class="highlight">{{ ip }}</span></p>
        {% if geo %}<p>Location / network: {{ geo }}</p>{% endif %}
        <p>Validation code: <span class="highlight">{{ code }}</span></p>
        <p>Access will be granted for {{ expiration }} seconds.</p>
        <form method="post" action="{{ action }}">
            <input type="hidden" name="ip" value="{{ ip }}">
            <input type="hidden" name="token" value="{{ token }}">
            <button type="submit" name="action" value="approve">Approve</button>
        </form>
        {% if geo and attributions %}<p class="hint">{% for a in attributions %}{{ a.prefix }}<a href="{{ a.url }}" rel="noreferrer">{{ a.text }}</a>{% if not loop.last %} · {% endif %}{% endfor %}</p>{% endif %}
    </div>
</body>
</html>
"""

REVOKE_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Access Active</title>
""" + PAGE_STYLE + """
</head>
<body>
    <div class="container">
        {% if notice %}<p class="notice">{{ notice }}</p>{% endif %}
        <h1>Access active</h1>
        <p>IP address: <span class="highlight">{{ ip }}</span></p>
        {% if geo %}<p>Location / network: {{ geo }}</p>{% endif %}
        <p>Allowed until {{ until }} ({{ remaining }} left).</p>
        <form method="post" action="{{ action }}">
            <input type="hidden" name="ip" value="{{ ip }}">
            <input type="hidden" name="token" value="{{ token }}">
            <button type="submit" name="action" value="revoke" class="danger">Revoke access</button>
        </form>
        <p class="hint">Open the approval link again any time before expiry to revoke.</p>
        {% if geo and attributions %}<p class="hint">{% for a in attributions %}{{ a.prefix }}<a href="{{ a.url }}" rel="noreferrer">{{ a.text }}</a>{% if not loop.last %} · {% endif %}{% endfor %}</p>{% endif %}
    </div>
</body>
</html>
"""

MESSAGE_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }}</title>
""" + PAGE_STYLE + """
</head>
<body>
    <div class="container">
        <h1>{{ title }}</h1>
        <p>{{ text }}</p>
    </div>
</body>
</html>
"""

CODE_WORDS = (
    'amber', 'anchor', 'apple', 'arrow', 'aspen', 'badger', 'bamboo', 'basil',
    'beacon', 'birch', 'bison', 'canyon', 'cedar', 'cherry', 'cobalt', 'comet',
    'copper', 'coral', 'cotton', 'crane', 'delta', 'desert', 'eagle', 'ember',
    'falcon', 'fern', 'forest', 'garnet', 'ginger', 'glacier', 'granite', 'harbor',
    'hazel', 'heron', 'island', 'ivory', 'jasper', 'juniper', 'kettle', 'lagoon',
    'lemon', 'lilac', 'lotus', 'maple', 'marble', 'meadow', 'mango', 'nectar',
    'ocean', 'olive', 'onyx', 'orchid', 'otter', 'pebble', 'pepper', 'pine',
    'quartz', 'raven', 'river', 'saffron', 'salmon', 'tiger', 'tulip', 'walnut',
)


def random_code():
    return f"{secrets.choice(CODE_WORDS)}-{secrets.choice(CODE_WORDS)}"


@app.after_request
def security_headers(response):
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Cache-Control'] = 'no-store'
    response.headers['X-Robots-Tag'] = 'noindex, nofollow'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    return response


@app.route('/auth', methods=['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'])
def auth():
    """forwardAuth endpoint. 2xx = let the request through, anything else = deny."""
    ip = get_client_ip()
    if ip is not None:
        wait_for_initial_server_ip()
        with state_lock:
            if is_allowed(ip):
                return '', 200
    return 'Forbidden', 403


@app.route('/healthz', methods=['GET'])
def healthz():
    return 'ok', 200


@app.route(GRANT_HTTP_ENDPOINT, methods=['GET'])
def request_access():
    ip = get_client_ip()
    if ip is None:
        return 'Could not determine your IP address.', 400

    if not is_approvable(ip):
        app.logger.warning(f"Refusing approval request from non-public IP {ip} "
                           "(proxy/gateway hiding the real client?)")
        return 'Access requests from this address are not allowed.', 403

    wait_for_initial_server_ip()
    now = time.time()
    key = rate_limit_key(ip)
    geo = geo_lookup(ip)   # outside the lock: local file read only

    with state_lock:
        if is_allowed(ip):
            return redirect('/')

        last = last_request.get(key)
        if last is not None and now - last < REQUEST_COOLDOWN:
            return 'You have already requested approval recently.', 403

        while notify_times and now - notify_times[0] > 3600:
            notify_times.popleft()
        if len(notify_times) >= MAX_NOTIFICATIONS_PER_HOUR:
            app.logger.warning(f"Notification cap reached; dropping request from {ip}")
            return 'Too many approval requests. Try again later.', 429

        last_request[key] = now
        notify_times.append(now)

        token = secrets.token_urlsafe(32)
        code = random_code()
        pending[ip] = {'token': token, 'created': now, 'code': code, 'geo': geo}

    approval_link = f"{APPURL}/approve?" + urlencode({'ip': ip, 'token': token})
    message = f"Access request from {ip} (code: {code})\n"
    if geo:
        message += f"{geo}\n"
    message += approval_link

    if send_notification(message):
        return render_template_string(REQUEST_PAGE, code=code), 200

    app.logger.info(f"Default notification channel failed. Here is the approval link via container logs: {approval_link}")
    return 'Approval required, but message to admin failed', 403


def lookup_pending(ip_raw, token):
    """Return (ip, entry) for a valid, unexpired pending request. Hold state_lock."""
    ip = parse_ip(ip_raw)
    if ip is None or not token:
        return None, None
    entry = pending.get(ip)
    if entry is None:
        return None, None
    if time.time() - entry['created'] > PENDING_TTL:
        pending.pop(ip, None)
        return None, None
    if not hmac.compare_digest(entry['token'].encode(), token.encode()):
        return None, None
    return ip, entry


def lookup_approved(ip_raw, token):
    """Return ip for an active approval created by this link's token. Hold state_lock."""
    ip = parse_ip(ip_raw)
    if ip is None or not token:
        return None
    entry = approved.get(ip)
    if entry is None or entry['expiry'] < time.time():
        return None
    if not hmac.compare_digest(entry['token'].encode(), token.encode()):
        return None
    return ip


def format_remaining(seconds):
    seconds = max(0, int(seconds))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    return f"{h}h {m:02d}m" if h else f"{m}m {s:02d}s"


def render_revoke_page(ip, notice=None):
    """Hold state_lock."""
    entry = approved[ip]
    return render_template_string(
        REVOKE_PAGE, ip=ip, token=entry['token'], notice=notice, geo=entry.get('geo', ''),
        attributions=geo_attributions(),
        until=time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(entry['expiry'])),
        remaining=format_remaining(entry['expiry'] - time.time()),
        action=f"{APPURL}/approve")


def message_page(title, text, status):
    return render_template_string(MESSAGE_PAGE, title=title, text=text), status


@app.route('/approve', methods=['GET'])
def approve_confirm():
    # GET never changes state: link previews / crawlers only see these pages.
    ip_raw, token = request.args.get('ip'), request.args.get('token')
    with state_lock:
        ip, entry = lookup_pending(ip_raw, token)
        if ip is not None:
            return render_template_string(
                CONFIRM_PAGE, ip=ip, code=entry['code'], token=entry['token'], geo=entry['geo'],
                attributions=geo_attributions(),
                expiration=EXPIRATION_TIME, action=f"{APPURL}/approve"), 200

        # Same link, already approved and not expired: offer to revoke
        ip = lookup_approved(ip_raw, token)
        if ip is not None:
            return render_revoke_page(ip), 200

    return message_page('Link not valid', 'This link is invalid, expired or was already used.', 403)


@app.route('/approve', methods=['POST'])
def approve_post():
    action = request.form.get('action', 'approve')
    if action == 'revoke':
        return revoke_ip()
    return approve_ip()


def approve_ip():
    ip_raw, token = request.form.get('ip'), request.form.get('token')
    with state_lock:
        ip, entry = lookup_pending(ip_raw, token)
        if ip is None or not is_approvable(ip):
            return message_page('Link not valid', 'This link is invalid, expired or was already used.', 403)
        del pending[ip]
        geo = entry['geo']
        # Keep the token so the same link can revoke this approval
        approved[ip] = {'expiry': time.time() + EXPIRATION_TIME, 'token': token, 'geo': geo}

    app.logger.info(f"Approved {describe_ip(ip, geo)} for {EXPIRATION_TIME} seconds")
    notified = send_notification(f"✅ Whitelisted {describe_ip(ip, geo)} for {format_remaining(EXPIRATION_TIME)}.")
    notice = 'IP address approved.' + ('' if notified else ' (Notification failed.)')
    with state_lock:
        if lookup_approved(ip, token) is None:   # revoked/expired in the meantime
            return message_page('Approved', notice, 200)
        return render_revoke_page(ip, notice=notice), 200


def revoke_ip():
    ip_raw, token = request.form.get('ip'), request.form.get('token')
    with state_lock:
        ip = lookup_approved(ip_raw, token)
        if ip is None:
            return message_page('Link not valid', 'This approval is not active anymore.', 403)
        geo = approved.pop(ip).get('geo', '')

    app.logger.info(f"Revoked {describe_ip(ip, geo)}")
    send_notification(f"🚫 Revoked access for {describe_ip(ip, geo)}.")
    return message_page('Access revoked', f'{ip} is no longer allowed.', 200)

# --------------------------------------------------------------------------
# Background maintenance
# --------------------------------------------------------------------------


def query_ip_service(url):
    try:
        resp = requests.get(url, timeout=SERVER_IP_CHECK_TIMEOUT,
                            headers={'User-Agent': 'curl/8', 'Accept': 'text/plain'})
        resp.raise_for_status()
        ip = parse_ip(resp.text)
        if ip and ipaddress.ip_address(ip).is_global:
            return ip
        app.logger.warning(f"Server IP check: {url} returned an unusable value: {resp.text[:64]!r}")
    except Exception as e:
        app.logger.warning(f"Server IP check: {url} failed: {e}")
    return None


def fetch_server_ip():
    """
    Ask services in order; return the first IP that SERVER_IP_MIN_AGREE
    services agree on. Failing or disagreeing services fall through to the next.
    """
    votes = {}
    for url in SERVER_IP_CHECK_URLS:
        ip = query_ip_service(url)
        if ip is None:
            continue
        votes[ip] = votes.get(ip, 0) + 1
        if votes[ip] >= SERVER_IP_MIN_AGREE:
            return ip
    app.logger.error(f"Server IP check: no {SERVER_IP_MIN_AGREE} services agreed (results: {votes}); keeping last known IP")
    return None


def maintenance_loop():
    global server_ip
    next_ip_check = 0

    while True:
        try:
            now = time.time()

            new_server_ip = None
            if ALLOW_SERVER_IP and SERVER_IP_CHECK_URLS and now >= next_ip_check:
                next_ip_check = now + SERVER_IP_CHECK_INTERVAL
                new_server_ip = fetch_server_ip()   # network call outside the lock

            with state_lock:
                # is_allowed() already checks expiry; this just cleans up and notifies
                expired = [(ip, a.get('geo', '')) for ip, a in approved.items() if a['expiry'] < now]
                for ip, _ in expired:
                    del approved[ip]

                for ip in [ip for ip, e in pending.items() if now - e['created'] > PENDING_TTL]:
                    del pending[ip]
                for key in [k for k, t in last_request.items() if now - t > REQUEST_COOLDOWN]:
                    del last_request[key]

                # Keep the last known server IP if the check failed
                if new_server_ip and new_server_ip != server_ip:
                    app.logger.info(f"Server public IP changed: {server_ip} -> {new_server_ip}")
                    server_ip = new_server_ip
            server_ip_ready.set()

            for ip, geo in expired:
                app.logger.info(f"Access for {describe_ip(ip, geo)} expired")
                send_notification(f"❌ Removed {describe_ip(ip, geo)} from whitelist. Access revoked.")

            # Pick up updated database files (cheap stat() calls)
            for db in GEO_DBS:
                db.reload_if_changed()
        except Exception as e:
            app.logger.error(f"Maintenance loop error: {e}")
            server_ip_ready.set()   # never leave requests waiting on a broken check

        time.sleep(10)


if __name__ == '__main__':
    import sys
    import signal
    from waitress import serve

    # Running as PID 1 in a container: exit cleanly on `docker stop`
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))

    threading.Thread(target=maintenance_loop, daemon=True).start()
    threading.Thread(target=geoip_download_loop, daemon=True).start()
    # In the background: a slow notification must not delay opening the port
    # (until it's open, Traefik answers 500 for every protected request).
    threading.Thread(target=send_notification, args=("⭐ TraefikShaper Enabled | whitelist reset ⭐",),
                     daemon=True).start()

    # Single process on purpose: all state lives in memory.
    # clear_untrusted_proxy_headers=False: waitress would otherwise delete
    # X-Forwarded-For, and get_client_ip() parses it itself.
    serve(app, host='0.0.0.0', port=LISTEN_PORT, threads=SERVER_THREADS, ident=None,
          clear_untrusted_proxy_headers=False)
