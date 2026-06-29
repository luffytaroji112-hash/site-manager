#!/usr/bin/env python3
"""
Scraper Worker — Discovers Shopify stores via many free subdomain / DNS /
certificate-transparency / crawl-index sources that work from datacenter IPs.
Stores results directly in PostgreSQL for the checker service to process.

Design goals:
  * NEVER STOP — every request, every cycle and the DB connection are wrapped
    so a single failing source (timeout, rate-limit, dead host) can never kill
    the worker. It reconnects and keeps scanning forever.
  * MAXIMUM VOLUME — pulls from ~15 no-key sources plus optional API-key
    sources. Pagination state persists across cycles so paginated sources keep
    advancing through fresh pages instead of re-reading page 1.

Sources (no API key required):
  - RapidDNS        passive DNS,  ~100 stores/page, effectively infinite
  - crt.sh          certificate transparency, huge single dump
  - certSpotter     certificate transparency (cursor paginated)
  - Wayback CDX     web.archive.org crawl index (offset paginated, huge)
  - CommonCrawl     crawl index, rotates through every available index
  - AlienVault OTX  passive DNS + crawled URL list (paginated)
  - urlscan.io      security scan database (cursor paginated)
  - SiteDossier     web crawl index (page paginated)
  - HackerTarget    host search
  - DNSRepo         DNS history database
  - ThreatMiner     passive DNS subdomains
  - Anubis (jldc)   subdomain aggregator
  - SubdomainCenter ML subdomain finder
  - BufferOver      DNS dataset (best-effort, sometimes keyed)

Search engines (proxyless HTML scraping, verified to work from datacenter IPs):
  - Yahoo           site:myshopify.com dorking, paginated
  - DuckDuckGo      site:myshopify.com dorking (html endpoint)
  - Brave           site:myshopify.com dorking, paginated
  - Mojeek          independent crawler, very bot-tolerant, paginated

Optional sources (enabled automatically when the API key env var is present):
  - VirusTotal      VT_API_KEY            (cursor paginated)
  - SecurityTrails  SECURITYTRAILS_API_KEY
  - Shodan          SHODAN_API_KEY
  - FullHunt        FULLHUNT_API_KEY
  - BinaryEdge      BINARYEDGE_API_KEY    (page paginated)

Environment variables:
  DATABASE_URL          — PostgreSQL connection string (required)
  SCRAPER_BATCH_SIZE    — URLs to buffer before inserting (default: 100)
  SCRAPER_REQUESTS      — API requests per cycle (default: 60)
  SCRAPER_CYCLE_DELAY   — Seconds between cycles (default: 10)
"""

import os
import re
import time
import random
from urllib.parse import quote, unquote

import urllib3
import psycopg2
import psycopg2.extras
import requests

urllib3.disable_warnings()

# ── Config ──────────────────────────────────────────────────────────
DATABASE_URL       = os.environ.get("DATABASE_URL", "")
BATCH_SIZE         = int(os.environ.get("SCRAPER_BATCH_SIZE", "100"))
REQUESTS_PER_CYCLE = int(os.environ.get("SCRAPER_REQUESTS", "60"))
CYCLE_DELAY        = int(os.environ.get("SCRAPER_CYCLE_DELAY", "10"))

# Optional API keys — a source is only registered if its key is set.
VT_API_KEY            = os.environ.get("VT_API_KEY", "")
SECURITYTRAILS_KEY    = os.environ.get("SECURITYTRAILS_API_KEY", "")
SHODAN_KEY            = os.environ.get("SHODAN_API_KEY", "")
FULLHUNT_KEY          = os.environ.get("FULLHUNT_API_KEY", "")
BINARYEDGE_KEY        = os.environ.get("BINARYEDGE_API_KEY", "")

# Desktop UA rotation (matches yaho.py's proxyless searcher).
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edge/121.0.0.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64) Chrome/121.0.0.0",
]


def search_headers() -> dict:
    """Realistic browser headers for proxyless search engines (mirrors yaho.py get_headers())."""
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "keep-alive",
        "Accept-Encoding": "gzip, deflate",
        "DNT": "1",
    }

# Fallback CommonCrawl indexes if the live index list can't be fetched.
COMMONCRAWL_FALLBACK = [
    "CC-MAIN-2024-51", "CC-MAIN-2024-46", "CC-MAIN-2024-42",
    "CC-MAIN-2024-38", "CC-MAIN-2024-33", "CC-MAIN-2024-26",
    "CC-MAIN-2024-18", "CC-MAIN-2024-10", "CC-MAIN-2023-50",
]

# ── URL extraction ──────────────────────────────────────────────────
MYSHOPIFY_RE = re.compile(r"\b([a-z0-9][a-z0-9\-]{1,}[a-z0-9])\.myshopify\.com\b", re.IGNORECASE)
LABEL_RE     = re.compile(r"^[a-z0-9][a-z0-9\-]{1,}[a-z0-9]$")


def extract_stores(text: str) -> set:
    """Pull every <store>.myshopify.com out of arbitrary text/JSON."""
    stores = set()
    if not text:
        return stores
    for m in MYSHOPIFY_RE.finditer(text):
        store = m.group(1).lower().strip("-")
        if len(store) >= 3:
            stores.add(f"https://{store}.myshopify.com")
    return stores


def prefixes_to_urls(prefixes) -> set:
    """Some APIs return only the subdomain label (e.g. 'shop'); build full URLs."""
    out = set()
    for p in prefixes or []:
        p = str(p).lower().strip().strip(".")
        # keep only the left-most label if a full host slipped through
        p = p.split(".")[0]
        if len(p) >= 3 and LABEL_RE.match(p):
            out.add(f"https://{p}.myshopify.com")
    return out


def ua() -> str:
    return random.choice(USER_AGENTS)


def http_get(session, url, timeout=15, retries=2, headers=None, **kw):
    """GET with UA rotation + retry/backoff. Returns (response_or_None, err)."""
    hdrs = {"User-Agent": ua(), "Accept": "*/*"}
    if headers:
        hdrs.update(headers)
    last = ""
    for attempt in range(retries + 1):
        try:
            r = session.get(url, timeout=timeout, headers=hdrs, **kw)
            return r, ""
        except Exception as e:
            last = type(e).__name__
            if attempt < retries:
                time.sleep(0.6 * (attempt + 1) + random.uniform(0, 0.4))
    return None, last or "request failed"


# Persistent state across cycles: per-source pagination + cooldowns + tallies.
STATE: dict = {"_meta": {}}


def st(name: str) -> dict:
    return STATE.setdefault(name, {})


# ── Sources ──────────────────────────────────────────────────────────
# Each handler takes (session) and returns (stores:set, label:str, err:str).
# Pagination/cursor state lives in STATE[name] so it advances between cycles.

def src_rapiddns(session):
    s = st("RapidDNS")
    page = s.get("page") or random.randint(1, 200)
    r, err = http_get(session, f"https://rapiddns.io/subdomain/myshopify.com?full=1&page={page}#result", timeout=18)
    label = f"RapidDNS/p{page}"
    if err:
        return set(), label, err
    if r.status_code != 200:
        s["page"] = random.randint(1, 500)
        return set(), label, f"HTTP {r.status_code}"
    stores = extract_stores(r.text)
    # advance; reshuffle when a page runs dry or we wander too far
    s["page"] = (page + 1) if stores and page < 600 else random.randint(1, 500)
    return stores, label, ""


def src_crtsh(session):
    r, err = http_get(session, "https://crt.sh/?q=%25.myshopify.com&output=json", timeout=90, retries=1)
    if err:
        return set(), "crt.sh", err
    if r.status_code != 200:
        return set(), "crt.sh", f"HTTP {r.status_code}"
    return extract_stores(r.text), "crt.sh", ""


def src_certspotter(session):
    s = st("certSpotter")
    after = s.get("after", "")
    url = ("https://api.certspotter.com/v1/issuances?domain=myshopify.com"
           "&include_subdomains=true&expand=dns_names")
    if after:
        url += f"&after={after}"
    r, err = http_get(session, url, timeout=25)
    if err:
        return set(), "certSpotter", err
    if r.status_code == 429:
        return set(), "certSpotter", "rate limited"
    if r.status_code != 200:
        return set(), "certSpotter", f"HTTP {r.status_code}"
    stores = extract_stores(r.text)
    try:
        data = r.json()
        if isinstance(data, list) and data:
            s["after"] = str(data[-1].get("id", ""))
        else:
            s["after"] = ""  # reached the end → restart from the beginning
    except Exception:
        s["after"] = ""
    return stores, "certSpotter", ""


def src_wayback(session):
    s = st("Wayback")
    offset = s.get("offset", 0)
    limit = 12000
    url = ("http://web.archive.org/cdx/search/cdx?url=*.myshopify.com"
           f"&output=text&fl=original&collapse=urlkey&limit={limit}&offset={offset}")
    r, err = http_get(session, url, timeout=40)
    label = f"Wayback/o{offset}"
    if err:
        return set(), label, err
    if r.status_code != 200:
        s["offset"] = 0
        return set(), label, f"HTTP {r.status_code}"
    stores = extract_stores(r.text)
    s["offset"] = (offset + limit) if stores else 0
    return stores, label, ""


def _cc_indexes(session):
    cached = STATE["_meta"].get("cc_indexes")
    if cached:
        return cached
    idxs = None
    r, _ = http_get(session, "https://index.commoncrawl.org/collinfo.json", timeout=20)
    if r is not None and r.status_code == 200:
        try:
            idxs = [c["id"] for c in r.json() if c.get("id")][:15]
        except Exception:
            idxs = None
    idxs = idxs or COMMONCRAWL_FALLBACK
    STATE["_meta"]["cc_indexes"] = idxs
    return idxs


def src_commoncrawl(session):
    s = st("CommonCrawl")
    indexes = _cc_indexes(session)
    idx = s.get("idx", 0) % len(indexes)
    page = s.get("page", 0)
    index = indexes[idx]
    url = (f"https://index.commoncrawl.org/{index}-index"
           f"?url=*.myshopify.com&output=json&limit=200&page={page}")
    r, err = http_get(session, url, timeout=25, retries=1)
    label = f"CommonCrawl/{index}/p{page}"
    if err:
        # bad/empty index → move to the next one next time
        s["idx"] = idx + 1
        s["page"] = 0
        return set(), label, err
    if r.status_code != 200:
        s["idx"] = idx + 1
        s["page"] = 0
        return set(), label, f"HTTP {r.status_code}"
    stores = extract_stores(r.text)
    if stores and page < 25:
        s["page"] = page + 1
    else:
        s["idx"] = idx + 1
        s["page"] = 0
    return stores, label, ""


def src_otx_urls(session):
    s = st("OTX-urls")
    page = s.get("page", 1)
    url = (f"https://otx.alienvault.com/api/v1/indicators/domain/myshopify.com/url_list"
           f"?limit=500&page={page}")
    r, err = http_get(session, url, timeout=25)
    label = f"OTX-urls/p{page}"
    if err:
        return set(), label, err
    if r.status_code != 200:
        s["page"] = 1
        return set(), label, f"HTTP {r.status_code}"
    stores = extract_stores(r.text)
    has_next = True
    try:
        has_next = bool(r.json().get("has_next", False))
    except Exception:
        has_next = bool(stores)
    s["page"] = (page + 1) if has_next else 1
    return stores, label, ""


def src_otx_pdns(session):
    url = "https://otx.alienvault.com/api/v1/indicators/domain/myshopify.com/passive_dns"
    r, err = http_get(session, url, timeout=25)
    if err:
        return set(), "OTX-pdns", err
    if r.status_code != 200:
        return set(), "OTX-pdns", f"HTTP {r.status_code}"
    return extract_stores(r.text), "OTX-pdns", ""


def src_urlscan(session):
    s = st("urlscan")
    url = "https://urlscan.io/api/v1/search/?q=page.domain:myshopify.com&size=100"
    after = s.get("after")
    if after:
        url += "&search_after=" + ",".join(str(x) for x in after)
    r, err = http_get(session, url, timeout=20)
    if err:
        return set(), "urlscan.io", err
    if r.status_code == 429:
        return set(), "urlscan.io", "rate limited"
    if r.status_code != 200:
        s["after"] = None
        return set(), "urlscan.io", f"HTTP {r.status_code}"
    stores = extract_stores(r.text)
    try:
        data = r.json()
        results = data.get("results", [])
        if results and data.get("has_more"):
            s["after"] = results[-1].get("sort")
        else:
            s["after"] = None
    except Exception:
        s["after"] = None
    return stores, "urlscan.io", ""


def src_sitedossier(session):
    s = st("SiteDossier")
    page = s.get("page") or random.randint(1, 30)
    label = f"SiteDossier/p{page}"
    # HTTPS first (more reliable), fall back to the legacy HTTP host.
    for scheme in ("https", "http"):
        r, err = http_get(session, f"{scheme}://www.sitedossier.com/parentdomain/myshopify.com/{page}",
                          timeout=15, allow_redirects=False)
        if err:
            continue
        if r.status_code in (301, 302):
            s["page"] = 1  # ran past the last page → wrap around
            return set(), label, "wrapped to start"
        if r.status_code != 200:
            continue
        stores = extract_stores(r.text)
        s["page"] = (page + 1) if stores and page < 200 else 1
        return stores, label, ""
    s["page"] = (page + 1) if page < 200 else 1
    return set(), label, "unreachable"


def src_hackertarget(session):
    r, err = http_get(session, "https://api.hackertarget.com/hostsearch/?q=myshopify.com", timeout=15)
    if err:
        return set(), "HackerTarget", err
    if r.status_code != 200:
        return set(), "HackerTarget", f"HTTP {r.status_code}"
    if "API count exceeded" in r.text or r.text.startswith("error"):
        return set(), "HackerTarget", "rate limited"
    return extract_stores(r.text), "HackerTarget", ""


def src_dnsrepo(session):
    r, err = http_get(session, "https://dnsrepo.noc.org/?domain=myshopify.com", timeout=15)
    if err:
        return set(), "DNSRepo", err
    if r.status_code != 200:
        return set(), "DNSRepo", f"HTTP {r.status_code}"
    return extract_stores(r.text), "DNSRepo", ""


def src_threatminer(session):
    r, err = http_get(session, "https://api.threatminer.org/v2/domain.php?q=myshopify.com&rt=5", timeout=20)
    if err:
        return set(), "ThreatMiner", err
    if r.status_code != 200:
        return set(), "ThreatMiner", f"HTTP {r.status_code}"
    return extract_stores(r.text), "ThreatMiner", ""


def src_anubis(session):
    r, err = http_get(session, "https://jldc.me/anubis/subdomains/myshopify.com", timeout=20)
    if err:
        return set(), "Anubis", err
    if r.status_code != 200:
        return set(), "Anubis", f"HTTP {r.status_code}"
    return extract_stores(r.text), "Anubis", ""


def src_subdomaincenter(session):
    r, err = http_get(session, "https://api.subdomain.center/?domain=myshopify.com", timeout=25)
    if err:
        return set(), "SubdomainCenter", err
    if r.status_code != 200:
        return set(), "SubdomainCenter", f"HTTP {r.status_code}"
    return extract_stores(r.text), "SubdomainCenter", ""


def src_bufferover(session):
    r, err = http_get(session, "https://dns.bufferover.run/dns?q=.myshopify.com", timeout=20)
    if err:
        return set(), "BufferOver", err
    if r.status_code != 200:
        return set(), "BufferOver", f"HTTP {r.status_code}"
    return extract_stores(r.text), "BufferOver", ""


# ── Search engines (proxyless, no key) ───────────────────────────────
# Verified to return Shopify stores from datacenter IPs without proxies.
# Each call walks a (dork, page) cursor so coverage keeps widening instead
# of re-reading the same first page every time.

SEARCH_DORKS = [
    "site:myshopify.com",
    "site:myshopify.com shop",
    "site:myshopify.com store",
    "site:myshopify.com buy",
    "site:myshopify.com products",
    "site:myshopify.com collections",
    "site:myshopify.com sale",
    "site:myshopify.com new",
    "site:myshopify.com best seller",
    "site:myshopify.com gift",
    "site:myshopify.com bundle",
    "site:myshopify.com makeup",
    "site:myshopify.com cosmetics",
    "site:myshopify.com beauty",
    "site:myshopify.com skincare",
    "site:myshopify.com perfume",
    "site:myshopify.com fragrance",
    "site:myshopify.com candles",
    "site:myshopify.com jewelry",
    "site:myshopify.com accessories",
    "site:myshopify.com bags",
    "site:myshopify.com watches",
    "site:myshopify.com sunglasses",
    "site:myshopify.com clothing",
    "site:myshopify.com fashion",
    "site:myshopify.com shoes",
    "site:myshopify.com kids",
    "site:myshopify.com baby",
    "site:myshopify.com pet",
    "site:myshopify.com home decor",
    "site:myshopify.com furniture",
    "site:myshopify.com kitchen",
    "site:myshopify.com electronics",
    "site:myshopify.com gadgets",
    "site:myshopify.com tech",
    "site:myshopify.com phone case",
    "site:myshopify.com fitness",
    "site:myshopify.com sports",
    "site:myshopify.com outdoor",
    "site:myshopify.com vitamins",
    "site:myshopify.com supplements",
    "site:myshopify.com organic",
    "site:myshopify.com handmade",
    "site:myshopify.com vintage",
    "site:myshopify.com luxury",
    "site:myshopify.com cheap",
    "site:myshopify.com coffee",
    "site:myshopify.com tea",
    "site:myshopify.com food",
    "site:myshopify.com art",
]


def _search_step(key, per_page, max_start):
    """Return the (query, start) to use now and advance the cursor for next time."""
    s = st(key)
    di = s.get("dork", 0) % len(SEARCH_DORKS)
    start = s.get("start", 0)
    q = SEARCH_DORKS[di]
    if start + per_page > max_start:
        s["dork"] = di + 1
        s["start"] = 0
    else:
        s["dork"] = di
        s["start"] = start + per_page
    return q, start


def _search_extract(text: str) -> set:
    """Search results wrap target URLs in percent-encoded redirects.
    Decode first so '...%2fstore.myshopify.com' yields 'store', not '2fstore'.
    unquote() never alters a clean (un-encoded) host, so decoding is always safe."""
    return extract_stores(unquote(text))


def _blocked(r) -> bool:
    if r.status_code in (403, 429, 503):
        return True
    low = r.text[:2000].lower()
    return any(k in low for k in ("captcha", "unusual traffic", "are you a robot", "verify you are human"))


def src_yahoo(session):
    # Endpoint/param/headers mirror yaho.py: GET search.yahoo.com/search?p=<dork>
    # with the desktop UA + browser headers. We add Yahoo's standard &b= offset
    # (1-indexed) purely to page deeper for more results — same API, same request.
    q, start = _search_step("Yahoo", per_page=10, max_start=90)
    b = start + 1
    url = "https://search.yahoo.com/search?p=" + quote(q) + f"&b={b}"
    r, err = http_get(session, url, timeout=20, headers=search_headers())
    label = f"Yahoo/b{b}"
    if err:
        return set(), label, err
    if _blocked(r):
        return set(), label, "blocked"
    if r.status_code not in (200, 202):
        return set(), label, f"HTTP {r.status_code}"
    return _search_extract(r.text), label, ""


def src_duckduckgo(session):
    q, _ = _search_step("DuckDuckGo", per_page=1, max_start=0)  # page 1, rotate dorks
    url = "https://html.duckduckgo.com/html/?q=" + quote(q)
    r, err = http_get(session, url, timeout=20, headers=search_headers())
    if err:
        return set(), "DuckDuckGo", err
    if _blocked(r):
        return set(), "DuckDuckGo", "blocked"
    if r.status_code not in (200, 202):
        return set(), "DuckDuckGo", f"HTTP {r.status_code}"
    return _search_extract(r.text), "DuckDuckGo", ""


def src_brave(session):
    q, start = _search_step("Brave", per_page=20, max_start=100)
    offset = start // 20  # Brave paginates by 0-based page offset
    url = "https://search.brave.com/search?q=" + quote(q) + f"&offset={offset}&source=web"
    r, err = http_get(session, url, timeout=20, headers=search_headers())
    label = f"Brave/o{offset}"
    if err:
        return set(), label, err
    if _blocked(r):
        return set(), label, "blocked"
    if r.status_code not in (200, 202):
        return set(), label, f"HTTP {r.status_code}"
    return _search_extract(r.text), label, ""


def src_mojeek(session):
    q, start = _search_step("Mojeek", per_page=10, max_start=90)
    s_idx = start + 1  # Mojeek result offset is 1-indexed
    url = "https://www.mojeek.com/search?q=" + quote(q) + f"&s={s_idx}"
    r, err = http_get(session, url, timeout=20, headers=search_headers())
    label = f"Mojeek/s{s_idx}"
    if err:
        return set(), label, err
    if _blocked(r):
        return set(), label, "blocked"
    if r.status_code not in (200, 202):
        return set(), label, f"HTTP {r.status_code}"
    return _search_extract(r.text), label, ""


# ── Optional keyed sources ───────────────────────────────────────────

def src_virustotal(session):
    s = st("VirusTotal")
    url = "https://www.virustotal.com/api/v3/domains/myshopify.com/subdomains?limit=40"
    cursor = s.get("cursor")
    if cursor:
        url += f"&cursor={cursor}"
    r, err = http_get(session, url, timeout=20, headers={"x-apikey": VT_API_KEY})
    if err:
        return set(), "VirusTotal", err
    if r.status_code == 429:
        return set(), "VirusTotal", "rate limited"
    if r.status_code != 200:
        s["cursor"] = None
        return set(), "VirusTotal", f"HTTP {r.status_code}"
    stores = extract_stores(r.text)
    try:
        s["cursor"] = r.json().get("meta", {}).get("cursor")
    except Exception:
        s["cursor"] = None
    return stores, "VirusTotal", ""


def src_securitytrails(session):
    url = "https://api.securitytrails.com/v1/domain/myshopify.com/subdomains?children_only=false"
    r, err = http_get(session, url, timeout=20, headers={"APIKEY": SECURITYTRAILS_KEY})
    if err:
        return set(), "SecurityTrails", err
    if r.status_code != 200:
        return set(), "SecurityTrails", f"HTTP {r.status_code}"
    try:
        return prefixes_to_urls(r.json().get("subdomains", [])), "SecurityTrails", ""
    except Exception as e:
        return set(), "SecurityTrails", type(e).__name__


def src_shodan(session):
    url = f"https://api.shodan.io/dns/domain/myshopify.com?key={SHODAN_KEY}"
    r, err = http_get(session, url, timeout=20)
    if err:
        return set(), "Shodan", err
    if r.status_code != 200:
        return set(), "Shodan", f"HTTP {r.status_code}"
    try:
        return prefixes_to_urls(r.json().get("subdomains", [])), "Shodan", ""
    except Exception as e:
        return set(), "Shodan", type(e).__name__


def src_fullhunt(session):
    url = "https://fullhunt.io/api/v1/domain/myshopify.com/subdomains"
    r, err = http_get(session, url, timeout=20, headers={"X-API-KEY": FULLHUNT_KEY})
    if err:
        return set(), "FullHunt", err
    if r.status_code != 200:
        return set(), "FullHunt", f"HTTP {r.status_code}"
    return extract_stores(r.text), "FullHunt", ""


def src_binaryedge(session):
    s = st("BinaryEdge")
    page = s.get("page", 1)
    url = f"https://api.binaryedge.io/v2/query/domains/subdomain/myshopify.com?page={page}"
    r, err = http_get(session, url, timeout=20, headers={"X-Key": BINARYEDGE_KEY})
    label = f"BinaryEdge/p{page}"
    if err:
        return set(), label, err
    if r.status_code != 200:
        s["page"] = 1
        return set(), label, f"HTTP {r.status_code}"
    stores = extract_stores(r.text)
    s["page"] = (page + 1) if stores else 1
    return stores, label, ""


# ── Source registry ──────────────────────────────────────────────────
# kind: "page"   → safe to hit every request (paginates forward)
#       "oneshot"→ returns a big batch; throttled by `cooldown` seconds
#
# fields: name, handler, weight, kind, cooldown
SOURCES = [
    {"name": "RapidDNS",        "fn": src_rapiddns,        "w": 40, "kind": "page"},
    {"name": "Wayback",         "fn": src_wayback,         "w": 30, "kind": "page"},
    {"name": "crt.sh",          "fn": src_crtsh,           "w": 35, "kind": "oneshot", "cd": 1800},
    {"name": "CommonCrawl",     "fn": src_commoncrawl,     "w": 18, "kind": "page"},
    {"name": "OTX-urls",        "fn": src_otx_urls,        "w": 16, "kind": "page"},
    {"name": "urlscan.io",      "fn": src_urlscan,         "w": 14, "kind": "page"},
    {"name": "SiteDossier",     "fn": src_sitedossier,     "w": 12, "kind": "page"},
    {"name": "certSpotter",     "fn": src_certspotter,     "w": 12, "kind": "page"},
    {"name": "OTX-pdns",        "fn": src_otx_pdns,        "w":  8, "kind": "oneshot", "cd": 900},
    {"name": "DNSRepo",         "fn": src_dnsrepo,         "w":  8, "kind": "oneshot", "cd": 900},
    {"name": "Anubis",          "fn": src_anubis,          "w":  8, "kind": "oneshot", "cd": 1800},
    {"name": "SubdomainCenter", "fn": src_subdomaincenter, "w":  8, "kind": "oneshot", "cd": 1800},
    {"name": "ThreatMiner",     "fn": src_threatminer,     "w":  5, "kind": "oneshot", "cd": 600},
    {"name": "HackerTarget",    "fn": src_hackertarget,    "w":  4, "kind": "oneshot", "cd": 3600},
    {"name": "BufferOver",      "fn": src_bufferover,      "w":  3, "kind": "oneshot", "cd": 1800},
    # Search engines — proxyless, paginated dorking (replaces the dead Tempest API)
    {"name": "Yahoo",           "fn": src_yahoo,           "w": 18, "kind": "page"},
    {"name": "DuckDuckGo",      "fn": src_duckduckgo,      "w": 12, "kind": "page"},
    {"name": "Brave",           "fn": src_brave,           "w": 12, "kind": "page"},
    {"name": "Mojeek",          "fn": src_mojeek,          "w": 10, "kind": "page"},
]

# Register keyed sources only when their API key is configured.
if VT_API_KEY:
    SOURCES.append({"name": "VirusTotal",     "fn": src_virustotal,     "w": 20, "kind": "page"})
if SECURITYTRAILS_KEY:
    SOURCES.append({"name": "SecurityTrails",  "fn": src_securitytrails, "w": 22, "kind": "oneshot", "cd": 1800})
if SHODAN_KEY:
    SOURCES.append({"name": "Shodan",          "fn": src_shodan,         "w": 14, "kind": "oneshot", "cd": 1800})
if FULLHUNT_KEY:
    SOURCES.append({"name": "FullHunt",        "fn": src_fullhunt,       "w": 14, "kind": "oneshot", "cd": 1800})
if BINARYEDGE_KEY:
    SOURCES.append({"name": "BinaryEdge",      "fn": src_binaryedge,     "w": 14, "kind": "page"})


def pick_source():
    """Weighted pick among sources that aren't currently on cooldown."""
    now = time.time()
    eligible = []
    weights = []
    for s in SOURCES:
        if now < st(s["name"]).get("next_ok", 0):
            continue
        eligible.append(s)
        weights.append(s["w"])
    if not eligible:  # everything cooling down → ignore cooldowns rather than stall
        eligible = SOURCES
        weights = [s["w"] for s in SOURCES]
    return random.choices(eligible, weights=weights, k=1)[0]


def cooldown(source, err):
    """Apply post-call cooldown: throttle one-shots, and back off when blocked/limited."""
    now = time.time()
    s = st(source["name"])
    low = (err or "").lower()
    blocked = any(k in low for k in ("rate", "429", "403", "503", "block", "captcha"))
    if blocked:
        s["next_ok"] = now + max(source.get("cd", 600), 600)
    elif source["kind"] == "oneshot":
        s["next_ok"] = now + source.get("cd", 600)


# ── Cycle ────────────────────────────────────────────────────────────

def scrape_cycle(num_requests: int, seen: set) -> set:
    found: set = set()
    session = requests.Session()
    session.verify = False

    for i in range(1, num_requests + 1):
        source = pick_source()
        try:
            stores, label, err = source["fn"](session)
        except Exception as e:               # a source must never crash the cycle
            stores, label, err = set(), source["name"], type(e).__name__

        cooldown(source, err)

        if err:
            print(f"  [{i}/{num_requests}] {label} -> ERROR: {err}", flush=True)
        else:
            new = stores - found - seen
            found.update(stores)
            tally = st(source["name"])
            tally["hits"] = tally.get("hits", 0) + len(new)
            print(f"  [{i}/{num_requests}] {label} -> {len(stores)} stores, +{len(new)} new", flush=True)

        time.sleep(random.uniform(0.3, 1.0))

    return found


def print_source_summary():
    rows = sorted(((st(s["name"]).get("hits", 0), s["name"]) for s in SOURCES), reverse=True)
    top = ", ".join(f"{name}:{hits}" for hits, name in rows if hits) or "none yet"
    print(f"  Source yield (all-time new): {top}", flush=True)


# ── Database ─────────────────────────────────────────────────────────

def connect_db():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL environment variable is not set")
    conn = psycopg2.connect(DATABASE_URL, connect_timeout=15)
    conn.autocommit = False
    return conn


def ensure_schema(conn):
    with conn.cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS sites (
                id             BIGSERIAL PRIMARY KEY,
                url            TEXT NOT NULL UNIQUE,
                status         TEXT NOT NULL DEFAULT 'pending',
                error_code     TEXT NOT NULL DEFAULT '',
                error_msg      TEXT NOT NULL DEFAULT '',
                checkout_price NUMERIC(10,2) NOT NULL DEFAULT 0,
                check_count    INTEGER NOT NULL DEFAULT 0,
                last_checked   TIMESTAMPTZ,
                created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            CREATE INDEX IF NOT EXISTS idx_sites_status ON sites(status);
            CREATE INDEX IF NOT EXISTS idx_sites_url    ON sites(url);
        """)
    conn.commit()


def insert_sites(conn, urls: list) -> int:
    if not urls:
        return 0
    try:
        with conn.cursor() as cur:
            psycopg2.extras.execute_values(
                cur,
                "INSERT INTO sites (url) VALUES %s ON CONFLICT (url) DO NOTHING",
                [(u,) for u in urls],
                page_size=500,
            )
            added = cur.rowcount
        conn.commit()
        return added
    except psycopg2.Error:
        conn.rollback()
        raise


def get_stats(conn) -> dict:
    with conn.cursor() as cur:
        cur.execute("SELECT status, COUNT(*) FROM sites GROUP BY status")
        rows = cur.fetchall()
    stats = {row[0]: row[1] for row in rows}
    stats["total"] = sum(stats.values())
    return stats


# ── Main loop ───────────────────────────────────────────────────────

def run_loop(conn):
    """Inner loop: scrape → insert, forever. Raises on DB errors to reconnect."""
    with conn.cursor() as cur:
        cur.execute("SELECT url FROM sites")
        seen: set = {row[0] for row in cur.fetchall()}
    print(f"Loaded {len(seen)} existing URLs from DB", flush=True)

    cycle = 0
    total_found = 0
    total_added = 0

    while True:
        cycle += 1
        stats = get_stats(conn)
        print(f"\n{'='*55}", flush=True)
        print(f"[Cycle {cycle}] DB: {stats['total']} total | "
              f"{stats.get('pending', 0)} pending | {stats.get('working', 0)} working", flush=True)

        try:
            found = scrape_cycle(REQUESTS_PER_CYCLE, seen)
        except Exception as e:
            # Scraping should never throw (each source is guarded), but just in case.
            print(f"[Cycle {cycle}] scrape error: {type(e).__name__}: {e}", flush=True)
            found = set()

        total_found += len(found)
        new_urls = [u for u in found if u not in seen]
        seen.update(new_urls)

        added = 0
        for i in range(0, len(new_urls), BATCH_SIZE):
            added += insert_sites(conn, new_urls[i:i + BATCH_SIZE])  # raises → reconnect
        total_added += added

        print(f"\n[Cycle {cycle}] Done — {len(found)} found, {added} new in DB", flush=True)
        print_source_summary()
        print(f"All-time: {total_found} found, {total_added} added | sleeping {CYCLE_DELAY}s...", flush=True)
        time.sleep(CYCLE_DELAY)


def main():
    print("Scraper Worker starting", flush=True)
    print(f"  Sources ({len(SOURCES)}): {', '.join(s['name'] for s in SOURCES)}", flush=True)
    print(f"  Requests per cycle: {REQUESTS_PER_CYCLE} | Cycle delay: {CYCLE_DELAY}s", flush=True)

    backoff = 5
    while True:  # self-healing: reconnect and resume on ANY fatal error
        conn = None
        try:
            conn = connect_db()
            ensure_schema(conn)
            print("Database connected", flush=True)
            backoff = 5
            run_loop(conn)
        except KeyboardInterrupt:
            print("Shutting down.", flush=True)
            break
        except Exception as e:
            print(f"!! Fatal: {type(e).__name__}: {e} — reconnecting in {backoff}s", flush=True)
            time.sleep(backoff)
            backoff = min(backoff * 2, 300)
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass


if __name__ == "__main__":
    main()
