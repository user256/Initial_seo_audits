"""
Networking + rendering + HTML extraction helpers.
"""
import os
import json
import re
import time
from urllib.parse import urljoin, urlparse, urlunparse, parse_qsl, urlencode

import requests
import lxml.html

from selenium import webdriver
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.chrome.service import Service as ChromeService

REQ_TIMEOUT = 20

# ----------------------------
# URL normalization and utilities
# ----------------------------
def norm_host(host: str) -> str:
    h = (host or "").lower()
    return h[4:] if h.startswith("www.") else h

def norm_url(u: str, base: str = "") -> str:
    if base:
        u = urljoin(base, u)
    p = urlparse(u)
    scheme = (p.scheme or "https").lower()
    host = norm_host(p.netloc)
    path = re.sub(r"/{2,}", "/", p.path or "/")
    if path != "/" and path.endswith("/"):
        path = path[:-1]
    if p.query:
        pairs = parse_qsl(p.query, keep_blank_values=True)
        pairs.sort()
        query = urlencode(pairs, doseq=True)
    else:
        query = ""
    return urlunparse((scheme, host, path, "", query, ""))

def is_internal(link: str, site_host: str) -> bool:
    try:
        h = norm_host(urlparse(link).netloc)
        return (h == "" or h == site_host)
    except Exception:
        return False

# ----------------------------
# HTML extraction helpers
# ----------------------------
def get_text_or_empty(doc, xpath: str) -> str:
    try:
        node = doc.xpath(xpath)
        if not node:
            return ""
        return node[0].text_content().strip()
    except Exception:
        return ""

def extract_meta(doc):
    metas = {
        (m.get("name") or m.get("property") or "").lower(): (m.get("content") or "").strip()
        for m in doc.xpath("//meta[@name or @property]")
    }
    title = get_text_or_empty(doc, "//title")
    canonical = ""
    can_nodes = doc.xpath(
        "//link[translate(@rel,'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz')='canonical']/@href"
    )
    if can_nodes:
        canonical = can_nodes[0].strip()
    robots = metas.get("robots", "")
    description = metas.get("description", "")
    h1s = [t.strip() for t in doc.xpath("//h1//text()") if t.strip()]
    return {
        "title": title,
        "canonical": canonical,
        "robots": robots,
        "description": description,
        "h1s": h1s,
        "meta_count": len(metas),
    }

def extract_links(doc, base_url: str, site_host: str):
    hrefs = set()
    for node in doc.xpath("//a[@href]"):
        href = (node.get("href") or "").strip()
        if not href or href in ("#",):
            continue
        if href.lower().startswith(("mailto:", "tel:", "javascript:")):
            continue
        absu = urljoin(base_url, href)
        hrefs.add(norm_url(absu))
    internal = {u for u in hrefs if is_internal(u, site_host)}
    external = hrefs - internal
    return internal, external

def extract_links_raw(doc, base_url: str, site_host: str):
    raw_set = set()
    for node in doc.xpath("//a[@href]"):
        href = (node.get("href") or "").strip()
        if not href or href in ("#",):
            continue
        if href.lower().startswith(("mailto:", "tel:", "javascript:")):
            continue
        absu = urljoin(base_url, href)
        p = urlparse(absu)
        absu_raw = urlunparse(((p.scheme or "https").lower(), norm_host(p.netloc), p.path, p.params, p.query, p.fragment))
        if is_internal(absu_raw, site_host):
            raw_set.add(absu_raw)
    return raw_set

def extract_html_canonical(doc):
    can_nodes = doc.xpath(
        "//link[translate(@rel,'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz')='canonical']/@href"
    )
    return (can_nodes[0].strip() if can_nodes else "") or ""

def extract_header_canonical(headers: dict) -> str:
    link = headers.get("Link") or headers.get("link") or ""
    if not link:
        return ""
    parts = [p.strip() for p in link.split(",")]
    for p in parts:
        m = re.search(r"<([^>]+)>\s*;\s*rel\s*=\s*\"?canonical\"?", p, flags=re.I)
        if m:
            return m.group(1).strip()
    return ""

def _normalize_robots_header_value(val: str) -> str:
    if not val:
        return ""
    v = re.sub(r"\s+", " ", val.strip().lower())
    v = re.sub(r"\s*([,;:])\s*", r"\1", v)
    return v

def extract_x_robots_tag(headers: dict) -> str:
    for k in ("x-robots-tag", "X-Robots-Tag", "X-ROBOTS-TAG"):
        if k in headers:
            return _normalize_robots_header_value(headers[k])
    for k, v in headers.items():
        if str(k).lower() == "x-robots-tag":
            return _normalize_robots_header_value(v)
    return ""

# ----------------------------
# Fetching (no-JS and JS)
# ----------------------------
def fetch_without_js(url: str, headers: dict):
    r = requests.get(url, headers=headers, timeout=REQ_TIMEOUT, allow_redirects=True)
    doc = lxml.html.fromstring(r.text)
    return {
        "final_url": r.url,
        "status": r.status_code,
        "headers": dict(r.headers),
        "doc": doc,
        "html_len": len(r.text),
    }

def make_chrome(ua: str):
    os.makedirs("/tmp/chrome-seo", exist_ok=True)

    chrome_opts = ChromeOptions()
    chrome_opts.add_argument("--headless=new")
    chrome_opts.add_argument("--no-sandbox")
    chrome_opts.add_argument("--disable-dev-shm-usage")
    chrome_opts.add_argument("--disable-gpu")
    chrome_opts.add_argument("--remote-debugging-port=0")
    chrome_opts.add_argument("--user-data-dir=/tmp/chrome-seo")
    chrome_opts.add_argument("--no-first-run")
    chrome_opts.add_argument("--no-default-browser-check")
    chrome_opts.add_argument("--window-size=1366,768")
    chrome_opts.add_argument(f"--user-agent={ua}")
    chrome_opts.set_capability("goog:loggingPrefs", {"performance": "ALL"})

    service = ChromeService()
    driver = webdriver.Chrome(service=service, options=chrome_opts)
    driver.set_page_load_timeout(45)
    driver.set_script_timeout(30)
    return driver

def _extract_main_document_from_perf_logs(driver, final_url: str):
    status = None
    headers = {}
    try:
        logs = driver.get_log("performance")
    except Exception:
        return None, {}

    for entry in reversed(logs):  # newest first
        try:
            msg = json.loads(entry["message"])["message"]
            if msg.get("method") != "Network.responseReceived":
                continue
            params = msg.get("params", {})
            r = params.get("response", {})
            if (params.get("type") == "Document") and r:
                url_match = (r.get("url") == final_url)
                if url_match or status is None:
                    status = r.get("status")
                    headers = r.get("headers") or {}
                    if url_match:
                        break
        except Exception:
            continue
    return status, headers

def fetch_with_js(url: str, ua: str):
    driver = make_chrome(ua)
    try:
        driver.get(url)
        time.sleep(2.0)  # brief wait; bump if SPA-heavy

        html = driver.page_source
        cur = driver.current_url
        status, headers = _extract_main_document_from_perf_logs(driver, cur)

        doc = lxml.html.fromstring(html)
        return {
            "final_url": cur,
            "status": status,
            "headers": headers,
            "doc": doc,
            "html_len": len(html),
        }
    finally:
        driver.quit()
