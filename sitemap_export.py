# sitemap_export.py
import io
import os
import re
import gzip
import time
import random
from typing import Dict, Iterable, List, Tuple
from urllib.parse import urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter, Retry
from lxml import etree

REQ_TIMEOUT = 45
FETCH_HEADERS = {
    "User-Agent": "paradise-crawler (+sitemap-export)",
    "Accept": "application/xml,text/xml,*/*;q=0.8",
    "Accept-Encoding": "gzip, deflate, br",
}

def _retry_session() -> requests.Session:
    s = requests.Session()
    retries = Retry(
        total=6,
        connect=3,
        read=3,
        backoff_factor=0.6,            # 0.6, 1.2, 2.4, 4.8, ...
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET", "HEAD"]),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retries, pool_connections=10, pool_maxsize=10)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    return s

def _is_probably_html(b: bytes) -> bool:
    sniff = b[:512].lower()
    return b"<html" in sniff or b"<!doctype html" in sniff

def _get_xml(url: str, headers=None, timeout=REQ_TIMEOUT) -> Tuple[bytes, int, str]:
    """Fetch XML or XML.GZ; return (bytes, status_code, content_type)."""
    h = dict(FETCH_HEADERS)
    if headers:
        h.update(headers)
    sess = _retry_session()
    r = sess.get(url, headers=h, timeout=timeout, allow_redirects=True)
    ct = r.headers.get("content-type", "")
    data = r.content
    # If it's a .gz file and server didn't decode, try manual gunzip
    if url.lower().endswith(".gz"):
        try:
            data = gzip.decompress(data)
        except Exception:
            # requests may have already decompressed if Content-Encoding: gzip
            pass
    return data, r.status_code, ct

def _parse_xml(xml_bytes: bytes):
    parser = etree.XMLParser(recover=True, resolve_entities=False, no_network=True)
    return etree.fromstring(xml_bytes, parser=parser)

def _ln(el) -> str:
    """local-name of an element/tag"""
    if isinstance(el.tag, str):
        return el.tag.split('}')[-1] if '}' in el.tag else el.tag
    return ""

def _iter_text(node, xpath: str):
    for el in node.xpath(xpath):
        if isinstance(el, etree._Element):
            t = (el.text or "").strip()
        else:
            t = (str(el) or "").strip()
        if t:
            yield t

def sitemaps_from_robots(start_url: str, headers=None) -> List[str]:
    parsed = urlparse(start_url)
    robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
    h = dict(FETCH_HEADERS)
    if headers:
        h.update(headers)
    try:
        sess = _retry_session()
        r = sess.get(robots_url, headers=h, timeout=REQ_TIMEOUT, allow_redirects=True)
        r.raise_for_status()
        sitemaps = []
        for line in r.text.splitlines():
            if line.lower().startswith("sitemap:"):
                loc = line.split(":", 1)[1].strip()
                if not re.match(r"^https?://", loc, re.I):
                    loc = urljoin(f"{parsed.scheme}://{parsed.netloc}/", loc)
                sitemaps.append(loc)
        # dedupe, preserve order
        seen = set()
        out = []
        for u in sitemaps:
            if u not in seen:
                out.append(u); seen.add(u)
        return out
    except Exception:
        return []

def _parse_urlset(root, base_url: str):
    results = []
    for url_el in root.xpath("//*[local-name()='urlset']/*[local-name()='url']"):
        locs = list(_iter_text(url_el, ".//*[local-name()='loc']/text()"))
        if not locs:
            continue
        loc = urljoin(base_url, locs[0])

        # hreflang alternates (xhtml:link rel=alternate hreflang=… href=…)
        hreflangs, hrefs = [], []
        for link in url_el.xpath(".//*[local-name()='link' and @rel='alternate' and @hreflang and @href]"):
            hreflangs.append(link.get("hreflang"))
            hrefs.append(link.get("href"))
        results.append({"url": loc, "hreflangs": hreflangs, "hrefs": hrefs})
    return results

def _parse_sitemapindex(root, base_url: str):
    children = []
    for sm in root.xpath("//*[local-name()='sitemapindex']/*[local-name()='sitemap']"):
        locs = list(_iter_text(sm, ".//*[local-name()='loc']/text()"))
        if locs:
            children.append(urljoin(base_url, locs[0]))
    return children

def crawl_all_sitemaps(
    start_sitemaps: List[str],
    headers=None,
    max_sitemaps: int = 20000,
    polite_sleep_range: Tuple[float, float] = (0.1, 0.35),
):
    """
    Returns: (crawled_sitemaps, url_map, url_source, debug_info)
      - crawled_sitemaps: set of parsed sitemap URLs
      - url_map: dict url -> {"hreflangs": [...], "hrefs": [...]}
      - url_source: dict url -> source sitemap URL
      - debug_info: list of dicts per-sitemap: {url, kind, status, count, error}
    """
    h = dict(FETCH_HEADERS)
    if headers:
        h.update(headers)
    to_visit = list(dict.fromkeys(start_sitemaps))
    visited, crawled = set(), set()
    url_map, url_source = {}, {}
    debug_info = []

    while to_visit and len(crawled) < max_sitemaps:
        sm_url = to_visit.pop(0)
        if sm_url in visited:
            continue
        visited.add(sm_url)

        # be polite & dodge bot-fight: tiny random sleep
        time.sleep(random.uniform(*polite_sleep_range))

        kind, count, err, status = "unknown", 0, "", 0
        try:
            data, status, ct = _get_xml(sm_url, headers=h)
            if status >= 400:
                err = f"HTTP {status}"
                debug_info.append({"url": sm_url, "kind": kind, "status": status, "count": count, "error": err})
                continue
            if _is_probably_html(data) or ("xml" not in (ct or "").lower()):
                err = "Non-XML response (likely HTML interstitial or challenge)"
                debug_info.append({"url": sm_url, "kind": kind, "status": status, "count": count, "error": err})
                continue

            root = _parse_xml(data)
            root_name = _ln(root).lower()
            if root_name == "sitemapindex" or root.xpath("boolean(//*[local-name()='sitemapindex'])"):
                kind = "index"
                children = _parse_sitemapindex(root, sm_url)
                for child in children:
                    if child not in visited:
                        to_visit.append(child)
                count = len(children)
            else:
                kind = "urlset"
                records = _parse_urlset(root, sm_url)
                for rec in records:
                    u = rec["url"]
                    if u not in url_map:
                        url_map[u] = {"hreflangs": rec["hreflangs"], "hrefs": rec["hrefs"]}
                        url_source[u] = sm_url
                count = len(records)

            crawled.add(sm_url)
            debug_info.append({"url": sm_url, "kind": kind, "status": status, "count": count, "error": err})

        except Exception as e:
            err = f"{type(e).__name__}: {e}"
            debug_info.append({"url": sm_url, "kind": "unknown", "status": status, "count": count, "error": err})
            continue

    return crawled, url_map, url_source, debug_info

def evaluate_crawlability(start_url: str, user_agent: str, urls_iterable: Iterable[str]) -> Dict[str, bool]:
    from seo_checks import robots_parser
    parsed = urlparse(start_url)
    robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
    rp, ok, _txt = robots_parser(robots_url, user_agent)
    def _can(u):
        try:
            if not rp or not getattr(rp, "entries", None):
                return True
            return rp.can_fetch(user_agent, u)
        except Exception:
            return True
    return {u: _can(u) for u in urls_iterable}

def export_csv(path: str, rows: List[dict]):
    import csv, json
    fieldnames = ["url", "hreflangs", "hrefs", "crawlable", "source_sitemap"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow({
                "url": r["url"],
                "hreflangs": json.dumps(r.get("hreflangs") or []),
                "hrefs": json.dumps(r.get("hrefs") or []),
                "crawlable": r.get("crawlable", True),
                "source_sitemap": r.get("source_sitemap", ""),
            })
