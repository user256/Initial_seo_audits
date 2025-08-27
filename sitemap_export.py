# sitemap_export.py
"""
Sitemap harvesting + robots.txt crawlability + CSV export.

- Pull sitemap URLs from robots.txt
- Recurse through sitemap indexes
- Extract <url><loc> plus xhtml:link hreflang alternates
- Evaluate crawlability for a given UA using robots.txt
- Export CSV: url, hreflangs, hrefs, crawlable, source_sitemap
"""

import csv
import io
import gzip
import re
from typing import Dict, List, Tuple, Iterable, Set
from urllib.parse import urlparse, urljoin, urlunparse

import requests
from lxml import etree

from seo_checks import robots_parser, is_crawlable as rp_can_fetch  # reuse your helpers :contentReference[oaicite:5]{index=5}
from fetch_render import norm_host, norm_url  # consistent URL normalization with the rest of the tool :contentReference[oaicite:6]{index=6}

REQ_TIMEOUT = 20  # mirrors defaults in your codebase

XML_PARSER = etree.XMLParser(ns_clean=True, recover=True, remove_comments=True, resolve_entities=False)

# Accepted namespaces often seen in sitemaps (we'll still interrogate dynamically)
NS_HINTS = {
    'sm': "http://www.sitemaps.org/schemas/sitemap/0.9",
    'xhtml': "http://www.w3.org/1999/xhtml",
    'image': "http://www.google.com/schemas/sitemap-image/1.1",
    'video': "http://www.google.com/schemas/sitemap-video/1.1",
    'news': "http://www.google.com/schemas/sitemap-news/0.9",
}


def _abs(url: str, base: str) -> str:
    return norm_url(urljoin(base, url))  # resolves + normalizes in one place


def _robots_url_for(site_url: str) -> str:
    p = urlparse(site_url)
    host = p.netloc or site_url
    scheme = p.scheme or "https"
    return urlunparse((scheme, host, "/robots.txt", "", "", ""))


def _fetch_bytes(url: str, headers: dict) -> bytes:
    r = requests.get(url, headers=headers, timeout=REQ_TIMEOUT, allow_redirects=True)
    r.raise_for_status()
    data = r.content
    # Support .gz sitemaps or gzipped content-type/encoding
    if url.lower().endswith(".gz") or r.headers.get("Content-Encoding", "").lower() == "gzip":
        try:
            return gzip.decompress(data)
        except OSError:
            # Some servers send already decompressed but keep .gz extension
            return data
    return data


def _parse_xml(content: bytes) -> etree._ElementTree:
    return etree.fromstring(content, parser=XML_PARSER)


def _detect_namespaces(root: etree._Element) -> Dict[str, str]:
    # Merge any present nsmap with common hints (root.nsmap can have None key for default ns)
    ns = dict(NS_HINTS)
    for k, v in (root.nsmap or {}).items():
        if k is None:
            # default ns → treat as 'sm' if it looks like the sitemap ns
            if v and "sitemap" in v:
                ns.setdefault("sm", v)
        else:
            ns[k] = v
    return ns


def extract_from_urlset(root: etree._Element, base_url: str) -> Dict[str, dict]:
    """
    Extract <url><loc> plus any xhtml:link alternates from a <urlset>.
    Returns: { url: {"hreflangs": [...], "hrefs": [...]} }
    """
    ns = _detect_namespaces(root)
    # Try both namespaced and non-namespaced forms
    url_nodes = root.findall(".//{*}url") or root.findall(".//url")
    out = {}

    for u in url_nodes:
        # Explicitly avoid Element truth-testing; check both namespaced and non-namespaced
        loc_node = u.find("./{*}loc")
        if loc_node is None:
            loc_node = u.find("./loc")
        if loc_node is None:
            continue
        if not (loc_node.text or "").strip():
            continue
        loc = _abs(loc_node.text.strip(), base_url)

        # hreflang alternates
        links = []
        hreflangs = []
        # Prefer xhtml ns, but fall back to any rel='alternate' pattern if ns varies
        xhtml_links = u.findall(".//{*}link")  # catch xhtml:link or similarly bound
        for ln in xhtml_links:
            rel = (ln.get("rel") or "").lower()
            hre = (ln.get("hreflang") or "").strip()
            href = (ln.get("href") or "").strip()
            if rel == "alternate" and href:
                links.append(_abs(href, base_url))
                if hre:
                    hreflangs.append(hre)

        out[loc] = {"hreflangs": hreflangs, "hrefs": links}
    return out


def extract_from_sitemapindex(root: etree._Element, base_url: str) -> List[str]:
    """
    Extract nested <sitemap><loc> URLs from a <sitemapindex>.
    """
    # Try both namespaced and non-namespaced forms
    site_nodes = root.findall(".//{*}sitemap") or root.findall(".//sitemap")
    out = []
    for sn in site_nodes:
        loc = sn.find("./{*}loc") or sn.find("./loc")
        if loc is not None and (loc.text or "").strip():
            out.append(_abs(loc.text.strip(), base_url))
    for sn in site_nodes:
        loc = sn.find("./{*}loc")
        if loc is None:
            loc = sn.find("./loc")
        if loc is None:
            continue
        text = (loc.text or "").strip()
        if not text:
            continue
        out.append(_abs(text, base_url))
    return out

def is_index(root: etree._Element) -> bool:
    tag = etree.QName(root.tag).localname.lower()
    return tag == "sitemapindex"


def process_sitemap_url(sitemap_url: str, headers: dict) -> Tuple[List[str], Dict[str, dict]]:
    """
    Returns (nested_sitemaps, url_map).
      - nested_sitemaps: list of more sitemap URLs (if this was an index)
      - url_map: { url: {"hreflangs": [...], "hrefs": [...]} } (if this was a urlset)
    """
    try:
        data = _fetch_bytes(sitemap_url, headers=headers)
    except Exception as e:
        print(f"[WARN] Failed fetching sitemap {sitemap_url}: {e}")
        return [], {}

    try:
        root = _parse_xml(data)
    except Exception as e:
        print(f"[WARN] Invalid XML for {sitemap_url}: {e}")
        return [], {}

    # Decide whether <sitemapindex> or <urlset>
    if is_index(root):
        return extract_from_sitemapindex(root, sitemap_url), {}
    else:
        return [], extract_from_urlset(root, sitemap_url)


def sitemaps_from_robots(site_or_sitemap: str, headers: dict) -> List[str]:
    """
    If input is a direct sitemap URL (contains '.xml' or '.gz'), return that.
    Otherwise fetch robots.txt and collect all 'Sitemap:' lines.
    """
    if re.search(r"\.(xml|gz)(\?.*)?$", site_or_sitemap, flags=re.I):
        return [site_or_sitemap]

    # Resolve to site root
    p = urlparse(site_or_sitemap)
    base = urlunparse(((p.scheme or "https"), p.netloc or p.path, "/", "", "", ""))

    robots_url = _robots_url_for(base)
    try:
        r = requests.get(robots_url, headers=headers, timeout=REQ_TIMEOUT)
        r.raise_for_status()
        sitemaps = []
        for line in r.text.splitlines():
            if line.lower().startswith("sitemap:"):
                sm = line.split(":", 1)[1].strip()
                if sm:
                    sitemaps.append(_abs(sm, base))
        return sorted(set(sitemaps))
    except Exception as e:
        print(f"[WARN] Could not read robots at {robots_url}: {e}")
        return []


def crawl_all_sitemaps(start_sitemaps: Iterable[str], headers: dict, max_to_crawl: int = 50_000) -> Tuple[Set[str], Dict[str, dict], Dict[str, str]]:
    """
    Recursively crawl every sitemap and accumulate URL entries.
    Returns:
      - crawled_sitemaps: set of sitemap URLs fetched
      - url_map: { url: {"hreflangs": [...], "hrefs": [...]} }
      - url_source: { url: source_sitemap_url }  (first seen source)
    """
    queue = list(dict.fromkeys(start_sitemaps))  # de-dup but preserve order
    crawled = set()
    url_map: Dict[str, dict] = {}
    url_source: Dict[str, str] = {}

    while queue and len(crawled) < max_to_crawl:
        sm = queue.pop(0)
        if sm in crawled:
            continue
        nested, urls = process_sitemap_url(sm, headers=headers)
        crawled.add(sm)

        for u, info in urls.items():
            if u not in url_map:
                url_map[u] = info
                url_source[u] = sm

        for ns in nested:
            if ns not in crawled:
                queue.append(ns)

        print(f"[INFO] Processed: {sm}")
        print(f"       ├─ nested discovered: {len(nested)}")
        print(f"       └─ total URLs so far: {len(url_map):,} | queue: {len(queue)}")
    return crawled, url_map, url_source


def evaluate_crawlability(site_or_sitemap: str, ua: str, all_urls: Iterable[str]) -> Dict[str, bool]:
    """
    Build a robots parser for the site root, then check each URL’s permission.
    """
    p = urlparse(site_or_sitemap)
    root = urlunparse(((p.scheme or "https"), p.netloc or p.path, "/", "", "", ""))

    rp, ok = robots_parser(urljoin(root, "/robots.txt"), ua)  # your helper (returns (rp, True/False)) :contentReference[oaicite:7]{index=7}
    allowed: Dict[str, bool] = {}
    for u in all_urls:
        try:
            allowed[u] = rp_can_fetch(rp, ua, u)  # your is_crawlable signature (rp, ua, url) :contentReference[oaicite:8]{index=8}
        except Exception:
            allowed[u] = True  # be permissive on parser errors
    return allowed


def export_csv(out_path: str, rows: List[dict]) -> None:
    fieldnames = ["url", "hreflangs", "hrefs", "crawlable", "source_sitemap"]
    with open(out_path, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow({
                "url": r["url"],
                "hreflangs": "|".join(r.get("hreflangs") or []),
                "hrefs": "|".join(r.get("hrefs") or []),
                "crawlable": "TRUE" if r.get("crawlable") else "FALSE",
                "source_sitemap": r.get("source_sitemap") or "",
            })


def export_sitemaps_csv(site_or_sitemap: str, ua: str, out_csv_path: str) -> Tuple[int, int, str]:
    """
    High-level convenience for CLI integration.
    Returns: (sitemap_count, url_count, out_csv_path)
    """
    headers = {
        "User-Agent": ua,
        "Accept": "application/xml,text/xml,application/xhtml+xml;q=0.9,*/*;q=0.8",
    }

    start_sitemaps = sitemaps_from_robots(site_or_sitemap, headers=headers)
    if not start_sitemaps:
        raise RuntimeError("No sitemap URLs discovered (robots.txt had none and input was not a sitemap).")

    crawled_sitemaps, url_map, url_source = crawl_all_sitemaps(start_sitemaps, headers=headers)

    allowed = evaluate_crawlability(site_or_sitemap, ua, url_map.keys())

    rows = []
    for u, info in url_map.items():
        rows.append({
            "url": u,
            "hreflangs": info.get("hreflangs") or [],
            "hrefs": info.get("hrefs") or [],
            "crawlable": allowed.get(u, True),
            "source_sitemap": url_source.get(u, ""),
        })

    export_csv(out_csv_path, rows)
    return len(crawled_sitemaps), len(url_map), out_csv_path