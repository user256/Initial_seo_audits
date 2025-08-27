"""
SEO checks: robots, consolidation, case sensitivity, 404s, and link status helpers.
"""
import random
import re
from urllib.parse import urljoin, urlparse, urlunparse
import requests

import requests
import lxml.html
from urllib import robotparser as urllib_robotparser

from fetch_render import extract_html_canonical, extract_header_canonical, norm_url, norm_host

REQ_TIMEOUT = 20

# ----------------------------
# robots.txt
# ----------------------------
def robots_parser(robots_url: str, ua: str):
    """
    Fetch and parse robots.txt, and also return the raw text so callers can log it.
    Returns: (rp, ok, raw_text)
    """
    rp = urllib_robotparser.RobotFileParser()
    rp.set_url(robots_url)
    raw = ""
    try:
        # Fetch ourselves so we can log the content, then parse it.
        r = requests.get(robots_url, headers={"User-Agent": ua}, timeout=REQ_TIMEOUT, allow_redirects=True)
        r.raise_for_status()
        raw = r.text or ""
        rp.parse(raw.splitlines())
        return rp, True, raw
    except Exception:
        return None, False, raw

def is_crawlable(rp, ua: str, url: str) -> bool:
    try:
        # If parser missing or parsed nothing, treat as allow-all.
        if rp is None:
            return True
        if getattr(rp, "entries", None) in (None, []):
            return True
        return rp.can_fetch(ua, url)
    except Exception:
        return True  # if parser fails, assume allowed

# ----------------------------
# Consolidation helpers
# ----------------------------
def check_http_to_https(root_url: str, headers: dict):
    p = urlparse(root_url)
    http_url = urlunparse(("http", p.netloc, p.path or "/", "", "", ""))
    try:
        r = requests.get(http_url, headers=headers, timeout=REQ_TIMEOUT, allow_redirects=True)
        final = urlparse(r.url)
        return {
            "tested": http_url,
            "final": r.url,
            "redirects_to_https": final.scheme == "https",
            "status": r.status_code,
            "history": [h.status_code for h in r.history],
        }
    except Exception as e:
        return {"tested": http_url, "error": str(e), "redirects_to_https": False}

def check_www_canon(root_url: str, headers: dict):
    p = urlparse(root_url)
    host = p.netloc
    bare = norm_host(host)
    www_host = f"www.{bare}"
    https_bare = urlunparse(("https", bare, "/", "", "", ""))
    https_www = urlunparse(("https", www_host, "/", "", "", ""))
    try:
        rb = requests.get(https_bare, headers=headers, timeout=REQ_TIMEOUT, allow_redirects=True)
        rw = requests.get(https_www, headers=headers, timeout=REQ_TIMEOUT, allow_redirects=True)
        return {
            "https_bare_final": rb.url,
            "https_www_final": rw.url,
            "consolidated": norm_url(rb.url) == norm_url(rw.url),
        }
    except Exception as e:
        return {"error": str(e), "consolidated": False}

# --------- camelCase test utilities (preserve original path) ----------
def _alternate_camel(s: str) -> str:
    out = []
    i = 0
    for ch in s:
        if ch.isalpha():
            out.append(ch.upper() if i % 2 == 0 else ch.lower())
            i += 1
        else:
            out.append(ch)
    return "".join(out)

def build_case_variants_from_lower(lower_url: str) -> dict:
    p = urlparse(lower_url)
    path = p.path or "/"
    path_upper = "".join(ch.upper() if ch.isalpha() else ch for ch in path)
    path_camel = _alternate_camel(path)

    upper_url = urlunparse((p.scheme, p.netloc, path_upper, p.params, p.query, p.fragment))
    camel_url = urlunparse((p.scheme, p.netloc, path_camel, p.params, p.query, p.fragment))
    return {"lower_original": lower_url, "upper": upper_url, "camel": camel_url}

def _inspect_single_variant(variant_url: str, lower_url: str, headers: dict) -> dict:
    out = {
        "tested": variant_url,
        "final": None,
        "status": None,
        "redirects_to_lower": None,
        "upper_canonical_raw": {"html_canonical": "", "header_canonical": "", "chosen_canonical": ""},
        "upper_canonical": "",
        "canonicalizes_to_lower": False,
        "acceptable": False,
        "error": None,
    }
    try:
        r = requests.get(variant_url, headers=headers, timeout=REQ_TIMEOUT, allow_redirects=True)
        out["final"] = r.url
        out["status"] = r.status_code

        redirects_to_lower = norm_url(r.url) == norm_url(lower_url)
        out["redirects_to_lower"] = redirects_to_lower

        html_canonical = ""
        header_canonical = ""
        chosen_canonical = ""

        if not redirects_to_lower:
            header_canonical = extract_header_canonical(r.headers)
            ctype = r.headers.get("Content-Type", "")
            if "text/html" in ctype and r.text:
                try:
                    doc = lxml.html.fromstring(r.text)
                    html_canonical = extract_html_canonical(doc)
                except Exception:
                    pass
            chosen_canonical = header_canonical or html_canonical or ""

        c_norm = norm_url(chosen_canonical, base=r.url) if chosen_canonical else ""
        canonicalizes_to_lower = (bool(c_norm) and c_norm == norm_url(lower_url))

        out["upper_canonical_raw"] = {
            "html_canonical": html_canonical,
            "header_canonical": header_canonical,
            "chosen_canonical": chosen_canonical,
        }
        out["upper_canonical"] = c_norm
        out["canonicalizes_to_lower"] = canonicalizes_to_lower

        out["acceptable"] = bool(redirects_to_lower or canonicalizes_to_lower or r.status_code == 404)
        return out
    except Exception as e:
        out["error"] = str(e)
        return out

def pick_case_test_path(internal_links_raw, site_root: str):
    candidates = []
    root_host = urlparse(urlunparse((urlparse(site_root).scheme, norm_host(urlparse(site_root).netloc), "", "", "", ""))).netloc

    for u in internal_links_raw:
        p = urlparse(u)
        if norm_host(p.netloc) != root_host:
            continue
        path = p.path or "/"
        if path == "/" or len(path) > 60:
            continue
        if re.fullmatch(r"/[a-z0-9/\-_]*", path):
            candidates.append(u)

    if not candidates:
        return None

    candidates.sort(key=lambda x: len(urlparse(x).path))
    lower_original = candidates[0]
    return build_case_variants_from_lower(lower_original)

def check_case_variants(variants: dict, headers: dict):
    if not variants:
        return {"skipped": True}

    lower = variants["lower_original"]
    upper_res = _inspect_single_variant(variants["upper"], lower, headers)
    camel_res = _inspect_single_variant(variants["camel"], lower, headers)

    return {
        "lower": lower,
        "upper": upper_res,
        "camel": camel_res,
        "all_acceptable": bool(upper_res.get("acceptable") and camel_res.get("acceptable")),
        "any_acceptable": bool(upper_res.get("acceptable") or camel_res.get("acceptable")),
        "skipped": False,
    }

def check_custom_404(root_url: str, headers: dict):
    p = urlparse(root_url)
    import random
    bogus = urlunparse((p.scheme, p.netloc, f"/__crawler-404-test-{random.randint(10_000, 99_999)}", "", "", ""))
    try:
        r = requests.get(bogus, headers=headers, timeout=REQ_TIMEOUT, allow_redirects=False)
        if 300 <= r.status_code < 400 and "Location" in r.headers:
            r2 = requests.get(urljoin(bogus, r.headers["Location"]), headers=headers,
                              timeout=REQ_TIMEOUT, allow_redirects=False)
            return {"tested": bogus, "status": r2.status_code, "ok_is_404": r2.status_code == 404}
        return {"tested": bogus, "status": r.status_code, "ok_is_404": r.status_code == 404}
    except Exception as e:
        return {"tested": bogus, "error": str(e), "ok_is_404": False}

def get_status_detail(url: str, headers: dict) -> dict:
    try:
        r = requests.head(url, headers=headers, timeout=REQ_TIMEOUT, allow_redirects=True)
        if r.status_code in (405, 501) or r.status_code >= 400:
            r = requests.get(url, headers=headers, timeout=REQ_TIMEOUT, allow_redirects=True)
        return {"status": r.status_code, "final_url": r.url, "error": None}
    except Exception as e:
        return {"status": None, "final_url": None, "error": str(e)}

# ----------------------------
# Comparisons
# ----------------------------
def compare_sets(a: set, b: set):
    return sorted(a - b), sorted(b - a)
