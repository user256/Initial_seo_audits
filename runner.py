#!/usr/bin/env python3
"""
Runner: orchestrates the SEO parity & consolidation checks.
Splits responsibilities across:
  - fetch_render.py  (network fetches & HTML extraction)
  - seo_checks.py    (robots/consolidation/case/404/link checks)
  - file_io.py       (logging helpers & file naming)

Usage:
  python runner.py --url https://example.com --user-agent "my-UA" --max-links 150
  # Export all URLs from XML sitemaps (incl. hreflang alternates) with robots.txt crawlability:
  python runner.py --url https://example.com -A "my-UA" --export-sitemaps-csv out.csv
"""
import argparse
import re
import time

from urllib.parse import urljoin, urlparse, urlunparse

import requests
import lxml.html

from fetch_render import (
    norm_host, norm_url, is_internal,
    extract_meta, extract_links, extract_links_raw,
    extract_header_canonical, extract_x_robots_tag,
    fetch_without_js, fetch_with_js,
)
from seo_checks import (
    robots_parser, is_crawlable,
    check_http_to_https, check_www_canon,
    pick_case_test_path, check_case_variants,
    check_custom_404, get_status_detail,
    compare_sets,
)
from file_io import FileLogger, make_logfile, pretty_header

# ----------------------------
# Defaults (fallbacks if CLI not provided)
# ----------------------------
DEFAULT_URL = "http://whiskipedia.com"
DEFAULT_UA  = "paradise-crawler"

# General config
REQ_TIMEOUT = 20
MAX_LINKS_TO_CHECK = 120  # cap for link parity / robots/status checks


def main():
    parser = argparse.ArgumentParser(
        description="SEO parity & consolidation checker (JS vs no-JS) with robots.txt validation."
    )
    parser.add_argument("--url", dest="url", help="Homepage URL to test.")
    parser.add_argument("--user-agent", "-A", dest="user_agent", help="User-Agent string to use.")
    parser.add_argument("--max-links", type=int, default=MAX_LINKS_TO_CHECK, help="Limit internal links checked")
    # Optional path; if provided without a value, default to 'sitemaps.csv'
    parser.add_argument(
        "--export-sitemaps-csv",
        nargs="?",
        const="sitemaps.csv",
        help="Export URLs from XML sitemaps (+hreflang) with robots.txt crawlability. "
             "If no path is given, defaults to 'sitemaps.csv'."
    )
    args = parser.parse_args()

    ua = (args.user_agent or "").strip() or DEFAULT_UA
    start_url = (args.url or "").strip() or DEFAULT_URL

    if not re.match(r"^https?://", start_url, re.I):
        start_url = "http://" + start_url

    logpath = make_logfile(start_url)
    logger = FileLogger(logpath)
    logger.log(f"[INFO] Logging results to {logpath}")
    logger.log(f"[INFO] Using URL: {start_url}")
    logger.log(f"[INFO] Using User-Agent: {ua}")

    requested_csv = getattr(args, "export_sitemaps_csv", "exported_urls.csv")

    headers = {
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }

    # ------------------------
    # BASIC FETCHES
    # ------------------------
    pretty_header(logger, "1) Fetching WITHOUT JavaScript")
    nojs = fetch_without_js(start_url, headers)
    logger.log(f"Final URL: {nojs['final_url']}  |  Status: {nojs['status']}  |  HTML length: {nojs['html_len']:,}")

    pretty_header(logger, "2) Fetching WITH JavaScript")
    js = fetch_with_js(start_url, ua)
    js_status_str = js['status'] if js['status'] is not None else "(unknown)"
    logger.log(f"Final URL: {js['final_url']}  |  Status: {js_status_str}  |  HTML length: {js['html_len']:,}")

    # Determine canonical site root (prefer JS final URL if present)
    final_url = js["final_url"] or nojs["final_url"] or start_url
    final_parsed = urlparse(final_url)
    site_host = norm_host(final_parsed.netloc)
    site_root = urlunparse((final_parsed.scheme or "https", final_parsed.netloc, "/", "", "", ""))

    # ------------------------
    # META & LINKS
    # ------------------------
    meta_nojs = extract_meta(nojs["doc"])
    meta_js   = extract_meta(js["doc"])

    # Header-level signals (parity on main page)
    header_canon_nojs = extract_header_canonical(nojs["headers"])
    header_canon_js   = extract_header_canonical(js["headers"])
    xrobots_nojs      = extract_x_robots_tag(nojs["headers"])
    xrobots_js        = extract_x_robots_tag(js["headers"])

    internal_nojs, _ = extract_links(nojs["doc"], nojs["final_url"], site_host)
    internal_js, _   = extract_links(js["doc"],  js["final_url"],  site_host)

    # RAW internal links (preserve trailing slashes) for camel-case tests
    internal_raw_nojs = extract_links_raw(nojs["doc"], nojs["final_url"], site_host)
    internal_raw_js   = extract_links_raw(js["doc"],  js["final_url"],  site_host)
    internal_raw_union = internal_raw_nojs | internal_raw_js

    only_in_nojs, only_in_js = compare_sets(internal_nojs, internal_js)

    # ------------------------
    # robots.txt
    # ------------------------
    robots_url = urljoin(site_root, "/robots.txt")
    # Fetch robots parser and the raw text for logging
    rp, robots_ok, robots_text = robots_parser(robots_url, ua)

    # ------------------------
    # CONSOLIDATION
    # ------------------------
    https_check = check_http_to_https(site_root, headers)
    www_check   = check_www_canon(site_root, headers)

    # camel/case variants (from RAW links so trailing slash is preserved)
    variants     = pick_case_test_path(internal_raw_union, site_root)
    case_results = check_case_variants(variants, headers) if variants else {"skipped": True}

    notfound_check = check_custom_404(site_root, headers)

    # ------------------------
    # ACCESSIBILITY & ROBOTS for internal links
    # ------------------------
    sample_internal = sorted((internal_nojs | internal_js))
    if len(sample_internal) > args.max_links:
        sample_internal = sample_internal[:args.max_links]

    status_details = {u: get_status_detail(u, headers) for u in sample_internal}
    # Safe robots evaluation: allow if no rules were parsed.
    def _robot_ok(u):
        if not rp:
            return True
        if getattr(rp, "entries", None) in (None, []):
            return True
        try:
            return rp.can_fetch(ua, u)
        except Exception:
            return True
    robots_allow   = {u: _robot_ok(u) for u in sample_internal}

    ok_200_count = sum(1 for d in status_details.values() if d.get("status") == 200)
    non200_list  = [(u, d) for u, d in status_details.items() if d.get("status") != 200]
    blocked_list = [u for u, allowed in robots_allow.items() if not allowed]

    # ------------------------
    # REPORTING
    # ------------------------
    pretty_header(logger, "RESULTS — Manual Checks (JS vs No-JS)")
    logger.log("Meta/title/description/canonical/robots parity:")

    logger.log(f" - <title> same: {meta_nojs['title'] == meta_js['title']} | noJS='{meta_nojs['title']}' | JS='{meta_js['title']}'")
    logger.log(f" - <meta name='description'> same: {meta_nojs['description'] == meta_js['description']}")

    # HTML canonical parity
    html_canon_same = True
    if meta_nojs["canonical"] or meta_js["canonical"]:
        from fetch_render import norm_url as _norm
        html_canon_same = _norm(meta_nojs['canonical'], nojs['final_url']) == _norm(meta_js['canonical'], js['final_url'])
    logger.log(f" - HTML <link rel='canonical'> same: {html_canon_same}")
    logger.log(f"   noJS canonical (HTML): {meta_nojs['canonical'] or '(none)'}")
    logger.log(f"   JS   canonical (HTML): {meta_js['canonical'] or '(none)'}")

    # Header canonical (Link rel=canonical) parity
    header_canon_same = True
    if header_canon_nojs or header_canon_js:
        from fetch_render import norm_url as _norm
        header_canon_same = _norm(header_canon_nojs, nojs['final_url']) == _norm(header_canon_js, js['final_url'])
    logger.log(f" - HTTP Link rel='canonical' same: {header_canon_same}")
    logger.log(f"   noJS canonical (HTTP): {header_canon_nojs or '(none)'}")
    logger.log(f"   JS   canonical (HTTP): {header_canon_js   or '(none)'}")

    # Robots meta parity
    logger.log(f" - <meta name='robots'> same: {meta_nojs['robots'] == meta_js['robots']}")
    logger.log(f"   noJS robots (meta): '{meta_nojs['robots'] or '(none)'}'")
    logger.log(f"   JS   robots (meta): '{meta_js['robots']   or '(none)'}'")

    # X-Robots-Tag header parity
    xrobots_same = (xrobots_nojs == xrobots_js)
    logger.log(f" - X-Robots-Tag (HTTP header) same: {xrobots_same}")
    logger.log(f"   noJS X-Robots-Tag: '{xrobots_nojs or '(none)'}'")
    logger.log(f"   JS   X-Robots-Tag: '{xrobots_js   or '(none)'}'")

    logger.log(f" - H1 counts (noJS / JS): {len(meta_nojs['h1s'])} / {len(meta_js['h1s'])}")

    logger.log("\nInternal link parity (normalized, same host incl. www/non-www):")
    logger.log(f" - Count no-JS: {len(internal_nojs)}")
    logger.log(f" - Count JS:    {len(internal_js)}")
    logger.log(f" - Overlap:     {len(internal_nojs & internal_js)}")
    if only_in_nojs:
        logger.log("\nLinks ONLY in NO-JS render:")
        for u in only_in_nojs[:50]:
            logger.log("  - " + u)
        if len(only_in_nojs) > 50:
            logger.log(f"  (+ {len(only_in_nojs)-50} more)")
    if only_in_js:
        logger.log("\nLinks ONLY in JS render:")
        for u in only_in_js[:50]:
            logger.log("  - " + u)
        if len(only_in_js) > 50:
            logger.log(f"  (+ {len(only_in_js)-50} more)")

    pretty_header(logger, "RESULTS — robots.txt")
    logger.log(f"robots.txt URL: {robots_url} | retrieved: {bool(rp)}")
    # Print the first ~40 lines to make debugging crystal-clear
    if robots_text:
        preview = "\n".join(robots_text.splitlines()[:40])
        logger.log("----- robots.txt (preview) -----")
        logger.log(preview)
        logger.log("----- end robots.txt preview -----")
    blocked = [u for u, allowed in robots_allow.items() if not allowed]
    logger.log(f" - Checked {len(sample_internal)} internal links; blocked by robots: {len(blocked)}")
    for u in blocked[:50]:
        logger.log("  - BLOCKED: " + u)
    if len(blocked) > 50:
        logger.log(f"  (+ {len(blocked)-50} more)")

    pretty_header(logger, "RESULTS — URL Consolidation")
    logger.log("HTTP → HTTPS:")
    if "error" in https_check:
        logger.log(f" - Error testing {https_check['tested']}: {https_check['error']}")
    else:
        logger.log(f" - Tested: {https_check['tested']}")
        logger.log(f" - Final:  {https_check['final']}")
        logger.log(f" - Redirects to HTTPS: {https_check['redirects_to_https']}")
        logger.log(f" - Status/History: {https_check['status']} via {https_check['history']}")

    logger.log("\nWWW vs non-WWW consolidation (HTTPS):")
    if "error" in www_check:
        logger.log(f" - Error: {www_check['error']}")
    else:
        logger.log(f" - Bare final: {www_check['https_bare_final']}")
        logger.log(f" - WWW  final: {www_check['https_www_final']}")
        logger.log(f" - Consolidated to same canonical: {www_check['consolidated']}")

    logger.log("\ncamelCase vs lowercase URL handling:")
    if case_results.get("skipped"):
        logger.log(" - Skipped (no suitable lowercase internal path found).")
    else:
        lower = case_results["lower"]
        upper = case_results["upper"]
        camel = case_results["camel"]

        logger.log(f" - Lowercase sample: {lower}")

        logger.log(" - UPPER variant:")
        can_raw_u = upper.get("upper_canonical_raw", {})
        logger.log(f"   · Tested         : {upper['tested']}")
        logger.log(f"   · Final          : {upper.get('final')}")
        logger.log(f"   · Status         : {upper.get('status')}")
        logger.log(f"   · Redirects->lower: {upper.get('redirects_to_lower')}")
        logger.log(f"   · HTML canonical : {can_raw_u.get('html_canonical') or '(none)'}")
        logger.log(f"   · Header Link can: {can_raw_u.get('header_canonical') or '(none)'}")
        logger.log(f"   · Chosen canonical: {upper.get('upper_canonical') or '(none)'}")
        logger.log(f"   · Canon->lower   : {upper.get('canonicalizes_to_lower')}")
        logger.log(f"   · Acceptable     : {upper.get('acceptable')} (redirect OR canonical OR 404)")

        logger.log(" - camel variant (mixed case):")
        can_raw_c = camel.get("upper_canonical_raw", {})
        logger.log(f"   · Tested         : {camel['tested']}")
        logger.log(f"   · Final          : {camel.get('final')}")
        logger.log(f"   · Status         : {camel.get('status')}")
        logger.log(f"   · Redirects->lower: {camel.get('redirects_to_lower')}")
        logger.log(f"   · HTML canonical : {can_raw_c.get('html_canonical') or '(none)'}")
        logger.log(f"   · Header Link can: {can_raw_c.get('header_canonical') or '(none)'}")
        logger.log(f"   · Chosen canonical: {camel.get('upper_canonical') or '(none)'}")
        logger.log(f"   · Canon->lower   : {camel.get('canonicalizes_to_lower')}")
        logger.log(f"   · Acceptable     : {camel.get('acceptable')} (redirect OR canonical OR 404)")

    logger.log("\nCustom 404 behavior:")
    if "error" in notfound_check:
        logger.log(f" - Error testing 404: {notfound_check['error']}")
    else:
        logger.log(f" - Tested: {notfound_check['tested']}  | Final status: {notfound_check.get('status')}  | Proper 404: {notfound_check['ok_is_404']}")

    pretty_header(logger, "RESULTS — Internal Link Accessibility")
    logger.log(f" - {ok_200_count}/{len(status_details)} internal links returned 200 OK")

    if non200_list:
        logger.log(" - Non-200 internal links:")
        for u, d in non200_list[:50]:
            st = d.get("status")
            fin = d.get("final_url") or "-"
            err = d.get("error")
            if err:
                logger.log(f"   · {u}  | status: {st}  | final: {fin}  | error: {err}")
            else:
                logger.log(f"   · {u}  | status: {st}  | final: {fin}")
        if len(non200_list) > 50:
            logger.log(f"   (+ {len(non200_list)-50} more)")

    if blocked_list:
        logger.log("\n - Disallowed by robots.txt for this UA:")
        for u in blocked_list[:50]:
            logger.log(f"   · {u}")
        if len(blocked_list) > 50:
            logger.log(f"   (+ {len(blocked_list)-50} more)")
    else:
        logger.log(" - No internal links disallowed by robots.txt for this UA.")

    # -------------------------------------------------------------------------
    # SITEMAPS — Discover via robots.txt, harvest, robots-check, and export CSV
    # (runs every time; uses --export-sitemaps-csv path if provided, else auto)
    # -------------------------------------------------------------------------
    pretty_header(logger, "SITEMAPS — Discover, Export, and Robots Checks")

    sm_blocked = None  # expose for summary flags below

    try:
        # Lazy import; if module missing, continue gracefully
        from sitemap_export import (
            sitemaps_from_robots, crawl_all_sitemaps,
            evaluate_crawlability, export_csv,
        )

        sm_headers = {
            "User-Agent": ua,
            "Accept": "application/xml,text/xml,application/xhtml+xml;q=0.9,*/*;q=0.8",
        }

        start_sitemaps = sitemaps_from_robots(start_url, headers=sm_headers)
        if not start_sitemaps:
            logger.log("[WARN] No sitemaps discovered via robots.txt and input URL is not a sitemap; skipping sitemap export.")
        else:
            crawled_sitemaps, url_map, url_source = crawl_all_sitemaps(start_sitemaps, headers=sm_headers)

            # Robots-only evaluation for ALL sitemap URLs (no status fetch)
            sitemap_allowed = evaluate_crawlability(start_url, ua, url_map.keys())

            # Decide output filename
            if requested_csv:
                out_csv = requested_csv
            else:
                host_tag = urlparse(start_url).netloc.replace(".", "_").replace(":", "_")
                out_csv = f"sitemaps_{host_tag}.csv"

            # Build rows & export
            rows = []
            for u, info in url_map.items():
                rows.append({
                    "url": u,
                    "hreflangs": info.get("hreflangs") or [],
                    "hrefs": info.get("hrefs") or [],
                    "crawlable": sitemap_allowed.get(u, True),
                    "source_sitemap": url_source.get(u, ""),
                })
            export_csv(out_csv, rows)

            # Log sitemap results
            total_sm = len(crawled_sitemaps)
            total_urls = len(url_map)
            sm_blocked = sum(1 for ok in sitemap_allowed.values() if not ok)

            logger.log(f"[OK] Sitemaps discovered: {total_sm}  | URLs harvested: {total_urls:,}")
            logger.log(f"[OK] CSV written: {out_csv}")
            logger.log(f"[INFO] Robots check on sitemap URLs — blocked: {sm_blocked} / {total_urls}")

    except ImportError:
        logger.log("[WARN] sitemap_export.py not found; skipping sitemap harvest/export. "
                "Add the module to enable this feature.")
    except Exception as e:
        logger.log(f"[WARN] Sitemap harvest/export failed: {e}")


    # ------------------------
    # SUMMARY FLAGS
    # ------------------------


    # Fail if any scraped internal link is not robots-allowed or not 200
    flags = []
    scraped_fail = [
        u for u in sample_internal
        if not robots_allow.get(u, True) or status_details.get(u, {}).get("status") != 200
    ]
    if scraped_fail:
        flags.append(f"{len(scraped_fail)} scraped internal links fail robots allow and/or 200 status.")

    # If sitemap harvest ran, include robots blocks from sitemap URLs
    if sm_blocked is not None and sm_blocked > 0:
        flags.append(f"{sm_blocked} sitemap URLs are disallowed by robots.txt for UA '{ua}'.")

    pretty_header(logger, "SUMMARY FLAGS")

    if not meta_nojs["title"] or not meta_js["title"]:
        flags.append("Missing <title> in one or both renders.")
    if meta_nojs["title"] != meta_js["title"]:
        flags.append("<title> differs between JS and non-JS.")
    if meta_nojs["description"] != meta_js["description"]:
        flags.append("Meta description differs between JS and non-JS.")

    # HTML canonical parity flag
    from fetch_render import norm_url as _norm
    c_no = _norm(meta_nojs["canonical"], nojs["final_url"]) if meta_nojs["canonical"] else ""
    c_js = _norm(meta_js["canonical"], js["final_url"]) if meta_js["canonical"] else ""
    if (c_no or c_js) and (c_no != c_js):
        flags.append("HTML canonical URL differs between JS and non-JS.")

    # Header canonical parity flag
    hc_no = _norm(header_canon_nojs, nojs["final_url"]) if header_canon_nojs else ""
    hc_js = _norm(header_canon_js,   js["final_url"])   if header_canon_js   else ""
    if (hc_no or hc_js) and (hc_no != hc_js):
        flags.append("HTTP Link rel=canonical differs between JS and non-JS.")

    # Robots parity flags
    if meta_nojs["robots"] != meta_js["robots"]:
        flags.append("Robots meta differs between JS and non-JS.")
    if xrobots_nojs != xrobots_js:
        flags.append("X-Robots-Tag headers differ between JS and non-JS.")

    if only_in_js:
        flags.append(f"{len(only_in_js)} internal links appear only when JS is enabled.")
    blocked_count = sum(1 for allowed in robots_allow.values() if not allowed)
    if blocked_count:
        flags.append(f"{blocked_count} internal links are disallowed by robots.txt for UA '{ua}'.")

    if "redirects_to_https" in https_check and not https_check["redirects_to_https"]:
        flags.append("HTTP does not redirect to HTTPS.")
    if "consolidated" in www_check and not www_check["consolidated"]:
        flags.append("WWW vs non-WWW do not consolidate to one canonical destination.")

    if not case_results.get("skipped"):
        if not case_results.get("any_acceptable"):
            flags.append("Uppercase/mixed-case variants neither redirect nor canonicalize to lowercase and don’t 404 (potential duplicate).")

    if notfound_check.get("ok_is_404") is False:
        flags.append("Custom 404 does not return HTTP 404.")

    if flags:
        for f in flags:
            logger.log(" - " + f)
    else:
        logger.log("No issues detected by automated checks.")

    logger.close()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        raise SystemExit(130)