#!/usr/bin/env python3
"""Refresh the static thite.site subdomain index."""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import html
import json
import re
import socket
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

USER_AGENT = "thite-site-subdomain-index/1.0"
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
DESC_RE = re.compile(
    r"<meta[^>]+name=[\"']description[\"'][^>]+content=[\"']([^\"']*)[\"']",
    re.I | re.S,
)


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def clean_host(name: str, domain: str) -> str | None:
    host = name.strip().lower().rstrip(".")
    if host.startswith("*."):
        host = host[2:]
    domain = domain.lower().rstrip(".")
    if host == domain or host.endswith(f".{domain}"):
        return host
    return None


def compact_text(value: str | None, limit: int = 180) -> str:
    if not value:
        return ""
    text = html.unescape(re.sub(r"\s+", " ", value)).strip()
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def extract_title(body: bytes) -> str:
    text = body[:300_000].decode("utf-8", "replace")
    match = TITLE_RE.search(text)
    return compact_text(match.group(1) if match else "", 90)


def extract_description(body: bytes) -> str:
    text = body[:300_000].decode("utf-8", "replace")
    match = DESC_RE.search(text)
    return compact_text(match.group(1) if match else "", 180)


def load_json(url: str, timeout: int) -> Any:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return json.load(response)


def certspotter_hosts(domain: str, timeout: int) -> set[str]:
    url = (
        "https://api.certspotter.com/v1/issuances?"
        + urllib.parse.urlencode(
            {"domain": domain, "include_subdomains": "true", "expand": "dns_names"}
        )
    )
    data = load_json(url, timeout)
    hosts: set[str] = set()
    for row in data:
        for name in row.get("dns_names", []):
            host = clean_host(name, domain)
            if host:
                hosts.add(host)
    return hosts


def crtsh_hosts(domain: str, timeout: int) -> set[str]:
    query = urllib.parse.quote(f"%.{domain}")
    data = load_json(f"https://crt.sh/?q={query}&output=json", timeout)
    hosts: set[str] = set()
    for row in data:
        for name in row.get("name_value", "").splitlines():
            host = clean_host(name, domain)
            if host:
                hosts.add(host)
    return hosts


def discover_hosts(domain: str, timeout: int) -> tuple[dict[str, set[str]], list[str]]:
    errors: list[str] = []
    for source, getter in (("certspotter", certspotter_hosts), ("crt.sh", crtsh_hosts)):
        discovered: dict[str, set[str]] = {}
        try:
            for host in getter(domain, timeout):
                discovered.setdefault(host, set()).add(source)
            if discovered:
                return discovered, errors
        except Exception as exc:  # source flakiness should not blank the index
            errors.append(f"{source}: {type(exc).__name__}: {exc}")
    return {}, errors


def resolve_ips(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return []
    return sorted({info[4][0] for info in infos})


def scrub_url(url: str) -> str:
    parts = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def request_url(url: str, timeout: int) -> tuple[int, str, bytes, str]:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return response.status, scrub_url(response.geturl()), response.read(300_000), ""
    except urllib.error.HTTPError as exc:
        return exc.code, scrub_url(exc.geturl()), exc.read(300_000), ""
    except Exception as exc:
        return 0, url, b"", f"{type(exc).__name__}: {exc}"


def classify(status: int, final_url: str) -> str:
    if status in {401, 403} or "cloudflareaccess.com" in final_url:
        return "protected"
    if 200 <= status < 500:
        return "online"
    return "offline"


def probe_host(host: str, sources: set[str], timeout: int) -> dict[str, Any]:
    checked_at = now_iso()
    ips = resolve_ips(host)
    last_error = ""
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        status, final_url, body, error = request_url(url, timeout)
        if not error:
            return {
                "host": host,
                "url": url,
                "final_url": final_url,
                "protocol": scheme,
                "status": status,
                "state": classify(status, final_url),
                "title": extract_title(body) or host,
                "description": extract_description(body),
                "ips": ips,
                "discovered_by": sorted(sources),
                "checked_at": checked_at,
                "error": "",
            }
        last_error = error
    return {
        "host": host,
        "url": f"https://{host}",
        "final_url": "",
        "protocol": "",
        "status": 0,
        "state": "offline",
        "title": host,
        "description": "",
        "ips": ips,
        "discovered_by": sorted(sources),
        "checked_at": checked_at,
        "error": last_error,
    }


def existing_hosts(path: Path, domain: str) -> dict[str, set[str]]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text())
    except Exception:
        return {}
    hosts: dict[str, set[str]] = {}
    for row in data.get("hosts", []):
        host = clean_host(row.get("host", ""), domain)
        if host:
            hosts[host] = set(row.get("discovered_by") or ["previous-scan"])
    return hosts


def sort_key(host: str, domain: str) -> tuple[int, str]:
    return (0 if host == domain else 1, host)


def scan(domain: str, output: Path, timeout: int, workers: int) -> dict[str, Any]:
    generated_at = now_iso()
    discovered, errors = discover_hosts(domain, timeout)
    if not discovered:
        discovered = existing_hosts(output, domain) or {domain: {"seed"}}
        errors.append("using previous scan or root-domain seed")

    hosts = sorted(discovered, key=lambda host: sort_key(host, domain))
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        rows = list(pool.map(lambda host: probe_host(host, discovered[host], timeout), hosts))

    return {
        "domain": domain,
        "generated_at": generated_at,
        "count": len(rows),
        "source_errors": errors,
        "hosts": rows,
    }


def self_test() -> None:
    assert clean_host("*.MAKE.Thite.Site.", "thite.site") == "make.thite.site"
    assert clean_host("nope.example", "thite.site") is None
    assert extract_title(b"<title> Hello\n world </title>") == "Hello world"
    assert scrub_url("https://example.com/path?token=nope#frag") == "https://example.com/path"
    assert classify(403, "https://example.com") == "protected"
    assert classify(200, "https://x.cloudflareaccess.com/login") == "protected"
    assert classify(502, "https://example.com") == "offline"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--domain", default="thite.site")
    parser.add_argument("--output", default="data/subdomains.json", type=Path)
    parser.add_argument("--timeout", default=8, type=int)
    parser.add_argument("--workers", default=8, type=int)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        print("self-test ok")
        return 0

    data = scan(args.domain, args.output, args.timeout, args.workers)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    print(f"wrote {data['count']} hosts to {args.output}")
    for error in data["source_errors"]:
        print(f"warning: {error}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
