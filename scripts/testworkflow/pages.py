#!/usr/bin/env python3
"""Bounded real HTTPS page visits through the owned OpenWrt proxy."""
import argparse
import asyncio
import json
from pathlib import Path
import re
import sys
import time
from urllib.parse import urlsplit


async def visit(args, result):
    from playwright.async_api import async_playwright
    hosts = set()
    async with async_playwright() as p:
        browser = await p.chromium.launch(proxy={"server": args.proxy},
            args=["--disable-quic", "--disable-background-networking", "--disable-component-update"])
        try:
            # First/repeat share the browser HTTP cache, while DNS replay below
            # is measured separately by the router controller.
            for site in ("https://www.qq.com/", "https://www.taobao.com/"):
                context = await browser.new_context(ignore_https_errors=False)
                for phase in ("first", "repeat"):
                    page = await context.new_page()
                    failures = []
                    responses = []
                    def request_seen(request):
                        host = urlsplit(request.url).hostname
                        if host:
                            hosts.add(host)
                    page.on("request", request_seen)
                    page.on("requestfailed", lambda r: failures.append({"host": urlsplit(r.url).hostname,
                                                                       "error": r.failure}))
                    page.on("response", lambda r: responses.append(r.status))
                    start = time.monotonic()
                    row = {"profile": args.profile, "site": site, "phase": phase}
                    try:
                        response = await page.goto(site, wait_until="domcontentloaded", timeout=45000)
                        row["dom_ready_seconds"] = time.monotonic() - start
                        if response is None or response.status >= 400:
                            raise RuntimeError("main document did not return a successful response")
                        row["http_status"] = response.status
                        await page.wait_for_timeout(10000)
                        await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                        await page.wait_for_timeout(2000)
                        timing = await page.evaluate("performance.getEntriesByType('navigation')[0]?.toJSON()")
                        row["navigation_timing"] = timing
                        row["status"] = "passed"
                        await page.screenshot(path=str(args.output / (urlsplit(site).hostname + "-" + phase + ".png")),
                                              full_page=False, timeout=10000)
                    except Exception as e:
                        row["status"] = "failed"
                        row["error"] = str(e)
                    row.update({"seconds": time.monotonic() - start, "requests_failed": len(failures),
                                "responses": len(responses), "request_failures": failures})
                    result["measurements"].append(row)
                    await page.close()
                await context.close()
        finally:
            await browser.close()
    (args.output / "hosts.json").write_text(json.dumps(sorted(hosts), indent=2) + "\n")
    result["checks"].append({"name": "four real page navigations",
        "status": "passed" if len(result["measurements"]) == 4 and all(r["status"] == "passed" for r in result["measurements"]) else "failed",
        "detail": "QQ/Taobao first and repeat; subresource failures remain visible in each sample"})


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--proxy", required=True)
    p.add_argument("--profile", choices=("full", "minimal"), required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--commit", required=True)
    a = p.parse_args()
    proxy = urlsplit(a.proxy)
    if proxy.scheme != "http" or proxy.hostname != "127.0.0.1" or not proxy.port or proxy.username or proxy.password:
        p.error("proxy must be an owned loopback HTTP endpoint")
    if not re.fullmatch(r"[0-9a-f]{40}", a.commit):
        p.error("commit must be a full SHA")
    a.output.mkdir(parents=True, exist_ok=False)
    result = {"schema_version": 1, "suite": "pages-" + a.profile, "source_commit": a.commit,
              "status": "failed", "environment": {"proxy": "owned SSH loopback forward"}, "checks": [],
              "measurements": [], "artifacts": [], "limitations": [
                  "Origin DNS/TCP executes on the router; browser rendering executes on the runner.",
                  "HTTPS certificates are validated. Origin TCP is IPv4; this does not prove IPv6 website egress.",
                  "Two visits per site describe this run; public content and CDN behavior vary."]}
    try:
        asyncio.run(visit(a, result))
        if result["checks"] and all(c["status"] == "passed" for c in result["checks"]):
            result["status"] = "passed"
    except Exception as e:
        result["checks"].append({"name": "browser execution", "status": "failed", "detail": str(e)})
    finally:
        result["artifacts"] = [f.name for f in a.output.iterdir() if f.is_file()]
        (a.output / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
