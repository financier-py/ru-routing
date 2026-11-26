"""Opening sites in a real browser and noting every host a page talks to.

The plain scanner sees one HTML file. A browser also runs the scripts, so it
sees the APIs, CDNs and players a page pulls in, and the text a page shows
after them ("not available in your country" often comes from a script).
Comparing the same visit from Russia and from abroad shows which of those
hosts are broken at home, not just whether the page as a whole opened.

Needs Playwright: pip install playwright && playwright install chromium.
"""

import asyncio
import contextlib
import json
import sys
import time
import urllib.parse
from pathlib import Path

from . import probe, scan

PAGE_TIMEOUT = 30_000  # ms for the page itself to arrive
SETTLE = 10_000        # ms for scripts to make their requests; "load" waits for every tracker
TRACE = "https://www.cloudflare.com/cdn-cgi/trace"


def host_of(url):
    return urllib.parse.urlsplit(url).hostname or ""


def user_agent(browser):
    """Headless Chromium names itself HeadlessChrome, and bot checks stop it at the door."""
    major = browser.version.split(".")[0]
    return (f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            f"(KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36")


async def visit(browser, target):
    """Open one site in a fresh context; return what happened as a dict."""
    url = target if "://" in target else f"https://{target}"
    result = {"host": target, "status": None, "error": None, "title": "", "marks": [], "requests": {}}
    hosts, pending = result["requests"], {}

    def stats(request):
        return hosts.setdefault(host_of(request.url), {"ok": 0, "failed": 0, "bytes": 0, "errors": []})

    def started(request):
        if request.url.startswith("http"):
            pending[request] = True
            stats(request)

    async def finished(request):
        if not pending.pop(request, None):
            return
        s = stats(request)
        s["ok"] += 1
        with contextlib.suppress(Exception):  # the page may be gone already
            s["bytes"] += (await request.sizes())["responseBodySize"]

    def failed(request):
        # a page cancels requests it no longer needs (video preloads, beacons): that's not a failure
        if not pending.pop(request, None) or request.failure == "net::ERR_ABORTED":
            return
        s = stats(request)
        s["failed"] += 1
        if request.failure and request.failure not in s["errors"]:
            s["errors"].append(request.failure)

    context = await browser.new_context(locale="ru-RU", user_agent=user_agent(browser))
    page = await context.new_page()
    page.on("request", started)
    page.on("requestfinished", finished)
    page.on("requestfailed", failed)
    start = time.monotonic()
    try:
        response = await page.goto(url, timeout=PAGE_TIMEOUT, wait_until="domcontentloaded")
        result["status"] = response.status if response else None
        with contextlib.suppress(Exception):  # a page that never goes quiet is still a page
            await page.wait_for_load_state("networkidle", timeout=SETTLE)
    except Exception as e:  # noqa: BLE001
        result["error"] = str(e).split("\n")[0][:160]
    result["ms"] = int((time.monotonic() - start) * 1000)
    result["final"] = page.url
    try:
        result["title"] = (await page.title())[:120]
        text = (await page.inner_text("body", timeout=2_000)).lower()
    except Exception:  # noqa: BLE001
        text = ""
    result["marks"] = [kind for kind, words in probe.MARKERS.items() if any(w in text for w in words)]
    if any(t in result["title"].lower() for t in probe.CHALLENGE_TITLES):
        result["marks"].append("challenge")
    for request in pending:  # still waiting when we gave up: a stall
        stats(request)["errors"].append("stalled")
    await context.close()
    return result


async def seen_from(browser):
    context = await browser.new_context()
    page = await context.new_page()
    try:
        await page.goto(TRACE, timeout=15_000)
        text = await page.inner_text("body")
        return next((line[4:] for line in text.splitlines() if line.startswith("loc=")), None)
    except Exception:  # noqa: BLE001
        return None
    finally:
        await context.close()


async def run_async(playwright, todo, done, f, jobs, proxy, executable):
    async with playwright() as p:
        browser = await p.chromium.launch(executable_path=executable,
                                          proxy={"server": proxy} if proxy else None)
        print(f"seen from {await seen_from(browser) or 'unknown'}; {len(todo)} to open, "
              f"{done} already done", file=sys.stderr)
        slots = asyncio.Semaphore(jobs)

        async def one(target):
            async with slots:
                try:
                    record = await visit(browser, target)
                except Exception as e:  # noqa: BLE001 - one odd site must not stop the run
                    record = {"host": target, "status": None, "error": f"scanner: {e}"[:160],
                              "title": "", "marks": [], "requests": {}}
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
            f.flush()
        await asyncio.gather(*(one(t) for t in todo))
        await browser.close()


def run(targets, out, jobs=4, proxy=None, executable=None):
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        sys.exit("The browser check needs Playwright: pip install playwright && playwright install chromium")
    out = Path(out)
    done = set(scan.records(out)) if out.exists() else set()
    todo = [t for t in targets if t not in done]
    with out.open("a", encoding="utf-8") as f:
        asyncio.run(run_async(async_playwright, todo, len(done), f, jobs, proxy, executable))


def broken(s):
    return s["ok"] == 0 and (s["failed"] or s["errors"])


def compare(home, abroad):
    """For one site seen from home and from abroad: (page verdict, hosts broken at home).

    A host counts as broken when nothing from it came through at home while
    abroad it answered. Hosts the page didn't use abroad prove nothing."""
    if not abroad or abroad["error"] or not abroad["status"] or abroad["status"] >= 500 \
            or "challenge" in abroad["marks"]:
        return "unknown", []
    hosts = [h for h, s in home["requests"].items()
             if broken(s) and abroad["requests"].get(h, {}).get("ok")]
    if "challenge" in home["marks"]:
        page = "unknown"
    elif "block" in home["marks"]:
        page = "blocked"
    elif "geo" in home["marks"] and "geo" not in abroad["marks"]:
        page = "geoblocked"
    elif home["error"] or not home["status"]:
        page = "broken"
    elif home["status"] in (403, 451) and abroad["status"] < 400:
        page = "geoblocked"
    else:
        page = "works"
    return page, sorted(hosts)
