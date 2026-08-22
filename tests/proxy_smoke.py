"""One-off smoke test: does the DE proxy unblock /status/eu-region/?

Reads credentials from .env (same loader as main.py), opens the page through
the Quarkip DE proxy, prints status + a body snippet. Not part of the crawl.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crawl.envfile import load_dotenv
from playwright.sync_api import sync_playwright

load_dotenv()
user = os.environ["VISUALPING_USER"]
pw = os.environ["VISUALPING_PASS"]
proxy = {
    "server": os.environ["PROXY_SERVER"],
    "username": os.environ["PROXY_USER"],
    "password": os.environ["PROXY_PASS"],
}

URL = os.environ["TARGET_URL"].rstrip("/") + "/status/eu-region/"

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True, proxy=proxy)
    ctx = browser.new_context(http_credentials={"username": user, "password": pw})
    page = ctx.new_page()
    resp = page.goto(URL, wait_until="domcontentloaded", timeout=30_000)
    print("status:", resp.status)
    body = page.content()
    print("body length:", len(body))
    print("--- first 600 chars ---")
    print(body[:600])
    browser.close()
