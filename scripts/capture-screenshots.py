#!/usr/bin/env python3
"""Capture TrueID UI screenshots using Playwright."""

import os
import sys
import time

from playwright.sync_api import sync_playwright

BASE_URL = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:3000"
OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "screenshots")
os.makedirs(OUT_DIR, exist_ok=True)

ADMIN_USER = "admin"
ADMIN_PASS = "integration12345"

TABS = [
    ("mappings", "Mappings"),
    ("search", "Search"),
    ("conflicts", "Conflicts"),
    ("alerts", "Alerts"),
    ("analytics", "Analytics"),
    ("map", "Net Map"),
    ("subnets", "Subnets"),
    ("switches", "Switches"),
    ("fingerprints", "FPrint"),
    ("dns", "DNS"),
    ("sycope", "Sycope"),
    ("status", "Status"),
]

ADMIN_TABS = [
    ("audit", "Audit"),
]


def screenshot(page, name, full_page=True):
    path = os.path.join(OUT_DIR, f"{name}.png")
    page.screenshot(path=path, full_page=full_page)
    print(f"  captured: {name}.png")


def main():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            viewport={"width": 1920, "height": 1080},
            device_scale_factor=2,
        )
        page = context.new_page()

        # 1. Login page
        print("Capturing login page...")
        page.goto(f"{BASE_URL}/login.html", wait_until="domcontentloaded")
        time.sleep(3)
        screenshot(page, "01-login")

        # 2. Perform login via API (bypass force_password_change UI)
        print("Logging in via API...")
        page.evaluate(f"""
            async () => {{
                const resp = await fetch('/api/auth/login', {{
                    method: 'POST',
                    headers: {{'Content-Type': 'application/json'}},
                    credentials: 'include',
                    body: JSON.stringify({{username: '{ADMIN_USER}', password: '{ADMIN_PASS}'}})
                }});
                return resp.ok;
            }}
        """)
        page.goto(f"{BASE_URL}/", wait_until="domcontentloaded")
        time.sleep(5)

        screenshot(page, "02-dashboard-overview", full_page=False)

        # Helper to switch tabs via JS (avoids collapsed sidebar groups)
        def switch_tab(tab_id):
            page.evaluate(f"""() => {{
                // Show hidden button if needed
                var btn = document.getElementById('tab-btn-{tab_id}');
                if (btn) btn.style.display = '';
                // Expand parent group
                var group = btn ? btn.closest('.tab-group') : null;
                if (group) group.classList.add('expanded');
                // Call app's switchTab
                if (typeof switchTab === 'function') switchTab('{tab_id}');
            }}""")
            time.sleep(3)

        # 3. Each tab
        all_tabs = TABS + ADMIN_TABS
        for idx, (tab_id, tab_name) in enumerate(all_tabs):
            print(f"Capturing {tab_name}...")
            switch_tab(tab_id)

            # For search tab, do a search
            if tab_id == "search":
                search_input = page.query_selector("#search-q")
                if search_input:
                    search_input.fill("jan")
                    search_input.press("Enter")
                    time.sleep(3)

            screenshot(page, f"{idx + 3:02d}-{tab_id}", full_page=False)

        # 4. Integration tabs (hidden by default)
        for tab_id in ["firewall", "siem", "ldap", "notifications"]:
            print(f"Capturing {tab_id}...")
            switch_tab(tab_id)
            screenshot(page, f"20-{tab_id}", full_page=False)

        # 5. Timeline detail — click on first IP in mappings
        print("Capturing timeline detail...")
        switch_tab("mappings")
        ip_link = page.query_selector("#mappings-body tr:first-child td:first-child")
        if ip_link:
            ip_link.click()
            time.sleep(3)
            screenshot(page, "25-timeline-detail", full_page=False)
        else:
            print("  no IP link found in mappings table")

        browser.close()

    print(f"\nAll screenshots saved to: {OUT_DIR}")
    print(f"Total: {len(os.listdir(OUT_DIR))} files")


if __name__ == "__main__":
    main()
