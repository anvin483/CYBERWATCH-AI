import os

import pytest


@pytest.mark.browser
def test_dashboard_browser_smoke():
    playwright = pytest.importorskip("playwright.sync_api")
    if os.environ.get("RUN_BROWSER_TESTS") != "1":
        pytest.skip("Set RUN_BROWSER_TESTS=1 to run the browser smoke test against the local server")
    with playwright.sync_playwright() as runtime:
        browser = runtime.chromium.launch(headless=True)
        page = browser.new_page()
        page.goto("http://127.0.0.1:5050/login")
        page.get_by_label("Username").fill("admin")
        page.get_by_label("Password").fill(os.environ.get("ADMIN_PASSWORD", "cyberwatch"))
        page.get_by_role("button", name="ENTER DASHBOARD").click()
        page.get_by_role("heading", name="MONITOR THE SITUATION").wait_for()
        assert page.locator("#threat-globe").count() == 1
        assert page.locator("#incident-drawer").count() == 1
        browser.close()
