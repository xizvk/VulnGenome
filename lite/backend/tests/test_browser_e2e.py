from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[3]
LITE = ROOT / "lite"
BACKEND = LITE / "backend"
BINARIES = ROOT / "work" / "annotation-free-invariants-20261021" / "binaries"
VULNERABLE = BINARIES / "transfer_vulnerable.so"
PATCHED = BINARIES / "transfer_patched.so"
VULNERABLE_SHA256 = "af5b3a669e147a4b9cd1f674c20ec5cbec73d1b54c57d66ac74ede8a26b1dd33"
PATCHED_SHA256 = "f5fc4b99929a4a6c0bb0bc57fc13a5ef495b5110218a87b540ae1fd7f2f0a8fc"
EDGE_CANDIDATES = (
    Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Microsoft/Edge/Application/msedge.exe",
    Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Microsoft/Edge/Application/msedge.exe",
)


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.mark.skipif(not (VULNERABLE.is_file() and PATCHED.is_file()),
                    reason="controlled fixture binaries are unavailable")
def test_browser_upload_displays_actual_engine_result_and_exports(tmp_path: Path, monkeypatch):
    playwright = pytest.importorskip("playwright.sync_api")
    edge = next((path for path in EDGE_CANDIDATES if path.is_file()), None)
    if edge is None:
        pytest.skip("Microsoft Edge executable is unavailable")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    port = _free_port()
    env = os.environ.copy()
    env["VULNGENOME_LITE_DATA_DIR"] = str(tmp_path / "runtime")
    env["PYTHONPATH"] = os.pathsep.join((str(ROOT / "src"), str(BACKEND), env.get("PYTHONPATH", "")))
    server = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(port)],
        cwd=BACKEND, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        import httpx
        base = f"http://127.0.0.1:{port}"
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            if server.poll() is not None:
                pytest.fail(f"local API server exited with code {server.returncode}")
            try:
                if httpx.get(f"{base}/api/v1/health", timeout=1).status_code == 200:
                    break
            except httpx.HTTPError:
                time.sleep(0.25)
        else:
            pytest.fail("local API did not become ready")

        with playwright.sync_playwright() as browser_runtime:
            browser = browser_runtime.chromium.launch(headless=True, executable_path=str(edge))
            page = browser.new_page(accept_downloads=True)
            page.goto(base, wait_until="networkidle")
            assert page.get_by_role("heading", name="Command center").is_visible()
            page.get_by_role("button", name="New analysis", exact=True).click()
            page.locator("#vulnerable-file").set_input_files(str(VULNERABLE))
            page.locator("#patched-file").set_input_files(str(PATCHED))
            page.get_by_role("button", name="Validate pair & analyze").click()
            page.locator("#job-status").wait_for(timeout=15000)
            page.wait_for_function("document.querySelector('#job-status')?.textContent === 'COMPLETED'", timeout=240000)

            hashes = page.locator("#job-hashes").inner_text()
            assert VULNERABLE_SHA256 in hashes
            assert PATCHED_SHA256 in hashes
            assert "POTENTIAL_VIOLATION" in page.locator("#solver-results").inner_text()
            assert "PROPERTY_HOLDS_WITHIN_MODEL" in page.locator("#solver-results").inner_text()
            assert "transfer → sensitive_sink" in page.locator("#inference-result").inner_text()
            assert "sensitive_sink" in page.locator("#functions-view").inner_text()

            page.get_by_role("button", name="Intelligence report").click()
            page.get_by_text("Executive summary").wait_for(timeout=10000)
            assert "LOCAL DETERMINISTIC FALLBACK" in page.locator("#intel-provider").inner_text()
            assert "source-" in page.locator("#intel-sources").inner_text()

            page.get_by_role("button", name="Analysis workbench").click()
            with page.expect_download(timeout=15000) as json_download:
                page.get_by_role("button", name="Export JSON").click()
            json_path = json_download.value.path()
            exported = json.loads(Path(json_path).read_text(encoding="utf-8"))
            assert exported["result"]["verification"]["vulnerable"]["capacity_source"] == "inferred"

            with page.expect_download(timeout=15000) as html_download:
                page.get_by_role("button", name="Export HTML").click()
            html_path = html_download.value.path()
            html_report = Path(html_path).read_text(encoding="utf-8")
            assert "Evidence references" in html_report
            assert "artifact-" in html_report or "source-" in html_report
            browser.close()
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=5)
