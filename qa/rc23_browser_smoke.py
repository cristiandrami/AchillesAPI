"""RC23 browser smoke against a *real local FastAPI process*.

Requires Chromium and Playwright installed separately. No target is contacted:
only the dashboard on loopback and an uploaded offline OpenAPI fixture.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.request import urlopen


def main() -> int:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print('SKIP: install playwright and Chromium before running browser QA')
        return 2
    root=Path(__file__).resolve().parents[1]
    spec=root/'tests'/'fixtures'/'independent-api-lab'/'openapi.json'
    with tempfile.TemporaryDirectory(prefix='achilles-rc23-') as tmp:
        env=os.environ.copy();env['PYTHONPATH']=str(root/'src')
        script=('from achillesapi.dashboard.server import create_app; import uvicorn; '
                f'uvicorn.run(create_app({tmp!r}), host="127.0.0.1",port=18766,log_level="error")')
        proc=subprocess.Popen([sys.executable,'-c',script],cwd=root,env=env,
                              stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        try:
            for _ in range(50):
                if proc.poll() is not None:
                    print('Dashboard unexpectedly exited:',proc.stderr.read().decode()[-1500:])
                    return 1
                try:
                    with urlopen('http://127.0.0.1:18766/',timeout=.4) as r:
                        if r.status==200:break
                except OSError:time.sleep(.15)
            else:
                print('Dashboard did not start on loopback')
                return 1
            with sync_playwright() as p:
                browser=p.chromium.launch(headless=True,executable_path='/usr/bin/chromium' if Path('/usr/bin/chromium').is_file() else None,args=['--no-sandbox'])
                page=browser.new_page()
                errors=[]
                page.on('pageerror',lambda exc:errors.append(str(exc)))
                try:
                    page.goto('http://127.0.0.1:18766/',wait_until='networkidle')
                except Exception as exc:
                    if 'ERR_BLOCKED_BY_ADMINISTRATOR' in str(exc):
                        print('SKIP: local browser navigation blocked by host policy; run offline DOM smoke and TestClient integration')
                        browser.close()
                        return 2
                    raise
                page.set_input_files('#specFile',str(spec))
                page.wait_for_function("document.getElementById('autopilotStatus').textContent.includes('operazioni analizzate')",timeout=18000)
                status=page.locator('#autopilotStatus').inner_text()
                checks=page.locator('#autopilotChecks .autopilot-check').count()
                flows=page.locator('#autopilotWorkflows .autopilot-flow').count()
                assert checks>=5,(checks,status)
                assert flows>=1,(flows,status)
                assert not errors,errors
                # Selecting a link must open the corresponding independent section.
                page.locator('#autopilotChecks .autopilot-check button').first.click()
                assert page.url.startswith('http://127.0.0.1:18766/#')
                print(f'PASS browser: {status}; {checks} categorie, {flows} workflow; JS errors=0')
                browser.close()
            return 0
        finally:
            proc.terminate()
            try:proc.wait(timeout=4)
            except subprocess.TimeoutExpired:proc.kill()


if __name__=='__main__':raise SystemExit(main())
