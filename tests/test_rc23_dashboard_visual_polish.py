"""Dashboard UX polish: read-only rendering and navigation without consent changes."""
from pathlib import Path
import shutil

import pytest
from bs4 import BeautifulSoup
from fastapi.testclient import TestClient
from achillesapi.dashboard.server import create_app

STATIC = Path(__file__).resolve().parents[1] / 'src' / 'achillesapi' / 'dashboard' / 'static'


def test_assets_and_guided_card_are_integrated(tmp_path):
    for page in ('index.html', 'job-viewer.html', 'job-ai.html'):
        document = BeautifulSoup((STATIC / page).read_text(encoding='utf8'), 'html.parser')
        links = [link.get('href','') for link in document.select('link[rel=stylesheet]')]
        assert any('dashboard-polish.css' in link for link in links), page
        assert links[-1].startswith('/assets/rc27-polish.css') if page == 'index.html' else links[-1].startswith('/assets/dashboard-polish.css')
    js = (STATIC / 'issue-guide.js').read_text(encoding='utf8')
    assert 'issue-guide__route' in js
    assert 'issue-guide__steps' in js
    assert 'issue-guide__instruction-label' in js
    assert 'Il messaggio non identifica un campo preciso' in js
    assert 'innerHTML' not in js
    assert 'fetch(' not in js
    with TestClient(create_app(tmp_path / 'storage'), base_url='http://127.0.0.1:8766') as client:
        stylesheet = client.get('/assets/dashboard-polish.css')
        assert stylesheet.status_code == 200
        assert '.issue-go--primary' in stylesheet.text
        assert 'dashboard-polish.css' in client.get('/').text


def test_guidance_navigation_and_mobile_contrast_in_chromium():
    playwright_module = pytest.importorskip('playwright.sync_api')
    chromium = shutil.which('chromium') or shutil.which('chromium-browser')
    if not chromium:
        pytest.skip('Optional Chromium not installed in this test runner')
    from playwright.sync_api import sync_playwright

    doc = BeautifulSoup((STATIC / 'index.html').read_text(encoding='utf8'), 'html.parser')
    for tag in doc.select('script[src],link[rel=stylesheet]'):
        tag.decompose()
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(executable_path=chromium, headless=True, args=['--no-sandbox'])
        try:
            for width, height in ((1440, 900), (390, 844)):
                page = browser.new_page(viewport={'width': width, 'height': height})
                problems = []
                page.on('pageerror', lambda error: problems.append(str(error)))
                page.set_content(str(doc))
                for name in ('style.css', 'ui-refactor.css', 'workspace-ui.css', 'dashboard-polish.css'):
                    page.add_style_tag(content=(STATIC / name).read_text(encoding='utf8'))
                page.add_script_tag(content=(STATIC / 'issue-guide.js').read_text(encoding='utf8'))
                page.evaluate("window.AchillesIssueGuide.report('Errore non classificato', 'suiteStatus')")
                panel = page.locator('#suiteStatus__guidance')
                assert panel.locator('.issue-guide__route-main').inner_text() == 'Suite completa'
                assert panel.locator('.issue-guide__route-detail').inner_text() == 'Autorizzazioni e impostazioni'
                assert panel.locator('.issue-guide__steps li').count() >= 2
                panel.locator('button[data-issue-go="fullSuite"]').click()
                assert page.evaluate('window.location.hash') == '#fullSuite'
                assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
                page.evaluate("window.AchillesIssueGuide.renderList([{label:'PATCH', message:'Sonde JSON PATCH richiedono campi'}], 'suiteStatus')")
                assert page.locator('#suiteStatus__guidance button[data-issue-go="massAssignmentPanel"]').count() == 1
                assert not problems, problems
                page.close()
        finally:
            browser.close()
