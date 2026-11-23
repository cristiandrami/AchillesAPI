"""Presentation-only RC9 translation and UX regressions."""
import json
import re
from pathlib import Path

import pytest
from bs4 import BeautifulSoup
from fastapi.testclient import TestClient

from achillesapi.dashboard.server import create_app

ASSETS = Path(__file__).resolve().parents[1] / 'src' / 'achillesapi' / 'dashboard' / 'static'


def _catalog():
    source=(ASSETS/'i18n-catalog.js').read_text(encoding='utf-8')
    return json.loads(source.split('window.AchillesUILocales = ',1)[1].rstrip().removesuffix(';'))


@pytest.mark.parametrize('lang', ['en', 'es', 'fr'])
def test_language_dictionaries_cover_the_safety_sensitive_controls(lang):
    translated=_catalog()[lang]
    assert len(translated) >= 400
    for original in (
        "Testa un'API in cinque passaggi",
        'Avvia suite completa',
        'Confermo di avere l\'autorizzazione per questo target e perimetro',
        'Autorizzo espressamente questa POST, la GET e la DELETE sul target/scope indicati sopra.',
        'Matrice autorizzazioni: crea o importa regole JSON',
        'Avvia test del workflow scelto',
        'Dossier AI completo',
        'Identità utilizzate · profili auth.yaml',
    ):
        assert translated.get(original), (lang, original)


def test_italian_is_source_and_main_layout_is_covered():
    assert set(_catalog()) == {'it','en','es','fr'}
    index=BeautifulSoup((ASSETS/'index.html').read_text(encoding='utf-8'),'html.parser')
    assert index.html['lang']=='it'
    assert _catalog()['it']['skipped']=='Saltato'
    assert _catalog()['it']['complete']=='Completato'
    catalog=_catalog()['en']
    ui_strings={str(node).strip() for node in index.strings
                if node.parent.name not in {'style','script','code','pre'} and str(node).strip()}
    ignored={'ACHILLES','API','A','AI','auto-assess','ai-analyze','ai-correlate','id',
             'SQLi Error-Based','SQLi Boolean-Based','NoSQL operator injection',
             'SSTI / Template expressions','XPath injection','LDAP filter injection',
             'CRLF / Header injection','1','2','3','4','5','★','◎',','}
    missing=ui_strings-set(catalog)-ignored
    # The untranslated fragments are API identifiers, never critical instructions.
    assert len(missing)<7, missing
    assert index.select_one('header.top .top-right')
    assert index.select_one('main#mainContent')


@pytest.mark.parametrize('name', ['index.html','job-viewer.html','job-ai.html'])
def test_same_i18n_assets_are_loaded_before_page_scripts(name):
    html=(ASSETS/name).read_text(encoding='utf-8')
    assert 'i18n-catalog.js' in html
    assert 'i18n.js' in html
    assert 'ui-refactor.css' in html
    assert html.index('i18n-catalog.js') < html.index('i18n.js')
    assert html.index('i18n.js') < html.index('app.js' if name=='index.html' else
                                                    'job-viewer.js' if name=='job-viewer.html' else 'job-ai.js')


def test_localization_preserves_security_evidence_and_inputs():
    js=(ASSETS/'i18n.js').read_text(encoding='utf-8')
    assert 'sourceNodes = new WeakMap()' in js
    assert 'sourceAttributes = new WeakMap()' in js
    assert 'document.documentElement.lang=language' in js
    assert "'achillesapi.ui.language.v1'" in js
    assert 'payload-evidence' in js
    assert 'reportPreview' in js
    assert 'dossier-text' in js
    assert 'textContent' in js
    assert 'input.value=' not in js
    assert 'fetch(' not in js
    assert 'innerHTML' not in js


def test_backend_serves_ui_assets_without_changing_contract(tmp_path):
    client=TestClient(create_app(tmp_path/'workspace'),base_url='http://127.0.0.1:8766')
    for uri in ('/','/assets/i18n.js','/assets/i18n-catalog.js',
                '/assets/ui-refactor.css','/assets/ui-experience.js'):
        response=client.get(uri)
        assert response.status_code==200, uri
    assert client.get('/api/bootstrap').status_code==200
    assert 'language-control' in client.get('/assets/ui-refactor.css').text
    assert 'ui-experience.js' in client.get('/').text
