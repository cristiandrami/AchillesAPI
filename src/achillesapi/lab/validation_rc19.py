"""Synthetic rc.19 enterprise API benchmark, FOR LOOPBACK-ONLY TRAINING.

Never expose this intentionally vulnerable API to an external network.
No real customer or Northstar systems are connected.
"""
from __future__ import annotations

from html import escape
from urllib.parse import urlparse
from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.responses import HTMLResponse, RedirectResponse

app = FastAPI(title='AchillesAPI RC19 Independent Enterprise Validation Lab',version='1.0',
              description='Synthetic data only. Vulnerable and protected endpoints for offline local QA.',
              servers=[{'url':'http://127.0.0.1:8009'}])
_INVOICES = {'beta-001':{'id':'beta-001','tenant':'beta','total':12},
             'alpha-001':{'id':'alpha-001','tenant':'alpha','total':9}}
_TOKENS = {'alpha-demo':'alpha','beta-demo':'beta','admin-demo':'admin'}


def identity(authorization: str | None) -> str:
    token = authorization.split(' ',1)[1] if authorization and authorization.startswith('Bearer ') else ''
    who = _TOKENS.get(token)
    if not who: raise HTTPException(401, 'Synthetic demo token required')
    return who


@app.get('/health')
def health(): return {'status':'ok','lab':'rc19-independent'}


@app.get('/v1/invoices/{invoice_id}')
def read_invoice_vulnerable(invoice_id: str, authorization: str | None = Header(None)):
    identity(authorization)
    if invoice_id not in _INVOICES: raise HTTPException(404)
    return _INVOICES[invoice_id]  # vulnerable cross-tenant read, local only


@app.get('/v1/secure/invoices/{invoice_id}')
def read_invoice_secure(invoice_id: str, authorization: str | None = Header(None)):
    caller=identity(authorization)
    invoice=_INVOICES.get(invoice_id)
    if not invoice: raise HTTPException(404)
    if caller not in ('admin',invoice['tenant']): raise HTTPException(403)
    return invoice


@app.get('/v1/admin/audit')
def audit_vulnerable(authorization: str | None = Header(None)):
    identity(authorization)
    return {'allowed':True,'records':'synthetic'}  # vulnerable BFLA


@app.get('/v1/secure/admin/audit')
def audit_secure(authorization: str | None = Header(None)):
    caller=identity(authorization)
    if caller!='admin': raise HTTPException(403)
    return {'allowed':True,'records':'synthetic'}


@app.get('/v1/echo',response_class=HTMLResponse)
def echo_vulnerable(q: str = Query('')):
    return HTMLResponse('<div>'+q+'</div>')  # intentionally unescaped tag


@app.get('/v1/secure/echo',response_class=HTMLResponse)
def echo_secure(q: str = Query('')):
    return HTMLResponse('<div>'+escape(q)+'</div>')


@app.get('/v1/redirect')
def redirect_vulnerable(return_url: str = Query('/health')):
    return RedirectResponse(return_url,status_code=302)


@app.get('/v1/secure/redirect')
def redirect_secure(return_url: str = Query('/health')):
    parsed=urlparse(return_url)
    if parsed.scheme or parsed.netloc or not return_url.startswith('/') or return_url.startswith('//'):
        raise HTTPException(400,'Only relative local redirect')
    return RedirectResponse(return_url,status_code=302)
