"""AI correlation must accept AchillesAPI assessment without YAML misuse.

The fake Ollama is loopback-only and never connects to external services.
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typer.testing import CliRunner
from achillesapi.cli import app

class OllamaFake(BaseHTTPRequestHandler):
    def do_POST(self):
        size=int(self.headers.get('content-length','0'))
        data=json.loads(self.rfile.read(size))
        assert data['stream'] is False and self.path=='/api/chat'
        content={'executive_summary':'Solo osservazioni, non vulnerabilità confermate',
                 'cross_correlations':['Un endpoint ha risposto 503'],
                 'false_positive_checks':['Ripetere con i dati di test'],
                 'next_steps':['Verifica manuale autorizzata'],
                 'limitations':['Metadati senza body HTTP']}
        response=json.dumps({'message':{'content':json.dumps(content)}}).encode()
        self.send_response(200);self.send_header('content-type','application/json');self.send_header('content-length',str(len(response)));self.end_headers();self.wfile.write(response)
    def log_message(self,*args):pass

def test_ai_correlate_from_real_assessment_metadata(tmp_path):
    server=ThreadingHTTPServer(('127.0.0.1',0),OllamaFake)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:
        spec=tmp_path/'api.yaml'
        spec.write_text('openapi: 3.0.3\ninfo:\n  title: Test API\n  version: "1"\npaths:\n  /health:\n    get:\n      responses:\n        "200":\n          description: OK\n')
        evidence=tmp_path/'assessment.json'
        evidence.write_text(json.dumps({'execution_report':{'observations':[
            {'method':'GET','path':'/health','status_code':503,'identity':'anonymous'}]}}))
        result=CliRunner().invoke(app,['ai-correlate',str(spec),str(evidence),
            '--endpoint',f'http://127.0.0.1:{server.server_port}', '--output',str(tmp_path/'correlation.json')])
        assert result.exit_code==0,result.output
        actual=json.loads((tmp_path/'correlation.json').read_text())
        assert actual['evidence_analysis']['responses_analyzed']==1
        assert actual['ai_correlation']['execution_authorized'] is False
        assert actual['target_requests_sent']==0
    finally:
        server.shutdown();server.server_close()
