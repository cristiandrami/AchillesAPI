"""Convert sanitised scanner observations into evidence suitable for local AI.

We deliberately never reconstruct response bodies or security headers. Observations
in AchillesAPI reports represent HTTP metadata, not full traffic captures.
"""
from __future__ import annotations
from typing import Any


def evidence_from_assessment(document: dict[str, Any]) -> dict[str, Any]:
    """Create {responses: [...]} from a real completed assessment or raw bundle.

    Raise a clear error if the selected document has no observed HTTP responses.
    This function is offline and never accesses the target API.
    """
    if not isinstance(document, dict):
        raise ValueError('L\'assessment deve essere un oggetto JSON.')
    raw = document.get('responses')
    if isinstance(raw, list):
        return {'responses': raw}
    found: list[dict[str, Any]] = []
    def descend(node: Any, depth: int) -> None:
        if depth > 8 or len(found) >= 1000:
            return
        if isinstance(node, dict):
            observations = node.get('observations')
            if isinstance(observations, list):
                for item in observations:
                    if not isinstance(item, dict):
                        continue
                    operation = item.get('operation') or item.get('endpoint')
                    if not operation and item.get('method') and item.get('path'):
                        operation = str(item['method'])+' '+str(item['path'])
                    status = item.get('status_code', item.get('status'))
                    if isinstance(operation, str) and isinstance(status, int) and 100 <= status <= 599:
                        parts = operation.split(' ', 1)
                        if len(parts) == 2 and parts[0].upper() in {'GET','POST','PATCH','PUT','DELETE','HEAD','OPTIONS'}:
                            found.append({'method': parts[0].upper(), 'path': parts[1], 'status_code':status,
                                          'headers':{}, 'body_preview':''})
            for k,v in node.items():
                if k not in {'observations', 'body', 'body_preview', 'request', 'response'} and isinstance(v,(dict,list)):
                    descend(v,depth+1)
        elif isinstance(node,list):
            for v in node: descend(v,depth+1)
    descend(document,0)
    if not found:
        raise ValueError('Il report selezionato non contiene osservazioni HTTP. Esegui prima un assessment attivo.')
    return {'responses':found[:1000], 'limitations': [
        'Dati derivati da metadati di assessment: header, body e valori delle risposte non sono disponibili.',
        'Una correlazione AI non prova una vulnerabilità senza evidenze ulteriori.']}
