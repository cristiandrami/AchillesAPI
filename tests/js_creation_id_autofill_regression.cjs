'use strict';
// Minimal DOM-driven regression for the actual dashboard helper functions.
// Run with: node tests/js_creation_id_autofill_regression.cjs < candidates.json
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const source = fs.readFileSync(path.join(root, 'src/achillesapi/dashboard/static/app.js'), 'utf8');
const begin = source.indexOf('function guideIdentifierSuggestion(');
const end = source.indexOf('function guideUpdateCandidate()', begin);
assert(begin >= 0 && end > begin, 'The current dashboard must define the actual autofill helpers.');
const code = source.slice(begin, end);
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const elements = new Map();
function element(id) {
  if (!elements.has(id)) {
    elements.set(id, {
      value: '', textContent: '', children: [],
      replaceChildren() { this.children = []; },
      append(node) { this.children.push(node); },
    });
  }
  return elements.get(id);
}
const document = {
  getElementById: element,
  createElement(tag) { return { tagName: tag, value: '' }; },
};
const script = `'use strict';
const $ = id => document.getElementById(id);
let specId = 'test-openapi', guidedCandidate = null, guidedIdCandidateKey = '';
${code}
guidedCandidate = input.documented;
guideApplyIdentifierSuggestion(true);
if ($('guidedId').value !== 'data/id') throw Error('Declared /data/id was not autofilled');
if (!$('guidedIdNotice').textContent.includes('schema della risposta POST')) throw Error('Missing documented provenance');
guidedCandidate = input.undocumented;
guideApplyIdentifierSuggestion(true);
if ($('guidedId').value !== 'id') throw Error('Undocumented responses must autofill the common id field while offering other hints');
if (!$('guidedIdNotice').textContent.includes('NON è verificato')) throw Error('Missing warning for speculative hint');
guidedCandidate = input.conventional;
guideApplyIdentifierSuggestion(true);
if ($('guidedId').value !== 'id') throw Error('GET path variable expense_id must not be mistaken for the POST field');
if (!$('guidedIdNotice').textContent.includes('NON è verificato')) throw Error('Path heuristic must be labeled unverified');
$('guidedId').value = 'payload/documentRef';
$('guidedIdNotice').textContent = 'Verificato da risposta reale';
guideApplyIdentifierSuggestion();
if ($('guidedId').value !== 'payload/documentRef') throw Error('Navigation erased manually verified pointer');
if ($('guidedIdNotice').textContent !== 'Verificato da risposta reale') throw Error('Navigation erased real response status');
guidedCandidate = input.multi;
guideApplyIdentifierSuggestion(true);
if ($('guidedId').value !== 'data/id') throw Error('Multiple declared fields should choose resource /data/id');
guidedCandidate = input.undocumented;
guideApplyIdentifierSuggestion(true);
if ($('guidedId').value !== 'id') throw Error('Switching workflows must refresh the ID suggestion');
guidedCandidate = input.missing;
guideApplyIdentifierSuggestion(true);
if ($('guidedId').value !== '') throw Error('ID not derivable should remain blank');
'OK';`;
const result = vm.runInNewContext(script, { document, input }, {timeout: 3000});
assert.equal(result, 'OK');
console.log('Dashboard ID autofill: 7 DOM scenarios passed.');
