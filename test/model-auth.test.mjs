import test from 'node:test';
import assert from 'node:assert/strict';

// Run the actual installed ASAR modules with:
// ELECTRON_RUN_AS_NODE=1 <DeepSeek Harness.exe> --require ./test/runtime-loader.cjs --test test/model-auth.test.mjs
// No real configuration, credential files, model endpoint, or network is used.
const runtimeOnly = { skip: !process.versions.electron && 'requires Electron ASAR runtime + test/runtime-loader.cjs' };
const REF = 'SYNTHETIC_VAULT_MODEL_KEY';
const KEY = 'sk-synthetic-model-auth-test-not-a-real-key';
const route = 'vault-fixture';

async function fixture() {
  const { apply, PiAiAdapter } = await import('@deepseek-ai/dsh-llm-pi-ai');
  const { VaultCredentialProvider } = await import('../lib/provider.mjs');
  // The provider's unmodified public resolve method reads a synthetic memory store.
  // Bypass its Cordis constructor/init to avoid migration and safeStorage disk IO.
  const vault = Object.create(VaultCredentialProvider.prototype);
  const document = { version: 1, refs: { [REF]: KEY }, records: {}, connectors: {} };
  vault.closed = false;
  vault.store = { read: async () => structuredClone(document) };
  vault.inherited = () => undefined;
  vault.dotenvFallback = () => undefined;
  const resolved = [];
  const credentials = new Proxy(vault, { get(target, key) {
    if (key === 'resolve') return async ref => { resolved.push(ref); return target.resolve(ref); };
    const value = Reflect.get(target, key);
    return typeof value === 'function' ? value.bind(target) : value;
  } });
  let adapter;
  const profiles = { [route]: {
    api: 'openai-completions', baseURL: 'https://model-auth.invalid/v1', apiKeyEnv: REF,
    models: [{ id: 'synthetic-model', name: 'Synthetic model', contextWindow: 4096, maxTokens: 64 }],
  } };
  const ctx = {
    fiber: { entry: { options: { id: 'synthetic-model-auth' } } },
    get(name) { if (name === 'credentials') return credentials; throw Error('Unexpected service access: ' + name); },
    inject() {}, on() {},
    waterfall(_event, _request, headers) { return headers; },
    logger: { warn() {}, error() {} },
    llm: {
      registerConfigurableProviders() { return { replace() {} }; },
      registerModelDiscovery() {},
      registerAdapter(routes, actual) { assert.deepEqual(routes, [route]); adapter = actual; return { replace() {} }; },
    },
  };
  apply(ctx, { providers: { get: () => profiles } });
  assert.ok(adapter instanceof PiAiAdapter);
  const options = {
    provider: route, model: 'synthetic-model', maxTokens: 16,
    messages: [
      { role: 'system', content: [{ type: 'text', text: 'Synthetic system instructions.' }] },
      { role: 'user', content: [{ type: 'text', text: 'List synthetic items.' }] },
    ],
    tools: [{ name: 'list_items', description: 'List synthetic items', parameters: { type: 'object', properties: { limit: { type: 'integer' } }, required: [], additionalProperties: false } }],
  };
  return { adapter, options, resolved, document, profiles };
}

function assertNoCredential(value) {
  const serialized = JSON.stringify(value);
  assert.equal(serialized.includes(KEY), false, 'key must not reach model-visible payload');
  assert.equal(serialized.includes(REF), false, 'credential ref must not be injected into model-visible payload');
}

function response() {
  const chunk = (delta, finish_reason = null) => 'data: ' + JSON.stringify({ id: 'synthetic-response', object: 'chat.completion.chunk', created: 0, model: 'synthetic-model', choices: [{ index: 0, delta, finish_reason }] }) + '\n\n';
  return new Response(chunk({ role: 'assistant', content: 'synthetic-ok' }) + chunk({}, 'stop') + 'data: [DONE]\n\n', { status: 200, headers: { 'content-type': 'text/event-stream' } });
}

test('real DSH OpenAI adapter resolves vault ref and keeps credential out of messages and tools', runtimeOnly, async t => {
  const captured = [];
  t.mock.method(globalThis, 'fetch', async (input, init) => {
    const request = new Request(input, init);
    assert.equal(request.url, 'https://model-auth.invalid/v1/chat/completions');
    captured.push({ headers: request.headers, body: JSON.parse(await request.text()) });
    return response();
  });
  const { adapter, options, resolved, profiles } = await fixture();
  const original = structuredClone(options);
  const chunks = [];
  for await (const chunk of adapter.stream(options)) chunks.push(chunk);
  assert.equal(captured.length, 1);
  assert.deepEqual(resolved, [REF]);
  assert.equal(captured[0].headers.get('authorization'), 'Bearer ' + KEY);
  assert.ok(captured[0].body.messages.some(message => JSON.stringify(message).includes('List synthetic items.')));
  assert.equal(captured[0].body.tools[0].function.name, 'list_items');
  assert.deepEqual(captured[0].body.tools[0].function.parameters, options.tools[0].parameters);
  assertNoCredential(captured[0].body);
  assertNoCredential(options);
  assertNoCredential(chunks);
  assert.equal(JSON.stringify(profiles).includes(KEY), false);
  assert.equal(profiles[route].apiKeyEnv, REF);
  assert.deepEqual(options, original);
  assert.ok(chunks.some(chunk => JSON.stringify(chunk).includes('synthetic-ok')));
});

test('real DSH OpenAI adapter refuses missing named vault ref before transport', runtimeOnly, async t => {
  let calls = 0;
  t.mock.method(globalThis, 'fetch', async () => { calls++; throw Error('Network forbidden'); });
  const { adapter, options, document, resolved } = await fixture();
  delete document.refs[REF];
  await assert.rejects(async () => {
    for await (const _chunk of adapter.stream(options)) { /* drain */ }
  }, error => error.code === 'MISSING_CREDENTIAL' && !error.message.includes(KEY));
  assert.deepEqual(resolved, [REF]);
  assert.equal(calls, 0);
  assertNoCredential(options);
});
