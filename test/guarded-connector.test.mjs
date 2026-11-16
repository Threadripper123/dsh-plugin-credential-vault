import test from 'node:test';
import assert from 'node:assert/strict';
import { Context } from '@deepseek-ai/cordis';
import { createScope } from '@deepseek-ai/dsh-scope';
import { ToolsService, defineTool } from '@deepseek-ai/dsh-tools';
import { SystemPrompt } from '@deepseek-ai/dsh-system-prompt';
import { NativeToolExecutor } from '@deepseek-ai/dsh-tool-executor-native';
import { VaultCredentialProvider } from '../lib/provider.mjs';
import { ConnectorVault, validateConnector } from '../lib/connectors.mjs';
import { registerConnectorTool } from '../lib/connector-tools.mjs';
import { applyAgentToolGuard } from '../lib/tool-guard.mjs';

// Run with the existing runtime-loader.cjs and ELECTRON_RUN_AS_NODE=1.
// Actual Cordis, scope, admission, native execution, provider resolve and connector;
// only agent identity, memory storage, forbidden tool bodies and HTTP are synthetic.
async function fixture(t) {
  const ctx = new Context();
  const prompt = ctx.plugin(SystemPrompt);
  await prompt.await();
  const runtime = ctx.plugin(ToolsService);
  await runtime.await();
  ctx.tools.setExecutor(new NativeToolExecutor(ctx));
  t.after(async () => { await runtime.dispose(); await prompt.dispose(); });

  const secret = 'synthetic-guarded-connector-key-only';
  const ref = 'FIXTURE_PROFILE_KEY';
  const document = { version: 1, refs: { [ref]: secret }, records: {}, connectors: {
    fixture: validateConnector({ id: 'fixture', ref, baseURL: 'https://fixture.invalid/v1' }),
  } };
  // Do not construct/init the provider: that would migrate/read a real vault.
  const provider = Object.create(VaultCredentialProvider.prototype);
  provider.closed = false;
  let reads = 0;
  provider.store = { read: async () => { reads++; return structuredClone(document); } };
  provider.inherited = provider.dotenvFallback = () => { throw Error('Environment credential access forbidden'); };
  assert.equal(provider.resolve, VaultCredentialProvider.prototype.resolve);
  const vault = new ConnectorVault(provider);
  let projections = 0;
  const unregister = vault.register({ connector: 'fixture', operation: 'profile', path: '/profile',
    project(value) { projections++; return { displayName: value.displayName }; },
  });
  t.after(unregister);
  // The helper only needs these trusted services; tools is the actual Cordis service.
  registerConnectorTool({ tools: ctx.tools, connectorVault: vault }, {
    name: 'vault_profile', description: 'Read the fixed fixture profile',
    connector: 'fixture', operation: 'profile', parameters: {},
    output: { schema: { type: 'object', properties: { displayName: { type: 'string' } }, additionalProperties: false },
      render: (_args, value) => [{ type: 'text', text: JSON.stringify(value) }] },
  });
  const bodies = [];
  for (const name of ['shell', 'read_key']) ctx.tools.register(defineTool({
    name, description: 'Forbidden synthetic capability', parameters: {},
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
    execute() { bodies.push(name); return secret; },
  }));
  let owner;
  const consumer = ctx.plugin({ name: 'guarded-connector-fixture', inject: ['tools', 'systemPrompt'], apply(value) { owner = value; } });
  await consumer.await();
  t.after(() => consumer.dispose());
  const agent = {};
  const scope = createScope(owner, agent);
  agent.ctx = scope.ctx;
  t.after(() => scope.dispose());
  const guard = applyAgentToolGuard(agent, { allow: ['vault_profile'] });
  t.after(guard);

  let fetches = 0;
  t.mock.method(globalThis, 'fetch', async (url, options) => {
    fetches++;
    assert.equal(String(url), 'https://fixture.invalid/v1/profile');
    // Boolean assertion deliberately avoids printing either header or secret on failure.
    assert.ok(options.headers.Authorization === 'Bearer ' + secret, 'fixed connector authorization matches');
    assert.equal(options.method, 'GET');
    assert.equal(options.redirect, 'error');
    return new Response(JSON.stringify({ displayName: 'fixture', token: secret }), {
      headers: { 'content-type': 'application/json' },
    });
  });
  async function execute(name, args = {}) {
    const batch = await ctx.tools.execute({ agent, signal: new AbortController().signal,
      calls: [{ id: 'fixture-call', name, arguments: JSON.stringify(args) }],
    });
    assert.equal(batch.results.length, 1);
    assert.equal(JSON.stringify(batch).includes(secret), false, 'native output contains no credential');
    return batch.results[0].result;
  }
  return { ctx, agent, execute, vault, unregister, bodies,
    counts: () => ({ fetches, reads, projections }) };
}

test('guarded native connector resolves synthetic vault credential and returns only projected profile', async t => {
  const { ctx, agent, execute, counts } = await fixture(t);
  const selection = await ctx.tools.resolve({ agent, signal: new AbortController().signal });
  t.after(() => selection.dispose());
  const schemas = ctx.tools.schemas(agent, selection);
  assert.deepEqual(schemas.map(value => value.name), ['vault_profile']);
  assert.deepEqual(Object.keys(schemas[0].parameters.properties), []);
  assert.equal(schemas[0].parameters.additionalProperties, false);
  const result = await execute('vault_profile');
  assert.equal(result.isError, false);
  assert.deepEqual(result.value, { displayName: 'fixture' });
  assert.deepEqual(result.content, [{ type: 'text', text: JSON.stringify({ displayName: 'fixture' }) }]);
  assert.equal(JSON.stringify(result).includes('token'), false);
  assert.deepEqual(counts(), { fetches: 1, reads: 2, projections: 1 });
});

test('same guarded native scope cannot execute shell, run_code or key-reading tools', async t => {
  const { ctx, agent, execute, bodies, counts } = await fixture(t);
  for (const name of ['shell', 'run_code', 'read_key']) {
    // run_code is a reserved PTC transport, unavailable with this real native executor.
    if (name !== 'run_code') assert.ok(ctx.tools.get(name), 'forbidden capability exists globally');
    assert.equal(ctx.tools.get(name, agent), undefined);
    assert.equal(ctx.tools.executable(name, agent), undefined);
    assert.equal((await execute(name)).isError, true);
  }
  assert.deepEqual(bodies, []);
  assert.deepEqual(counts(), { fetches: 0, reads: 0, projections: 0 });
});

test('native argument validation rejects forged URL, credential ref and operation before connector access', async t => {
  const { execute, counts } = await fixture(t);
  for (const args of [{ url: 'https://attacker.invalid/profile' }, { ref: 'OTHER_KEY' }, { operation: 'unknown' },
    { url: 'https://attacker.invalid/profile', ref: 'OTHER_KEY' }]) {
    const result = await execute('vault_profile', args);
    assert.equal(result.isError, true);
    assert.match(result.error.message, /^invalid arguments:/);
    assert.deepEqual(counts(), { fetches: 0, reads: 0, projections: 0 });
  }
  assert.equal((await execute('vault_profile')).isError, false);
  assert.deepEqual(counts(), { fetches: 1, reads: 2, projections: 1 });
});

test('unregistered connector operation rejects directly and through native tool without fetch or credential read', async t => {
  const { execute, vault, unregister, counts } = await fixture(t);
  await assert.rejects(vault.invoke('fixture', 'unknown', {}), { message: 'vault: connector operation is not registered' });
  unregister();
  const result = await execute('vault_profile');
  assert.equal(result.isError, true);
  assert.match(JSON.stringify(result), /connector operation is not registered/);
  assert.deepEqual(counts(), { fetches: 0, reads: 0, projections: 0 });
});
