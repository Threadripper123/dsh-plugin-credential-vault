import test from 'node:test';
import assert from 'node:assert/strict';
import { Context } from '@deepseek-ai/cordis';
import { bindScopeParent, createScope } from '@deepseek-ai/dsh-scope';
import * as guardedSession from '../lib/guarded-session.mjs';
import { ToolsService, defineTool } from '@deepseek-ai/dsh-tools';
import { SystemPrompt } from '@deepseek-ai/dsh-system-prompt';
import { NativeToolExecutor } from '@deepseek-ai/dsh-tool-executor-native';
import { PtcExecutor } from '@deepseek-ai/dsh-tool-executor-ptc';
import { ToolExecutionPipeline } from '@deepseek-ai/dsh-tools/pipeline';
import { applyAgentToolGuard } from '../lib/tool-guard.mjs';

// Run with the existing runtime-loader.cjs and ELECTRON_RUN_AS_NODE=1.
// Every registry, context, layer, executor, admission, and pipeline below is real.
// Only tool bodies and agent identity/session data are synthetic; no credentials.
async function fixture(t, { native = true } = {}) {
  const ctx = new Context();
  const prompt = ctx.plugin(SystemPrompt);
  await prompt.await();
  const runtime = ctx.plugin(ToolsService);
  await runtime.await();
  t.after(async () => { await runtime.dispose(); await prompt.dispose(); });
  if (native) ctx.tools.setExecutor(new NativeToolExecutor(ctx));
  const bodies = new Map();
  const makeTool = name => defineTool({
    name, description: 'Synthetic test operation', parameters: {},
    output: { schema: { type: 'string' }, render: (_args, value) => [{ type: 'text', text: value }] },
    execute: () => { bodies.set(name, (bodies.get(name) || 0) + 1); return 'synthetic-ok'; },
  });
  for (const name of ['fixed_operation', 'pwsh', 'shell']) ctx.tools.register(makeTool(name));
  let scopedOwner;
  const consumer = ctx.plugin({ name: 'guard-test-consumer', inject: ['tools', 'systemPrompt'], apply(owner) { scopedOwner = owner; } });
  await consumer.await();
  const scopes = new Map();
  t.after(() => consumer.dispose());
  function agent(parent) {
    const result = {};
    const scope = createScope(scopedOwner, result, parent ? {parent} : undefined);
    scopes.set(result, scope);
    result.ctx = scope.ctx;
    t.after(() => scope.dispose());
    return result;
  }
  const guarded = agent(), sibling = agent();
  return { ctx, guarded, sibling, agent, makeTool, bodies, scopes };
}
async function admitted(ctx, agent) {
  return ctx.tools.resolve({ agent, signal: new AbortController().signal });
}
async function run(ctx, agent, name) {
  const pipeline = new ToolExecutionPipeline(ctx);
  const prepared = await pipeline.prepare({ agent, name, arguments: {}, callId: 'synthetic-call', signal: new AbortController().signal });
  if (prepared.kind === 'dispatch') return (await pipeline.dispatch(prepared.exec)).result;
  return prepared.result;
}

test('real scoped restriction rejects shell lookup, executable and step schemas including later global registrations', async t => {
  const {ctx, guarded, sibling, makeTool, bodies} = await fixture(t);
  const before = await admitted(ctx, guarded);
  assert.ok(ctx.tools.executable('pwsh', guarded, before));
  const allow = ['fixed_operation'];
  const dispose = applyAgentToolGuard(guarded, {allow});
  allow.push('pwsh'); // copied, never a live policy reference
  for (const name of ['pwsh', 'shell']) {
    assert.equal(ctx.tools.get(name, guarded), undefined);
    assert.equal(ctx.tools.executable(name, guarded), undefined);
    assert.equal(ctx.tools.executable(name, guarded, before), undefined);
    assert.ok(ctx.tools.get(name, sibling));
    assert.equal((await run(ctx, guarded, name)).isError, true);
  }
  ctx.tools.register(makeTool('new_global_tool'));
  const selection = await admitted(ctx, guarded);
  t.after(() => selection.dispose());
  assert.deepEqual(ctx.tools.schemas(guarded, selection).map(x => x.name), ['fixed_operation']);
  assert.equal(ctx.tools.get('new_global_tool', guarded), undefined);
  assert.equal(ctx.tools.executable('new_global_tool', guarded, selection), undefined);
  assert.equal((await run(ctx, guarded, 'new_global_tool')).isError, true);
  assert.equal((await run(ctx, guarded, 'fixed_operation')).isError, false);
  assert.deepEqual(ctx.tools.selectExecutor(guarded).describe(ctx.tools.definitions(guarded, selection)).schemas.map(x => x.name), ['fixed_operation']);
  assert.equal(bodies.get('fixed_operation'), 1);
  assert.equal(bodies.get('pwsh'), undefined);
  assert.equal(bodies.get('shell'), undefined);
  assert.equal(bodies.get('new_global_tool'), undefined);
  before.dispose();
  dispose(); dispose();
  assert.ok(ctx.tools.get('pwsh', guarded));
  assert.ok(ctx.tools.get('new_global_tool', guarded));
});

test('explicit empty allow denies every inherited capability and composes with existing restrictions', async t => {
  const {ctx, guarded} = await fixture(t);
  const earlier = guarded.ctx.tools.restrict({deny:['fixed_operation']});
  const dispose = applyAgentToolGuard(guarded, {allow:['fixed_operation']});
  assert.deepEqual(ctx.tools.schemas(guarded), []);
  dispose(); earlier();
  const empty = applyAgentToolGuard(guarded, {allow:[]});
  assert.deepEqual(ctx.tools.schemas(guarded), []);
  empty();
  assert.equal(ctx.tools.schemas(guarded).length, 3);
});

test('fails closed for own local tools, including same-name shadows of inherited tools', async t => {
  const {ctx, guarded, makeTool} = await fixture(t);
  for (const name of ['local_only', 'pwsh', 'fixed_operation']) {
    const remove = guarded.ctx.tools.register(makeTool(name));
    if (name !== 'local_only') assert.ok(ctx.tools.view(guarded).restrictableNames.has(name));
    assert.throws(() => applyAgentToolGuard(guarded, {allow:['fixed_operation']}), /scope own tools/);
    assert.ok(ctx.tools.get('shell', guarded));
    remove();
  }
});

test('monotonic execution guard rejects later scope-local and same-name shadow bodies', async t => {
  const {ctx, guarded, makeTool, bodies} = await fixture(t);
  const dispose = applyAgentToolGuard(guarded, {allow:['fixed_operation']});
  const removeLocal = guarded.ctx.tools.register(makeTool('later_local'));
  const removeShadow = guarded.ctx.tools.register(makeTool('fixed_operation'));
  // Restrict does not hide own tools: explicitly demonstrate the actual limit.
  assert.ok(ctx.tools.get('later_local', guarded));
  for (const name of ['later_local', 'fixed_operation']) {
    const result = await run(ctx, guarded, name);
    assert.equal(result.isError, true);
    assert.match(result.error.message, /fixed capability definitions/);
    assert.equal(bodies.get(name), undefined);
  }
  removeLocal(); removeShadow(); dispose();
});

test('rejects malformed policies, unknown names, transport and non-agent contexts without masking globals', async t => {
  const {ctx, guarded} = await fixture(t);
  for (const options of [undefined, {}, {allow:'fixed_operation'}, {allow:[1]}, {allow:['*']}, {allow:['pwsh ']}, {allow:['run_code']}, {allow:['shell','shell']}, {allow:[],trustedAllowLocal:true}]) {
    assert.throws(() => applyAgentToolGuard(guarded, options));
  }
  assert.throws(() => applyAgentToolGuard(guarded, {allow:['missing']}), /unknown global/);
  assert.throws(() => applyAgentToolGuard({ctx}, {allow:[]}), /exact agent.ctx/);
  assert.throws(() => applyAgentToolGuard(null, {allow:[]}), /exact agent.ctx/);
  assert.ok(ctx.tools.get('pwsh', guarded));
  assert.ok(ctx.tools.get('pwsh'));
});

test('rejects absent and actual PTC executors; scoped PTC cannot inherit native approval', async t => {
  const {ctx, guarded} = await fixture(t, {native:false});
  assert.throws(() => applyAgentToolGuard(guarded, {allow:[]}), /executor/i);
  ctx.tools.setExecutor(new NativeToolExecutor(ctx));
  guarded.ctx.tools.setExecutor(new PtcExecutor(guarded.ctx));
  assert.throws(() => applyAgentToolGuard(guarded, {allow:[]}), /actual native executor/);
  assert.ok(ctx.tools.get('shell', guarded));
});

test('scope disposal lifts only that agent policy and guard', async t => {
  const {ctx, agent, sibling, scopes} = await fixture(t);
  const target = agent();
  applyAgentToolGuard(target, {allow:[]});
  assert.equal(ctx.tools.get('pwsh', target), undefined);
  // Explicit disposer semantics tested above; real ownership via another scope.
  assert.ok(ctx.tools.get('pwsh', sibling));
  assert.ok(ctx.tools.guards.peek(target));
  await scopes.get(target).dispose();
  assert.equal(ctx.tools.guards.peek(target), undefined);
  assert.equal(ctx.tools.layers.peek(target), undefined);
  assert.ok(ctx.tools.get('pwsh', target));
  assert.ok(ctx.tools.get('pwsh', sibling));
});

test('native batch executor actually denies shell and executes only fixed operation', async t => {
  const {ctx, guarded, bodies} = await fixture(t);
  applyAgentToolGuard(guarded, {allow:['fixed_operation']});
  const batch = await ctx.tools.execute({agent:guarded, signal:new AbortController().signal, calls:[
    {id:'blocked',name:'pwsh',arguments:'{}'},
    {id:'allowed',name:'fixed_operation',arguments:'{}'},
  ]});
  assert.equal(batch.results[0].result.isError, true);
  assert.equal(batch.results[1].result.isError, false);
  assert.equal(bodies.get('pwsh'), undefined);
  assert.equal(bodies.get('fixed_operation'), 1);
});

test('standing preset policy follows an existing agent binding into and out of preset without created', async t => {
  const {ctx, guarded, sibling, agent, bodies} = await fixture(t, {native:false});
  const ptc = new PtcExecutor(ctx);
  ctx.tools.setExecutor(ptc);
  const standing = agent();
  const allow = ['fixed_operation'];
  const plugin = standing.ctx.plugin(guardedSession, {allow});
  await plugin.await();
  t.after(() => plugin.dispose());
  allow.push('pwsh');
  const native = ctx.tools.selectExecutor(standing);
  assert.ok(native instanceof NativeToolExecutor);
  assert.equal(ctx.tools.selectExecutor(guarded), ptc);
  const before = await admitted(ctx, guarded);
  t.after(() => before.dispose());
  const binding = bindScopeParent(guarded, standing);
  assert.equal(ctx.tools.selectExecutor(guarded), native);
  assert.equal(ctx.tools.layers.peek(guarded), undefined);
  assert.equal(ctx.tools.guards.peek(guarded), undefined);
  assert.equal(ctx.tools.get('pwsh', guarded), undefined);
  assert.equal(ctx.tools.executable('pwsh', guarded, before), undefined);
  const selection = await admitted(ctx, guarded);
  t.after(() => selection.dispose());
  assert.deepEqual(native.describe(ctx.tools.definitions(guarded, selection)).schemas.map(x => x.name), ['fixed_operation']);
  const batch = await ctx.tools.execute({agent:guarded, signal:new AbortController().signal, calls:[
    {id:'blocked',name:'pwsh',arguments:'{}'}, {id:'allowed',name:'fixed_operation',arguments:'{}'},
  ]});
  assert.equal(batch.results[0].result.isError, true);
  assert.equal(batch.results[1].result.isError, false);
  assert.equal(bodies.get('pwsh'), undefined);
  assert.equal(bodies.get('fixed_operation'), 1);
  assert.equal(ctx.tools.selectExecutor(sibling), ptc);
  assert.equal(ctx.tools.selectExecutor(), ptc);
  assert.ok(ctx.tools.get('pwsh', sibling));
  assert.ok(ctx.tools.get('pwsh'));
  binding.rebind(undefined);
  assert.equal(ctx.tools.selectExecutor(guarded), ptc);
  assert.ok(ctx.tools.schemas(guarded).some(x => x.name === 'pwsh'));
  assert.equal((await run(ctx, guarded, 'pwsh')).isError, false);
  binding.rebind(standing);
  assert.equal(ctx.tools.selectExecutor(guarded), native);
  assert.equal((await run(ctx, guarded, 'pwsh')).isError, true);
});

test('standing native presenter hides later own schemas and guard rejects local shadows and child executors', async t => {
  const {ctx, guarded, agent, makeTool, bodies} = await fixture(t);
  const standing = agent();
  const plugin = standing.ctx.plugin(guardedSession, {allow:['fixed_operation']});
  await plugin.await();
  t.after(() => plugin.dispose());
  bindScopeParent(guarded, standing);
  const native = ctx.tools.selectExecutor(guarded);
  ctx.tools.register(makeTool('later_global'));
  standing.ctx.tools.register(makeTool('standing_later'));
  guarded.ctx.tools.register(makeTool('later_local'));
  const removeShadow = guarded.ctx.tools.register(makeTool('fixed_operation'));
  const selection = await admitted(ctx, guarded);
  t.after(() => selection.dispose());
  assert.deepEqual(native.describe(ctx.tools.definitions(guarded)).schemas, []);
  assert.deepEqual(native.describe(ctx.tools.definitions(guarded, selection)).schemas, []);
  for (const name of ['standing_later', 'later_local', 'fixed_operation', 'later_global']) {
    assert.equal((await run(ctx, guarded, name)).isError, true);
    assert.equal(bodies.get(name), undefined);
  }
  removeShadow();
  assert.deepEqual(native.describe(ctx.tools.definitions(guarded)).schemas.map(x => x.name), ['fixed_operation']);
  const removeNative = guarded.ctx.tools.setExecutor(new NativeToolExecutor(guarded.ctx));
  let result = await run(ctx, guarded, 'fixed_operation');
  assert.equal(result.isError, true);
  assert.match(result.error.message, /standing native executor/);
  removeNative();
  guarded.ctx.tools.setExecutor(new PtcExecutor(guarded.ctx));
  result = await run(ctx, guarded, 'fixed_operation');
  assert.equal(result.isError, true);
  assert.match(result.error.message, /standing native executor/);
  assert.equal(bodies.get('fixed_operation'), undefined);
});

test('standing wrapper refuses root, own tools and ancestor shadows before installing effects', async t => {
  const {ctx, guarded, agent, makeTool} = await fixture(t);
  const rootExecutor = ctx.tools.selectExecutor();
  assert.throws(() => guardedSession.apply(ctx, {allow:[]}), /root mounting/);
  assert.equal(ctx.tools.selectExecutor(), rootExecutor);
  for (const name of ['local_only', 'fixed_operation']) {
    const remove = guarded.ctx.tools.register(makeTool(name));
    assert.throws(() => guardedSession.apply(guarded.ctx, {allow:['fixed_operation']}), /scope own tools/);
    assert.equal(ctx.tools.guards.peek(guarded), undefined);
    assert.equal(ctx.tools.selectExecutor(guarded), rootExecutor);
    remove();
  }
  const child = agent(guarded);
  guarded.ctx.tools.register(makeTool('fixed_operation'));
  assert.throws(() => guardedSession.apply(child.ctx, {allow:['fixed_operation']}), /inherited visible global tool/);
  for (const allow of [['missing'], ['run_code'], ['*'], [1], ['shell','shell']]) {
    assert.throws(() => guardedSession.apply(child.ctx, {allow}));
  }
  assert.equal(ctx.tools.selectExecutor(child), rootExecutor);
  assert.ok(ctx.tools.get('pwsh', child));
});

