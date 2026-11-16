import { scopeOf } from '@deepseek-ai/dsh-scope';
import { NativeToolExecutor } from '@deepseek-ai/dsh-tool-executor-native';

function explicitAllow(options) {
  if (!options || !Object.hasOwn(options, 'allow') || !Array.isArray(options.allow)) {
    throw new TypeError('tool guard requires an explicit allow string array (empty denies all inherited tools)');
  }
  if (Object.keys(options).some(key => key !== 'allow')) {
    throw new TypeError('tool guard only supports allow; scope-local exceptions are not supported');
  }
  const allow = [];
  for (const name of options.allow) {
    if (typeof name !== 'string' || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(name) || name === 'run_code') {
      throw new TypeError('allow must contain exact tool names and must not contain run_code');
    }
    if (allow.includes(name)) throw new TypeError('allow must not contain duplicate names');
    allow.push(name);
  }
  return allow;
}

/**
 * Opt-in capability attenuation through the real DSH ToolsService restriction.
 * This is NOT an OS sandbox. All allowlisted implementations must be trusted.
 * The viewing scope's own registrations bypass restrict: reject existing ones,
 * including shadows of global names. This does not prevent trusted host plugins
 * from changing implementations, around-dispatch hooks, or minting other scopes.
 * Later own tools stay visible to schema/lookup; the pipeline guard denies their
 * bodies at its checkpoint. A later executor switch to PTC or trusted hook
 * mutation is outside the guarantee: the host must preserve native execution.
 * Install before execution; do not treat this helper as revoking in-flight work.
 */
export function applyAgentToolGuard(agent, options) {
  const allow = explicitAllow(options);
  const ctx = agent?.ctx;
  if (!agent || !ctx || scopeOf(ctx) !== agent) {
    throw new TypeError('tool guard requires the exact agent.ctx scoped context');
  }
  const tools = ctx.tools;
  if (typeof tools?.view !== 'function' || typeof tools?.restrict !== 'function' ||
      typeof tools?.layers?.peek !== 'function' || typeof tools?.guard !== 'function') {
    throw new TypeError('tool guard requires verified DSH ToolsService view, restrict, and layers.peek APIs');
  }
  if (typeof tools.selectExecutor !== 'function' ||
      !(tools.selectExecutor(agent) instanceof NativeToolExecutor)) {
    throw new Error('tool guard requires the actual native executor; PTC run_code is not a sandbox');
  }
  const view = tools.view(agent);
  if (typeof view?.visible?.keys !== 'function' || typeof view?.restrictableNames?.has !== 'function') {
    throw new TypeError('tool guard cannot verify the scoped tool view');
  }
  const own = tools.layers.peek(agent);
  if (own !== undefined && typeof own.tools?.keys !== 'function') {
    throw new TypeError('tool guard cannot verify scope own registrations');
  }
  const local = new Set(own === undefined ? [] : own.tools.keys());
  for (const name of view.visible.keys()) {
    if (!view.restrictableNames.has(name)) local.add(name);
  }
  if (local.size) throw new Error('tool guard refuses scope own tools that bypass restrict: ' + [...local].sort().join(', '));
  const definitions = new Map(allow.map(name => [name, view.visible.get(name)]));
  // restrict validates allow names and intersects with existing restrictions.
  // guard is a monotonic denial after extensible pre-execute policy. It also
  // rejects later local/shadow registrations at that checkpoint. Host plugins
  // and around-dispatch hooks remain trusted; this is not an OS sandbox.
  return ctx.effect(function* () {
    yield tools.restrict({ allow });
    yield tools.guard(exec => {
      if (!(tools.selectExecutor(exec.agent) instanceof NativeToolExecutor)) return 'tool guard requires native execution';
      const expected = definitions.get(exec.name);
      if (expected === undefined || tools.executable(exec.name, exec.agent, exec.toolSet) !== expected) {
        return 'tool guard denied a tool outside the fixed capability definitions';
      }
    });
  }, 'credential-vault.applyAgentToolGuard()');
}

// No lifecycle installer: executor selection and own registrations can still change
// after agent/created. Call explicitly after trusted host setup, before execution.

