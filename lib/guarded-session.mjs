import { scopeOf } from '@deepseek-ai/dsh-scope';
import { NativeToolExecutor } from '@deepseek-ai/dsh-tool-executor-native';

export const name = 'credential-vault-guarded-session';
export const inject = ['tools'];

// Mount in a trusted preset's standing scope, so existing agents inherit the
// policy immediately on parent binding without an agent/created event.
export function apply(ctx, config = {}) {
  const scope = scopeOf(ctx);
  if (scope === undefined) throw new TypeError('guarded session requires a standing scoped context; root mounting is forbidden');
  const input = config.allow ?? [];
  if (!Array.isArray(input) || Object.keys(config).some(key => key !== 'allow')) throw new TypeError('guarded session requires an explicit tool allow list');
  const allow = Object.freeze([...input]);
  if (allow.some(name => typeof name !== 'string' || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(name) || name === 'run_code') || new Set(allow).size !== allow.length) {
    throw new TypeError('allow must contain unique exact tool names and must not contain run_code');
  }
  const tools = ctx.tools;
  if (typeof tools?.view !== 'function' || typeof tools?.restrict !== 'function' ||
      typeof tools?.layers?.peek !== 'function' || typeof tools?.guard !== 'function' ||
      typeof tools?.get !== 'function' || typeof tools?.executable !== 'function' ||
      typeof tools?.selectExecutor !== 'function' || typeof tools?.setExecutor !== 'function') {
    throw new TypeError('guarded session requires verified scoped ToolsService APIs');
  }
  const view = tools.view(scope);
  const own = tools.layers.peek(scope);
  if (typeof view?.visible?.keys !== 'function' || typeof view?.restrictableNames?.has !== 'function' ||
      (own !== undefined && typeof own.tools?.keys !== 'function')) {
    throw new TypeError('guarded session cannot verify the standing scoped tool view');
  }
  const local = new Set(own === undefined ? [] : own.tools.keys());
  for (const name of view.visible.keys()) {
    if (!view.restrictableNames.has(name)) local.add(name);
  }
  if (local.size) throw new Error('guarded session refuses scope own tools that bypass restrict: ' + [...local].sort().join(', '));
  const definitions = new Map(allow.map(name => {
    const global = tools.get(name);
    if (global === undefined || view.visible.get(name) !== global) {
      throw new Error('guarded session requires an inherited visible global tool: ' + name);
    }
    return [name, global];
  }));
  const approved = new Set(definitions.values());
  const executor = new NativeToolExecutor(ctx);
  const describe = executor.describe.bind(executor);
  executor.describe = definitions => describe(definitions.filter(definition => approved.has(definition)));
  // This attenuates trusted host capabilities, not OS privileges or host plugins.
  // Keep all effects on standing: moving an agent out restores its prior policy.
  return ctx.effect(function* () {
    yield tools.restrict({ allow });
    yield tools.guard(exec => {
      if (tools.selectExecutor(exec.agent) !== executor) return 'guarded session requires its standing native executor';
      const expected = definitions.get(exec.name);
      if (expected === undefined || tools.executable(exec.name, exec.agent, exec.toolSet) !== expected) {
        return 'guarded session denied a tool outside the fixed capability definitions';
      }
    });
    yield tools.setExecutor(executor);
  }, 'credential-vault.guardedSession()');
}
