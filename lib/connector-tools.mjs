import { defineTool } from '@deepseek-ai/dsh-tools';

/** Register a trusted, fixed operation. Model arguments never select credentials or targets. */
export function registerConnectorTool(ctx, definition) {
  const { name, description, connector, operation, parameters = {}, output } = definition ?? {};
  if (!/^[a-z][a-z0-9_]{0,63}$/.test(name) || typeof description !== 'string' ||
      !/^[a-z][a-z0-9-]{0,63}$/.test(connector) || !/^[a-z][a-z0-9-]{0,63}$/.test(operation) || !output) {
    throw new TypeError('vault: invalid fixed connector tool');
  }
  if (!ctx.connectorVault || !ctx.tools) throw new Error('vault: connectorVault and tools services required');
  const allowedArguments = new Set(Object.keys(parameters));
  const tool = defineTool({
    name, description, parameters, output,
    execute(args, exec) {
      if (!args || typeof args !== 'object' || Array.isArray(args) || Object.keys(args).some(key => !allowedArguments.has(key))) throw new Error('vault: unexpected connector arguments');
      return ctx.connectorVault.invoke(connector, operation, args, { signal: exec.signal });
    },
  });
  tool.parameters.additionalProperties = false;
  return ctx.tools.register(tool);
}
