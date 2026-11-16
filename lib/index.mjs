import { Service } from '@deepseek-ai/cordis';
import { ConnectorVault } from './connectors.mjs';
import { registerWeb } from './web.mjs';
export const name = 'credential-vault-management';
export const inject = ['credentials', 'connection', 'webServer'];
class ConnectorVaultService extends Service {
  constructor(ctx) {
    super(ctx, 'connectorVault');
    this.operations = new ConnectorVault(ctx.credentials);
  }
  register(definition) { return this.operations.register(definition); }
  invoke(connector, operation, args, options) { return this.operations.invoke(connector, operation, args, options); }
}
export function apply(ctx) {
  if (typeof ctx.credentials.publicSnapshot !== 'function') throw new Error('vault: encrypted credential provider is required');
  ctx.plugin(ConnectorVaultService);
  registerWeb(ctx, ctx.credentials);
}
