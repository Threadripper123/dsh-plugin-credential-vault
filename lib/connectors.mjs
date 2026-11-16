import { isIP } from 'node:net';
const idPattern = /^[a-z][a-z0-9-]{0,63}$/;
const refPattern = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
function fail() { throw new Error('vault: invalid connector policy'); }
export function validateConnector(input) {
  if (!input || typeof input !== 'object' || !idPattern.test(input.id) || !refPattern.test(input.ref)) fail();
  const label = input.label || input.id;
  if (typeof label !== 'string' || label.length > 120 || /[\x00-\x1f]/.test(label)) fail();
  let url; try { url = new URL(input.baseURL); } catch { fail(); }
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || isIP(url.hostname) || url.hostname === 'localhost' || !url.hostname.includes('.') || url.hostname.endsWith('.localhost') || url.hostname.endsWith('.local')) fail();
  const header = input.header || 'Authorization';
  if (!['Authorization', 'x-api-key', 'api-key', 'X-API-Key'].includes(header)) fail();
  const prefix = input.prefix ?? (header === 'Authorization' ? 'Bearer ' : '');
  if (!['', 'Bearer ', 'Basic ', 'Token '].includes(prefix)) fail();
  return { id: input.id, label, ref: input.ref, baseURL: (url.href.endsWith('/') ? url.href.slice(0, -1) : url.href), header, prefix };
}
// Host plugins register the operations and their result projections. No raw request tool is exposed.
export class ConnectorVault {
  #provider; #operations = new Map();
  constructor(provider) { this.#provider = provider; }
  register({ connector, operation, method = 'GET', path, encode = () => undefined, project }) {
    if (!idPattern.test(connector) || !idPattern.test(operation) || !['GET','POST','PUT','PATCH','DELETE'].includes(method) || typeof path !== 'string' || !path.startsWith('/') || path.startsWith('//') || /[?#%\\\s]/.test(path) || typeof encode !== 'function' || typeof project !== 'function') fail();
    const key = connector + '/' + operation;
    if (this.#operations.has(key)) throw new Error('vault: duplicate connector operation');
    const def = Object.freeze({ connector, method, path, encode, project });
    this.#operations.set(key, def);
    return () => { if (this.#operations.get(key) === def) this.#operations.delete(key); };
  }
  async invoke(connector, operation, args, { signal } = {}) {
    const op = this.#operations.get(connector + '/' + operation);
    if (!op) throw new Error('vault: connector operation is not registered');
    const data = await this.#provider.store.read();
    if (!Object.hasOwn(data.connectors, connector)) throw new Error('vault: connector is not configured');
    const policy = validateConnector(data.connectors[connector]);
    const root = new URL(policy.baseURL + '/');
    const url = new URL(op.path.slice(1), root);
    if (url.origin !== root.origin || !url.pathname.startsWith(root.pathname)) fail();
    const credential = await this.#provider.resolve(policy.ref);
    if (!credential?.value) throw new Error('vault: connector credential is not configured');
    const secret = credential.value;
    try {
      const body = op.encode(args);
      const response = await fetch(url, { method: op.method, headers: { [policy.header]: policy.prefix + secret, Accept: 'application/json', ...(body === undefined ? {} : {'Content-Type':'application/json'}) }, body: body === undefined ? undefined : JSON.stringify(body), redirect: 'error', signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(30000)]) : AbortSignal.timeout(30000) });
      if (!response.ok) { await response.body?.cancel(); throw new Error('upstream'); }
      const chunks = []; let size = 0;
      for await (const chunk of response.body ?? []) { size += chunk.length; if (size > 2 * 1024 * 1024) { throw new Error('limit'); } chunks.push(chunk); }
      const value = op.project(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      // A trusted operation must project useful fields. Redaction is a final guard for literal echoes.
      const serialized = JSON.stringify(value);
      if (serialized === undefined) return null;
      const variants = [secret, policy.prefix + secret].flatMap(value => [value, Buffer.from(value).toString('base64'), Buffer.from(value).toString('base64url'), Buffer.from(value).toString('hex'), encodeURIComponent(value), JSON.stringify(value).slice(1,-1)]).filter(Boolean);
      let clean = serialized;
      for (const variant of variants.sort((a,b) => b.length-a.length)) clean = clean.split(variant).join('[REDACTED]');
      return JSON.parse(clean);
    } catch { throw new Error('vault: connector request failed'); }
  }
}
