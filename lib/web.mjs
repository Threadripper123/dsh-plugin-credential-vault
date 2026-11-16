import { readFile } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';

const ROOT = '/credential-vault';
const MAX_BODY = 64 * 1024;
const REQUEST_MS = 15000;
class HttpError extends Error { constructor(status) { super('Vault request rejected'); this.status = status; } }
const reject = status => { throw new HttpError(status); };
const messages = { 400: '请求格式无效', 401: '请先登录 DSH', 403: '请求被拒绝', 404: '页面不存在', 405: '不支持此请求方法', 408: '请求超时', 413: '请求内容过大', 415: '请使用 JSON', 429: '请求过于频繁，请稍后再试', 500: '操作失败，请检查本机服务' };

function header(req, key) {
  const value = req.headers[key];
  if (value === undefined) return undefined;
  if (typeof value !== 'string') reject(400);
  // Node retains duplicate security headers in rawHeaders even when headers coalesces them.
  if (req.rawHeaders) {
    let count = 0;
    for (let i = 0; i < req.rawHeaders.length; i += 2) if (req.rawHeaders[i].toLowerCase() === key) count++;
    if (count > 1) reject(400);
  }
  return value;
}
function checkOrigin(req, port) {
  const host = header(req, 'host');
  const match = /^(localhost|127\.0\.0\.1|\[::1\])(?::([1-9][0-9]{0,4}))?$/.exec(host || '');
  const scheme = req.socket?.encrypted ? 'https' : 'http';
  const effectivePort = match?.[2] ? Number(match[2]) : scheme === 'https' ? 443 : 80;
  if (!match || !Number.isInteger(port) || port < 1 || port > 65535 || effectivePort !== port) reject(403);
  const origin = header(req, 'origin');
  if ((req.method === 'POST' && origin === undefined) || (origin !== undefined && origin !== scheme + '://' + host)) reject(403);
  const site = header(req, 'sec-fetch-site');
  if (site && site !== 'same-origin' && site !== 'none') reject(403);
  if (req.method === 'POST' && header(req, 'x-dsh-vault') !== '1') reject(403);
}
function readBody(req) {
  const type = header(req, 'content-type');
  if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(type || '')) reject(415);
  if (header(req, 'content-encoding') !== undefined) reject(415);
  const declared = header(req, 'content-length');
  if (declared !== undefined && (!/^[0-9]+$/.test(declared) || Number(declared) > MAX_BODY)) reject(413);
  return new Promise((resolve, rejectBody) => {
    let size = 0;
    const chunks = [];
    const timer = setTimeout(() => finish(new HttpError(408)), 10000);
    function finish(error, value) {
      clearTimeout(timer);
      req.off('data', onData); req.off('end', onEnd); req.off('aborted', onAbort); req.off('error', onAbort);
      if (error) { req.resume(); rejectBody(error); } else resolve(value);
    }
    function onData(chunk) { size += chunk.length; if (size > MAX_BODY) finish(new HttpError(413)); else chunks.push(Buffer.from(chunk)); }
    function onAbort() { finish(new HttpError(400)); }
    function onEnd() {
      try { const text = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks)); finish(null, JSON.parse(text)); }
      catch { finish(new HttpError(400)); }
    }
    req.on('data', onData); req.once('end', onEnd); req.once('aborted', onAbort); req.once('error', onAbort);
  });
}
function command(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) reject(400);
  const keys = { set: ['action','ref','value'], unset: ['action','ref'], 'connector-set': ['action','id','label','ref','baseURL','header','prefix'], 'connector-delete': ['action','id'] };
  const allowed = Object.hasOwn(keys, body.action) ? keys[body.action] : undefined;
  if (!allowed || Object.keys(body).some(key => !allowed.includes(key))) reject(400);
  for (const key of allowed) {
    if (typeof body[key] !== 'string' || body[key].length > (key === 'value' ? 60000 : 2048) || (key !== 'value' && /[\r\n\0]/.test(body[key]))) reject(400);
  }
  for (const key of ['ref', 'id']) if (allowed.includes(key) && !body[key].trim()) reject(400);
  return body;
}
function bounded(promise, ms = REQUEST_MS) {
  let timer;
  return Promise.race([promise, new Promise((_, no) => { timer = setTimeout(() => no(new HttpError(408)), ms); })]).finally(() => clearTimeout(timer));
}
function send(res, status, value, html = false) {
  if (res.destroyed || res.writableEnded) return;
  res.statusCode = status;
  res.setHeader('Content-Type', html ? 'text/html; charset=utf-8' : 'application/json; charset=utf-8');
  res.end(html ? value : JSON.stringify(value));
}

/** Register an owner-only HTTP surface; intentionally exposes no agent management tool. */
export function registerWeb(ctx, provider) {
  const rates = new Map();
  let active = 0;
  let writing = false;
  const disposer = ctx.webServer.register({ kind: 'prefix', path: ROOT, async handler(req, res) {
    let counted = false;
    let ownsWrite = false;
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
    res.setHeader('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'; base-uri 'none'");
    try {
      checkOrigin(req, ctx.webServer.port);
      const pathname = (req.url || '').split('?')[0];
      if (pathname !== ROOT && pathname !== ROOT + '/' && pathname !== ROOT + '/api') reject(404);
      if (req.method !== 'GET' && req.method !== 'POST') { res.setHeader('Allow', 'GET, POST'); reject(405); }
      if (req.method === 'POST' && pathname !== ROOT + '/api') reject(405);
      const now = Date.now();
      for (const [key, state] of rates) if (state.until <= now) rates.delete(key);
      const key = req.socket?.remoteAddress || 'unknown';
      let rate = rates.get(key);
      if (!rate) { if (rates.size >= 1024) reject(429); rates.set(key, rate = { count: 0, until: now + 60000 }); }
      if (++rate.count > 60 || active >= 16) { res.setHeader('Retry-After', '60'); reject(429); }
      active++; counted = true;
      // HTTP admission only authenticates: it neither claims a socket nor owns the Peer.
      const admission = await bounded(Promise.resolve().then(() => ctx.connection.admit(req)));
      if (!admission || !admission.peer || admission.rejection) reject(admission?.rejection === 403 ? 403 : 401);
      if (admission.peer.principal?.kind !== 'owner') reject(403);
      if (req.method === 'GET') {
        if (pathname === ROOT + '/api') send(res, 200, await bounded(Promise.resolve().then(() => provider.publicSnapshot())));
        else {
          const nonce = randomBytes(24).toString('base64');
          const template = await readFile(new URL('./ui.html', import.meta.url), 'utf8');
          res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'nonce-" + nonce + "'; style-src 'nonce-" + nonce + "'; connect-src 'self'; img-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
          send(res, 200, template.replaceAll('__VAULT_NONCE__', nonce), true);
        }
      } else {
        if (writing) { res.setHeader('Retry-After', '1'); reject(429); }
        // Claim before body parsing, so concurrent uploads cannot queue mutations.
        writing = true; ownsWrite = true;
        const body = command(await readBody(req));
        // A timeout cannot cancel a transaction: report its real outcome and retain
        // both busy and active admission until it settles, including on disconnect.
        await Promise.resolve().then(() => {
          switch (body.action) {
            case 'set': return provider.set(body.ref, body.value);
            case 'unset': return provider.unset(body.ref);
            case 'connector-set': { const { action, ...connector } = body; return provider.setConnector(connector); }
            case 'connector-delete': return provider.deleteConnector(body.id);
          }
        });
        send(res, 200, { ok: true });
      }
    } catch (error) {
      const status = error instanceof HttpError ? error.status : 500;
      send(res, status, { error: messages[status] || messages[500] });
    } finally {
      if (ownsWrite) writing = false;
      if (counted) active--;
    }
  } });
  ctx.effect(() => disposer);
  return disposer;
}
