import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { randomBytes, createCipheriv, createDecipheriv } from 'node:crypto';
import { spawn } from 'node:child_process';
import { VaultStore } from '../lib/store.mjs';

const key = randomBytes(32); // Ephemeral synthetic test key only.
function cryptoFor(key) {
  return {
    protect(plain) {
      const iv = randomBytes(12);
      const cipher = createCipheriv('aes-256-gcm', key, iv);
      const data = Buffer.concat([cipher.update(plain), cipher.final()]);
      return Buffer.concat([iv, cipher.getAuthTag(), data]);
    },
    unprotect(data) {
      const decipher = createDecipheriv('aes-256-gcm', key, data.subarray(0, 12));
      decipher.setAuthTag(data.subarray(12, 28));
      return Buffer.concat([decipher.update(data.subarray(28)), decipher.final()]);
    }
  };
}
const crypto = cryptoFor(key);
async function fixture(t) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'dsh-vault-test-'));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const file = path.join(dir, 'vault.bin');
  return { dir, file, store: new VaultStore(file, crypto) };
}

test('missing store is empty; reopening preserves data without plaintext on disk', async t => {
  const { dir, file, store } = await fixture(t);
  assert.deepEqual(await store.read(), { version: 1, refs: {}, records: {}, connectors: {} });
  const secret = 'SYNTHETIC-secret-汉字-\u0000';
  assert.equal(await store.transaction(v => { v.records.demo = { secret }; return 42; }), 42);
  assert.equal((await new VaultStore(file, crypto).read()).records.demo.secret, secret);
  assert.equal((await fs.readFile(file)).includes(Buffer.from(secret)), false);
  assert.deepEqual(await fs.readdir(dir), ['vault.bin']);
});

test('authenticated ciphertext tampering fails closed and is never overwritten', async t => {
  const { file, store } = await fixture(t);
  await store.transaction(v => { v.records.demo = 'synthetic'; });
  const damaged = await fs.readFile(file);
  damaged[damaged.length - 1] ^= 1;
  await fs.writeFile(file, damaged);
  await assert.rejects(store.read());
  await assert.rejects(store.transaction(v => { v.records.other = 'bad'; }));
  assert.deepEqual(await fs.readFile(file), damaged);
});

test('empty, arbitrary and oversized files are rejected without rebuilding', async t => {
  const { file, store } = await fixture(t);
  for (const data of [Buffer.alloc(0), Buffer.from('corrupt'), Buffer.alloc(4 * 1024 * 1024 + 1)]) {
    await fs.writeFile(file, data);
    await assert.rejects(store.read());
    await assert.rejects(store.transaction(() => {}));
    assert.deepEqual(await fs.readFile(file), data);
  }
});

test('parallel transactions across instances do not lose writes', async t => {
  const { file, store } = await fixture(t);
  await Promise.all(Array.from({ length: 30 }, (_, i) => new VaultStore(file, crypto).transaction(async v => {
    await new Promise(resolve => setTimeout(resolve, 1));
    v.records['item' + i] = i;
    v.connectors.count = (v.connectors.count || 0) + 1;
  })));
  const value = await store.read();
  assert.equal(Object.keys(value.records).length, 30);
  assert.equal(value.connectors.count, 30);
});

test('independent Node processes serialize through mkdir lock', async t => {
  const { file, store } = await fixture(t);
  // Synthetic key is sent through stdin, never process arguments or environment.
  const worker = 'import { VaultStore } from ' + JSON.stringify(new URL('../lib/store.mjs', import.meta.url).href) + ';' +
    'import { randomBytes, createCipheriv, createDecipheriv } from "node:crypto";' +
    'let input=""; for await (const c of process.stdin) input+=c; const key=Buffer.from(input,"hex");' +
    'const crypto=(' + cryptoFor.toString() + ')(key); const s=new VaultStore(process.argv[1],crypto);' +
    'for(let i=0;i<8;i++) await s.transaction(async v=>{await new Promise(r=>setTimeout(r,2));v.connectors.count=(v.connectors.count||0)+1;});';
  await Promise.all(Array.from({ length: 4 }, () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--input-type=module', '-e', worker, file], { stdio: ['pipe', 'ignore', 'pipe'] });
    let diagnostic = '';
    child.stderr.on('data', chunk => { diagnostic += chunk; });
    child.on('error', reject);
    child.on('close', code => code === 0 ? resolve() : reject(new Error(diagnostic)));
    child.stdin.end(key.toString('hex'));
  })));
  assert.equal((await store.read()).connectors.count, 32);
});

test('invalid containers, non-JSON values and over-limit payload cannot replace valid file', async t => {
  const { file, store } = await fixture(t);
  await store.transaction(v => { v.records.good = true; });
  const before = await fs.readFile(file);
  for (const mutate of [v => { v.version = 2; }, v => { v.refs = []; }, v => { v.extra = {}; }, v => { v.records.no = undefined; }, v => { v.records.no = NaN; }, v => { v.records.no = new Date(); }, v => { v.records.no = v; }, v => { v.records.no = 'x'.repeat(4 * 1024 * 1024); }, v => { Object.defineProperty(v.records, 'no', { get() { throw new Error('SECRET'); }, enumerable: true }); }]) {
    await assert.rejects(store.transaction(mutate));
    assert.deepEqual(await fs.readFile(file), before);
  }
});

test('decrypted invalid schema is rejected', async t => {
  const { file } = await fixture(t);
  const store = new VaultStore(file, { protect: crypto.protect, unprotect: () => Buffer.from('{"version":1,"refs":{},"records":[]}') });
  await store.transaction(() => {});
  await assert.rejects(store.read());
  await assert.rejects(store.transaction(() => {}));
});

test('callback and crypto errors never expose secret, failed queue can recover', async t => {
  const { file, store } = await fixture(t);
  await assert.rejects(store.transaction(() => { throw new Error('SYNTHETIC-SECRET'); }), error => !String(error.stack).includes('SYNTHETIC-SECRET'));
  const bad = new VaultStore(file, { ...crypto, protect: () => { throw new Error('SYNTHETIC-SECRET'); } });
  await assert.rejects(bad.transaction(() => {}), error => !String(error.stack).includes('SYNTHETIC-SECRET'));
  await store.transaction(v => { v.records.ok = true; });
  assert.equal((await store.read()).records.ok, true);
});

test('links and junction ancestors are rejected', async t => {
  const { dir, file, store } = await fixture(t);
  const target = path.join(dir, 'target');
  await fs.mkdir(target);
  const link = path.join(dir, 'junction');
  await fs.symlink(target, link, process.platform === 'win32' ? 'junction' : 'dir');
  const linked = new VaultStore(path.join(link, 'vault.bin'), crypto);
  await assert.rejects(linked.read());
  await assert.rejects(linked.transaction(() => {}));
  await fs.writeFile(file, 'original');
  const hard = path.join(dir, 'hard');
  await fs.link(file, hard);
  await assert.rejects(store.read());
  await assert.rejects(store.transaction(() => {}));
  assert.equal(await fs.readFile(hard, 'utf8'), 'original');
});

test('existing lock times out without automatic lock breaking', { timeout: 15000 }, async t => {
  const { file, store } = await fixture(t);
  await fs.mkdir(file + '.lock');
  // An ancient timestamp must not permit takeover.
  await fs.utimes(file + '.lock', new Date(0), new Date(0));
  await assert.rejects(store.transaction(() => {}), /lock timed out/);
  assert.equal((await fs.stat(file + '.lock')).isDirectory(), true);
});

test('default Windows PowerShell 5.1 DPAPI round-trip with synthetic data', { skip: process.platform !== 'win32' }, async t => {
  const { file } = await fixture(t);
  const store = new VaultStore(file);
  await store.transaction(v => { v.records.test = { secret: 'SYNTHETIC-DPAPI-凭据' }; });
  assert.equal((await new VaultStore(file).read()).records.test.secret, 'SYNTHETIC-DPAPI-凭据');
  assert.equal((await fs.readFile(file)).includes(Buffer.from('SYNTHETIC-DPAPI')), false);
  const corrupt = await fs.readFile(file);
  corrupt[corrupt.length - 1] ^= 1;
  await fs.writeFile(file, corrupt);
  await assert.rejects(store.read());
});

test('default crypto refuses non-Windows writes', { skip: process.platform === 'win32' }, async t => {
  const { file } = await fixture(t);
  await assert.rejects(new VaultStore(file).transaction(() => {}), /encryption failed/);
});
