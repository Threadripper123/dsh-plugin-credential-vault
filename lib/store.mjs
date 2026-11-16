import { constants } from 'node:fs';
import * as fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';

const MAX = 4 * 1024 * 1024;
const MAGIC = Buffer.from('DSHVAULT1\0', 'ascii');
const queues = new Map();
const empty = () => ({ version: 1, refs: {}, records: {}, connectors: {} });
const fail = (message) => new Error(message);
const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

function bytes(value) {
  if (!Buffer.isBuffer(value) && !(value instanceof Uint8Array)) throw fail('Vault crypto returned invalid bytes');
  const result = Buffer.from(value);
  if (!result.length || result.length > MAX) throw fail('Vault size limit exceeded');
  return result;
}

function validate(value) {
  let nodes = 0;
  const seen = new Set();
  function visit(v, depth) {
    if (++nodes > 500000 || depth > 64) throw fail('Invalid vault container');
    if (v === null || typeof v === 'string' || typeof v === 'boolean') return;
    if (typeof v === 'number' && Number.isFinite(v)) return;
    if (typeof v !== 'object' || seen.has(v)) throw fail('Invalid vault container');
    const proto = Object.getPrototypeOf(v);
    if (!Array.isArray(v) && proto !== Object.prototype && proto !== null) throw fail('Invalid vault container');
    if (Array.isArray(v) && proto !== Array.prototype) throw fail('Invalid vault container');
    seen.add(v);
    const keys = Reflect.ownKeys(v);
    if (Array.isArray(v) && keys.length !== v.length + 1) throw fail('Invalid vault container');
    for (const key of keys) {
      if (Array.isArray(v) && key === 'length') continue;
      if (Array.isArray(v) && (typeof key !== 'string' || !/^(0|[1-9][0-9]*)$/.test(key) || Number(key) >= v.length)) throw fail('Invalid vault container');
      if (typeof key !== 'string' || ['__proto__', 'prototype', 'constructor'].includes(key)) throw fail('Invalid vault container');
      const d = Object.getOwnPropertyDescriptor(v, key);
      if (!d.enumerable || !('value' in d)) throw fail('Invalid vault container');
      visit(d.value, depth + 1);
    }
    seen.delete(v);
  }
  visit(value, 0);
  if (!value || Array.isArray(value) || typeof value !== 'object' ||
      Object.keys(value).sort().join(',') !== 'connectors,records,refs,version' || value.version !== 1) throw fail('Invalid vault container');
  for (const key of ['refs', 'records', 'connectors']) {
    if (!value[key] || typeof value[key] !== 'object' || Array.isArray(value[key])) throw fail('Invalid vault container');
  }
  const encoded = Buffer.from(JSON.stringify(value), 'utf8');
  if (encoded.length > MAX) throw fail('Vault size limit exceeded');
  return encoded;
}

async function statMaybe(filename) {
  try { return await fs.lstat(filename); }
  catch (error) { if (error.code === 'ENOENT') return null; throw fail('Vault filesystem access failed'); }
}

// Refuse links in every existing component, including Windows junctions.
async function directories(directory, create = false) {
  const root = path.parse(directory).root;
  let current = root;
  for (const part of directory.slice(root.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, part);
    let info = await statMaybe(current);
    if (!info && create) {
      try { await fs.mkdir(current, { mode: 0o700 }); }
      catch (error) { if (error.code !== 'EEXIST') throw fail('Vault directory creation failed'); }
      info = await statMaybe(current);
    }
    if (!info) return false;
    if (info.isSymbolicLink() || !info.isDirectory()) throw fail('Unsafe vault path');
  }
  return true;
}

async function regular(filename) {
  const info = await statMaybe(filename);
  if (info && (info.isSymbolicLink() || !info.isFile() || info.nlink !== 1)) throw fail('Unsafe vault file');
  return info;
}

function dpapi(mode, input) {
  if (process.platform !== 'win32') return Promise.reject(fail('Windows DPAPI is required'));
  return new Promise((resolve, reject) => {
    const executable = path.join(process.env.SystemRoot || 'C:/Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
    const script = fileURLToPath(new URL('./dpapi.ps1', import.meta.url));
    let child;
    try { child = spawn(executable, ['-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', script, mode], { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true }); }
    catch { reject(fail('DPAPI operation failed')); return; }
    const chunks = [];
    let length = 0;
    let done = false;
    const timer = setTimeout(() => { child.kill(); finish(); }, 30000);
    function finish(result) {
      if (done) return;
      done = true;
      clearTimeout(timer);
      if (result) resolve(result); else reject(fail('DPAPI operation failed'));
    }
    child.on('error', () => finish());
    child.stdin.on('error', () => finish());
    child.stdout.on('data', chunk => {
      length += chunk.length;
      if (length > MAX) { child.kill(); finish(); }
      else chunks.push(chunk);
    });
    // Never retain or forward PowerShell diagnostics, which could contain input.
    child.stderr.on('data', () => {});
    child.on('close', code => finish(code === 0 && length > 0 ? Buffer.concat(chunks) : undefined));
    child.stdin.end(input);
  });
}

/** Whole-document encrypted store. Crypto adapters accept and return Buffer/Uint8Array. */
export class VaultStore {
  constructor(filename, { protect = input => dpapi('protect', input), unprotect = input => dpapi('unprotect', input) } = {}) {
    if (typeof filename !== 'string' || !filename || typeof protect !== 'function' || typeof unprotect !== 'function') throw fail('Invalid vault configuration');
    this.filename = path.resolve(filename);
    this.protect = protect;
    this.unprotect = unprotect;
  }

  async read() {
    try {
      if (!await directories(path.dirname(this.filename))) return empty();
      const info = await regular(this.filename);
      if (!info) return empty();
      if (info.size <= MAGIC.length || info.size > MAX) throw fail('Invalid encrypted vault');
      const handle = await fs.open(this.filename, constants.O_RDONLY | (constants.O_NOFOLLOW || 0));
      let file;
      try {
        const opened = await handle.stat();
        if (!opened.isFile() || opened.nlink !== 1 || opened.ino !== info.ino || opened.dev !== info.dev) throw fail('Unsafe vault file');
        // Bounded read prevents a file growing after lstat from allocating unbounded memory.
        file = Buffer.alloc(MAX + 1);
        let offset = 0;
        while (offset < file.length) {
          const result = await handle.read(file, offset, file.length - offset, offset);
          if (!result.bytesRead) break;
          offset += result.bytesRead;
        }
        file = file.subarray(0, offset);
      } finally { await handle.close(); }
      if (file.length > MAX || !file.subarray(0, MAGIC.length).equals(MAGIC)) throw fail('Invalid encrypted vault');
      let plain;
      try { plain = bytes(await this.unprotect(file.subarray(MAGIC.length))); }
      catch { throw fail('Vault decryption failed'); }
      try {
        const text = new TextDecoder('utf-8', { fatal: true }).decode(plain);
        const document = JSON.parse(text);
        validate(document);
        return document;
      } finally { plain.fill(0); }
    } catch { throw fail('Vault read failed: invalid, unsafe, or inaccessible data'); }
  }

  async transaction(fn) {
    if (typeof fn !== 'function') throw fail('Invalid vault transaction');
    const key = process.platform === 'win32' ? this.filename.toLowerCase() : this.filename;
    const previous = queues.get(key) || Promise.resolve();
    const task = previous.catch(() => {}).then(() => this._transaction(fn));
    queues.set(key, task);
    try { return await task; }
    finally { if (queues.get(key) === task) queues.delete(key); }
  }

  async _transaction(fn) {
    const directory = path.dirname(this.filename);
    const lock = this.filename + '.lock';
    let held = false;
    let temp;
    let identity;
    try {
      await directories(directory, true);
      const deadline = Date.now() + 10000;
      while (!held) {
        try { await fs.mkdir(lock, { mode: 0o700 }); held = true; identity = await fs.lstat(lock); }
        catch (error) {
          if (error.code !== 'EEXIST') throw fail('Vault lock acquisition failed');
          const info = await statMaybe(lock);
          if (info && (info.isSymbolicLink() || !info.isDirectory())) throw fail('Unsafe vault lock');
          if (Date.now() >= deadline) throw fail('Vault lock timed out; manual recovery required');
          await sleep(25 + Math.floor(Math.random() * 25));
          await directories(directory);
        }
      }
      const document = await this.read();
      let result;
      try { result = await fn(document); } catch { throw fail('Vault transaction callback failed'); }
      const plain = validate(document);
      let cipher;
      try { cipher = bytes(await this.protect(plain)); }
      catch { throw fail('Vault encryption failed'); }
      finally { plain.fill(0); }
      if (cipher.length + MAGIC.length > MAX) throw fail('Vault size limit exceeded');
      await directories(directory);
      await regular(this.filename);
      temp = this.filename + '.' + randomUUID() + '.tmp';
      const handle = await fs.open(temp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW || 0), 0o600);
      try { await handle.writeFile(Buffer.concat([MAGIC, cipher])); await handle.sync(); }
      finally { await handle.close(); }
      await directories(directory);
      await regular(this.filename);
      await fs.rename(temp, this.filename);
      temp = undefined;
      // Windows does not support opening directories for fsync.
      if (process.platform !== 'win32') {
        const parent = await fs.open(directory, constants.O_RDONLY);
        try { await parent.sync(); } finally { await parent.close(); }
      }
      return result;
    } catch (error) {
      const safe = ['Vault lock timed out; manual recovery required', 'Vault transaction callback failed', 'Vault encryption failed', 'Vault size limit exceeded', 'Invalid vault container', 'Vault read failed: invalid, unsafe, or inaccessible data', 'Unsafe vault path', 'Unsafe vault file', 'Unsafe vault lock'];
      throw fail(safe.includes(error.message) ? error.message : 'Vault transaction failed');
    } finally {
      if (temp) await fs.unlink(temp).catch(() => {});
      if (held) {
        const info = await statMaybe(lock);
        if (info && !info.isSymbolicLink() && info.ino === identity?.ino && info.dev === identity?.dev) {
          try { await fs.rmdir(lock); } catch { throw fail('Vault lock release failed; manual recovery required'); }
        }
      }
    }
  }
}
