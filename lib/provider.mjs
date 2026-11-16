import CredentialProvider from '@deepseek-ai/dsh-credentials';
import { Service } from '@deepseek-ai/cordis';
import { launchEnvironmentOf } from '@deepseek-ai/dsh-launch-environment';
import { resolveDshHome } from '@deepseek-ai/dsh-home-paths';
import { withFileLock, writeFileAtomic } from '@deepseek-ai/dsh-atomic-write';
import { readFile, lstat } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { parseDocument } from 'yaml';
import { VaultStore } from './store.mjs';
import { validateConnector } from './connectors.mjs';

const BACKUP = 'credential-vault/legacy-backup';
const MAX_TEXT = 1024 * 1024;
const own = (obj, key) => Object.hasOwn(obj, key);
const invalid = () => new TypeError('Invalid credential input');
const clone = value => value === undefined ? undefined : structuredClone(value);
const reserved = key => ['__proto__', 'constructor', 'prototype'].includes(key);

function refName(value) {
  if (typeof value !== 'string' || value.length > 256 || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(value) || reserved(value)) throw invalid();
  return value;
}
function recordKey(value) {
  if (typeof value !== 'string' || value.length > 256 || !/^[a-z][a-z0-9-]*\/[a-z][a-z0-9-]*$/.test(value)) throw invalid();
  return value;
}
function secret(value) {
  if (typeof value !== 'string' || !value.length || Buffer.byteLength(value) > MAX_TEXT || value.includes('\0')) throw invalid();
  return value;
}
function mapping(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) throw invalid();
  return value;
}
// Validate descriptors before reading fields: getters, sparse arrays, symbols and
// custom prototypes cannot silently change meaning at the JSON boundary.
function jsonValue(value) {
  let nodes = 0;
  const seen = new Set();
  function visit(v, depth) {
    if (++nodes > 100000 || depth > 48) throw invalid();
    if (v === null || typeof v === 'string' || typeof v === 'boolean') return;
    if (typeof v === 'number' && Number.isFinite(v)) return;
    if (typeof v !== 'object' || seen.has(v)) throw invalid();
    if (Array.isArray(v)) { if (Object.getPrototypeOf(v) !== Array.prototype) throw invalid(); }
    else mapping(v);
    seen.add(v);
    const keys = Reflect.ownKeys(v);
    if (Array.isArray(v) && keys.length !== v.length + 1) throw invalid();
    for (const key of keys) {
      if (Array.isArray(v) && key === 'length') continue;
      if (typeof key !== 'string' || reserved(key)) throw invalid();
      const descriptor = Object.getOwnPropertyDescriptor(v, key);
      if (!descriptor.enumerable || !own(descriptor, 'value')) throw invalid();
      visit(descriptor.value, depth + 1);
    }
    seen.delete(v);
  }
  visit(value, 0);
  if (Buffer.byteLength(JSON.stringify(value)) > MAX_TEXT) throw invalid();
  return value;
}
function record(value) {
  mapping(value);
  jsonValue(value);
  if (value.kind === 'grant') {
    if (Object.keys(value).some(k => !['kind', 'payload'].includes(k)) || !own(value, 'payload')) throw invalid();
  } else if (value.kind === 'api-key') {
    if (Object.keys(value).some(k => !['kind', 'key', 'env'].includes(k))) throw invalid();
    if (own(value, 'key')) secret(value.key);
    if (own(value, 'env')) {
      mapping(value.env);
      for (const [key, val] of Object.entries(value.env)) { refName(key); secret(val); }
    }
  } else throw invalid();
  return clone(value);
}
function sections(doc) {
  mapping(doc); mapping(doc.refs); mapping(doc.records); mapping(doc.connectors);
  if (doc.version !== 1) throw invalid();
  for (const [key, value] of Object.entries(doc.refs)) { refName(key); secret(value); }
  for (const [key, value] of Object.entries(doc.records)) { recordKey(key); record(value); }
  return doc;
}

/** Only synthetic dependencies should be injected by tests. No plaintext is
 * removed until an independent decrypt/read verifies every imported value. */
export async function migrateLegacyCredentials(store, filename, dependencies = {}) {
  const io = { readFile, lstat, withFileLock, writeFileAtomic, parseDocument, ...dependencies };
  try {
    let info;
    try { info = await io.lstat(filename); }
    catch (error) { if (error.code === 'ENOENT') return false; throw error; }
    if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1 || info.size > MAX_TEXT) throw invalid();
    return await io.withFileLock(filename, async () => {
      const currentInfo = await io.lstat(filename);
      if (!currentInfo.isFile() || currentInfo.isSymbolicLink() || currentInfo.nlink !== 1 || currentInfo.size > MAX_TEXT) throw invalid();
      const text = await io.readFile(filename, 'utf8');
      if (typeof text !== 'string' || Buffer.byteLength(text) > MAX_TEXT) throw invalid();
      const parsed = io.parseDocument(text, { uniqueKeys: true, prettyErrors: false });
      if (parsed.errors.length || parsed.warnings?.length) throw invalid();
      const root = parsed.toJS({ maxAliasCount: 100 }) ?? {};
      mapping(root); jsonValue(root);
      if (Object.keys(root).length && root.version !== 1) throw invalid();
      const refs = root.refs == null ? {} : mapping(root.refs);
      const records = root.records == null ? {} : mapping(root.records);
      for (const [key, value] of Object.entries(refs)) { refName(key); secret(value); }
      for (const [key, value] of Object.entries(records)) { recordKey(key); record(value); }
      // Even a refs-free file can contain old credential comments. Retain every
      // distinct original before discarding annotations from the remainder.
      const remainder = Object.fromEntries(Object.entries(root).filter(([k]) => k !== 'refs' && k !== 'records'));
      const sanitized = JSON.stringify(remainder, null, 2) + '\n';
      const before = sections(await store.read());
      if (!own(root, 'refs') && !own(root, 'records') && own(before.records, BACKUP) && text === sanitized) return false;
      let expectedBackup;
      await store.transaction(async doc => {
        sections(doc);
        for (const [section, values] of [['refs', refs], ['records', records]]) {
          for (const [key, value] of Object.entries(values)) {
            if (key === BACKUP) throw invalid();
            if (own(doc[section], key) && !isDeepStrictEqual(doc[section][key], value)) throw new Error('Legacy credential conflict');
          }
        }
        for (const [key, value] of Object.entries(refs)) doc.refs[key] = value;
        for (const [key, value] of Object.entries(records)) doc.records[key] = clone(value);
        if (!own(doc.records, BACKUP)) doc.records[BACKUP] = { kind: 'grant', payload: { text } };
        else {
          const backup = doc.records[BACKUP];
          if (backup.kind !== 'grant') throw invalid();
          const payload = mapping(backup.payload);
          if (typeof payload.text !== 'string' || (own(payload, 'history') && !Array.isArray(payload.history))) throw invalid();
          const history = payload.history ?? [];
          for (const item of history) {
            mapping(item);
            if (typeof item.text !== 'string') throw invalid();
          }
          if (payload.text !== text && !history.some(item => item.text === text)) payload.history = [...history, { text }];
        }
        // Apply the existing per-record JSON budget to the accumulated archive.
        // Overflow aborts the transaction and leaves the plaintext untouched.
        expectedBackup = record(doc.records[BACKUP]);
      });
      const verified = sections(await store.read());
      for (const [section, values] of [['refs', refs], ['records', records]]) {
        for (const [key, value] of Object.entries(values)) if (!own(verified[section], key) || !isDeepStrictEqual(verified[section][key], value)) throw invalid();
      }
      if (!isDeepStrictEqual(verified.records[BACKUP], expectedBackup)) throw invalid();
      await io.writeFileAtomic(filename, sanitized, { mode: 0o600, dirMode: 0o700 });
      return true;
    }, { waitMs: 30000 });
  } catch { throw new Error('Legacy credential migration failed; plaintext was not intentionally removed without verified encrypted storage'); }
}

export class VaultCredentialProvider extends CredentialProvider {
  constructor(ctx, config = {}) {
    super(ctx);
    this.config = config;
    const home = resolveDshHome(config.dshHome);
    this.store = new VaultStore(resolve(config.path ?? join(home, 'credential-vault', 'vault.bin')));
    this.legacyPath = join(home, '.credentials.yaml');
    this.closed = false;
  }
  async *[Service.init]() {
    yield () => { this.closed = true; };
    await migrateLegacyCredentials(this.store, this.legacyPath);
    await this.readDocument();
  }
  assertOpen() { if (this.closed) throw new Error('Credential vault is disposed'); }
  async readDocument() { this.assertOpen(); return sections(await this.store.read()); }
  inherited(ref) {
    const entry = launchEnvironmentOf(this.ctx).getFrom(ref, ['process']);
    return entry && typeof entry.value === 'string' && entry.value.length ? entry.value : undefined;
  }
  dotenvFallback(ref) {
    const entry = launchEnvironmentOf(this.ctx).getFrom(ref, ['project-env', 'user-env']);
    return entry && typeof entry.value === 'string' && entry.value.length ? entry : undefined;
  }
  async resolve(ref) {
    refName(ref);
    const doc = await this.readDocument();
    if (own(doc.refs, ref)) return { value: doc.refs[ref], source: 'file' };
    const inherited = this.inherited(ref);
    if (inherited !== undefined) return { value: inherited, source: 'env' };
    const fallback = this.dotenvFallback(ref);
    if (fallback) return { value: fallback.value, source: fallback.source };
    return undefined;
  }
  async describe(ref) {
    const value = await this.resolve(ref);
    return value ? { configured: true, source: value.source, writable: true } : { configured: false, writable: true };
  }
  async set(ref, value) {
    refName(ref); secret(value); this.assertOpen();
    await this.store.transaction(async doc => { this.assertOpen(); sections(doc); doc.refs[ref] = value; });
    this.notifyUpdated(ref);
  }
  async unset(ref) {
    refName(ref); this.assertOpen();
    const changed = await this.store.transaction(async doc => { this.assertOpen(); sections(doc); const had = own(doc.refs, ref); delete doc.refs[ref]; return had; });
    if (changed) this.notifyUpdated(ref);
  }
  async readRecord(key) { recordKey(key); this.assertOpen(); if (key === BACKUP) return undefined; const doc = await this.readDocument(); return own(doc.records, key) ? record(doc.records[key]) : undefined; }
  async describeRecord(key) {
    const value = await this.readRecord(key);
    return value ? { configured: true, kind: value.kind, writable: true } : { configured: false, writable: true };
  }
  async listRecords() {
    const doc = await this.readDocument();
    return Object.entries(doc.records).filter(([key]) => key !== BACKUP).map(([key, value]) => ({ key, kind: value.kind }));
  }
  async modifyRecord(key, mutate) {
    recordKey(key); this.assertOpen();
    if (key === BACKUP || typeof mutate !== 'function') throw invalid();
    const outcome = await this.store.transaction(async doc => {
      this.assertOpen(); sections(doc);
      const current = own(doc.records, key) ? record(doc.records[key]) : undefined;
      const next = await mutate(clone(current));
      this.assertOpen();
      if (next === undefined) return { changed: false, value: current };
      doc.records[key] = record(next);
      return { changed: true, value: clone(doc.records[key]) };
    });
    if (outcome.changed) this.notifyRecordUpdated(key);
    return outcome.value;
  }
  async deleteRecord(key) {
    recordKey(key); this.assertOpen(); if (key === BACKUP) throw invalid();
    const changed = await this.store.transaction(async doc => { this.assertOpen(); sections(doc); const had = own(doc.records, key); delete doc.records[key]; return had; });
    if (changed) this.notifyRecordUpdated(key);
  }
  async setConnector(input) {
    this.assertOpen();
    let connector;
    try { connector = validateConnector(input); jsonValue(connector); }
    catch { throw new TypeError('Invalid connector input'); }
    await this.store.transaction(async doc => { this.assertOpen(); sections(doc); doc.connectors[connector.id] = clone(connector); });
    return clone(connector);
  }
  async deleteConnector(id) {
    if (typeof id !== 'string' || id.length > 128 || !/^[a-z][a-z0-9-]*$/.test(id) || reserved(id)) throw new TypeError('Invalid connector input');
    this.assertOpen();
    await this.store.transaction(async doc => { this.assertOpen(); sections(doc); delete doc.connectors[id]; });
  }
  async publicSnapshot() {
    const doc = await this.readDocument();
    return {
      storage: 'windows-dpapi-current-user',
      refs: Object.keys(doc.refs).sort().map(ref => ({ ref, configured: true })),
      records: Object.entries(doc.records).filter(([key]) => key !== BACKUP).map(([key, value]) => ({ key, kind: value.kind })),
      connectors: Object.values(doc.connectors).map(value => {
        let connector;
        try { connector = validateConnector(value); } catch { throw new Error('Invalid stored connector'); }
        return Object.fromEntries(['id', 'label', 'ref', 'baseURL', 'header', 'prefix'].map(key => [key, connector[key]]));
      }),
    };
  }
}
export default VaultCredentialProvider;
