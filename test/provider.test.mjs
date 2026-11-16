import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, mkdtemp, writeFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import { randomBytes, createCipheriv, createDecipheriv } from 'node:crypto';
import { VaultStore } from '../lib/store.mjs';

// Load the actual provider body with service seams substituted; never activate a
// real provider or access the user's credential path. YAML is the real parser.
const require = createRequire(import.meta.url);
let yamlPath;
try { yamlPath = require.resolve('yaml'); }
catch { yamlPath = createRequire(path.join(process.env.DSH_HOME || path.join(os.homedir(), '.dsh'), 'profiles', 'desktop', 'package.json')).resolve('yaml'); }
const moduleURL = code => 'data:text/javascript;base64,' + Buffer.from(code).toString('base64');
const service = moduleURL('export const Service = {init: Symbol.for("vault-test-init")};');
const base = moduleURL('export default class { constructor(ctx){this.ctx=ctx;} notifyUpdated(ref){this.ctx.notifications.push(["ref",ref]);} notifyRecordUpdated(key){this.ctx.notifications.push(["record",key]);} }');
const environment = moduleURL('export const launchEnvironmentOf = ctx => ctx.environment;');
const home = moduleURL('export const resolveDshHome = value => value || "synthetic-test-home";');
const atomic = moduleURL('export const withFileLock = async (_path, fn) => fn(); export const writeFileAtomic = async () => { throw Error("test IO must be injected"); };');
let source = await readFile(new URL('../lib/provider.mjs', import.meta.url), 'utf8');
for (const [name, url] of Object.entries({
  '@deepseek-ai/dsh-credentials': base,
  '@deepseek-ai/cordis': service,
  '@deepseek-ai/dsh-launch-environment': environment,
  '@deepseek-ai/dsh-home-paths': home,
  '@deepseek-ai/dsh-atomic-write': atomic,
  yaml: pathToFileURL(yamlPath).href,
  './store.mjs': new URL('../lib/store.mjs', import.meta.url).href,
  './connectors.mjs': new URL('../lib/connectors.mjs', import.meta.url).href,
})) source = source.replaceAll("'" + name + "'", JSON.stringify(url));
const { VaultCredentialProvider, migrateLegacyCredentials } = await import(moduleURL(source));
const BACKUP = 'credential-vault/legacy-backup';
test('real Cordis service activation migrates synthetic YAML before consumers and disposes cleanly', {skip:!process.versions.electron}, async t => {
  const { Context } = await import('@deepseek-ai/cordis');
  const { default: RealProvider } = await import('../lib/provider.mjs');
  const dir = await mkdtemp(path.join(os.tmpdir(),'dsh-provider-lifecycle-'));
  t.after(()=>rm(dir,{recursive:true,force:true}));
  await writeFile(path.join(dir,'.credentials.yaml'), 'version: 1\nrefs: {SYNTHETIC_KEY: synthetic-lifecycle}\n');
  const store = memoryStore();
  class SyntheticProvider extends RealProvider {
    constructor(ctx,config) {super(ctx,config);this.store=store;}
  }
  const ctx = new Context();
  const fiber = ctx.plugin(SyntheticProvider,{dshHome:dir});
  await fiber.await();
  const active = ctx.credentials;
  assert.ok(active instanceof RealProvider);
  assert.deepEqual(await active.resolve('SYNTHETIC_KEY'),{value:'synthetic-lifecycle',source:'file'});
  assert.deepEqual(JSON.parse(await readFile(path.join(dir,'.credentials.yaml'),'utf8')),{version:1});
  const management = await import('../lib/index.mjs');
  const routes = [];
  ctx.provide('connection', {readToken: async () => 'synthetic-auth'});
  ctx.provide('webServer', {port:3335,register(route){routes.push(route);return ()=>{};}});
  const manager = ctx.plugin(management);
  await manager.await();
  await ctx.registry.get('credential-vault-management')?.await?.();
  assert.ok(ctx.connectorVault);
  const unregister = ctx.connectorVault.register({connector:'demo',operation:'list',path:'/items',project:value=>value});
  assert.equal(typeof unregister,'function'); unregister();
  assert.equal(routes.length,1);
  await manager.dispose();
  await fiber.dispose();
  assert.equal(active.closed,true);
  await assert.rejects(active.set('SYNTHETIC_KEY','synthetic-after-close'),/disposed/);
});
function memoryStore(initial = {version:1, refs:{}, records:{}, connectors:{}}) {
  let data = structuredClone(initial), queue = Promise.resolve();
  return {
    read: async () => structuredClone(data),
    transaction(fn) {
      const task = queue.then(async () => { const draft = structuredClone(data); const value = await fn(draft); data = draft; return value; });
      queue = task.catch(() => {}); return task;
    },
  };
}
function provider(store = memoryStore()) {
  const ctx = {notifications: [], environment: {getFrom(ref, sources) {
    if (ref !== 'SYNTHETIC_KEY') return undefined;
    return sources[0] === 'process' ? {value:'synthetic-env',source:'env'} : {value:'synthetic-dotenv',source:'project-env'};
  }}};
  const result = new VaultCredentialProvider(ctx, {dshHome:'synthetic-test-home'});
  result.store = store;
  return result;
}
function legacyIO(text) {
  let current = text, writes = 0;
  return {
    get text() {return current;}, get writes() {return writes;},
    lstat: async () => ({isFile:()=>true,isSymbolicLink:()=>false,nlink:1,size:Buffer.byteLength(current)}),
    readFile: async () => current,
    withFileLock: async (_file, fn) => fn(),
    writeFileAtomic: async (_file, next) => {writes++; current=next;},
  };
}
const legacy = '# synthetic-comment-secret\nversion: 1\nrefs:\n  SYNTHETIC_KEY: synthetic-stored\nrecords:\n  demo/grant:\n    kind: grant\n    payload: {token: synthetic-token}\nforeign: {enabled: true}\n';

test('refs preserve stored/process/dotenv precedence and metadata shape', async () => {
  const p = provider();
  assert.deepEqual(await p.resolve('SYNTHETIC_KEY'), {value:'synthetic-env',source:'env'});
  await p.set('SYNTHETIC_KEY','synthetic-stored');
  assert.deepEqual(await p.resolve('SYNTHETIC_KEY'), {value:'synthetic-stored',source:'file'});
  assert.deepEqual(await p.describe('SYNTHETIC_KEY'), {configured:true,source:'file',writable:true});
  await p.unset('SYNTHETIC_KEY');
  p.ctx.environment.getFrom = (_ref, sources) => sources[0] === 'process' ? undefined : {value:'synthetic-dotenv',source:'project-env'};
  assert.equal((await p.resolve('SYNTHETIC_KEY')).source,'project-env');
  p.ctx.environment.getFrom = () => undefined;
  assert.deepEqual(await p.describe('ABSENT'), {configured:false,writable:true});
});
test('records serialize mutations, isolate callback/read values and implement undefined as no-op', async () => {
  const p = provider();
  await p.modifyRecord('demo/grant', () => ({kind:'grant',payload:{n:0}}));
  await Promise.all(Array.from({length:12}, () => p.modifyRecord('demo/grant', async current => ({kind:'grant',payload:{n:current.payload.n+1}}))));
  const retained = await p.modifyRecord('demo/grant', current => { current.payload.n=999; });
  assert.equal(retained.payload.n,12);
  const read = await p.readRecord('demo/grant'); read.payload.n=888;
  assert.equal((await p.readRecord('demo/grant')).payload.n,12);
  await p.modifyRecord('demo/api', () => ({kind:'api-key',env:{SYNTHETIC_KEY:'synthetic-value'}}));
  assert.deepEqual(await p.describeRecord('demo/api'),{configured:true,kind:'api-key',writable:true});
  await p.deleteRecord('demo/api');
  assert.equal(await p.readRecord('demo/api'),undefined);
  assert.deepEqual(await p.describeRecord('demo/api'),{configured:false,writable:true});
});
test('invalid names, tags, fields, JSON values and getter payloads fail without echo', async () => {
  const p = provider();
  for (const name of ['bad/name', '', 'A'.repeat(257), '__proto__']) await assert.rejects(p.set(name,'synthetic-secret'), /Invalid credential input/);
  for (const val of ['', 5, null, 'A'.repeat(1048577)]) await assert.rejects(p.set('SYNTHETIC_KEY',val), /Invalid credential input/);
  const cyclic = {}; cyclic.self=cyclic;
  const accessor = {}; Object.defineProperty(accessor,'token',{enumerable:true,get(){throw Error('synthetic-secret');}});
  for (const value of [{kind:'synthetic-secret'}, {kind:'api-key',key:2}, {kind:'api-key',env:{BAD_NAME:''}}, {kind:'api-key',extra:'synthetic-secret'}, {kind:'grant'}, ...[cyclic, new Date(), 1n, NaN, undefined, new Array(2), accessor].map(payload => ({kind:'grant',payload}))]) {
    await assert.rejects(p.modifyRecord('demo/grant',()=>value), error=>error.message==='Invalid credential input');
  }
});
test('public snapshot has only declared metadata and hides backup', async () => {
  const p = provider(); await p.set('SYNTHETIC_KEY','synthetic-secret');
  await p.modifyRecord('demo/grant',()=>({kind:'grant',payload:'synthetic-payload'}));
  await p.store.transaction(doc => {doc.records[BACKUP]={kind:'grant',payload:{text:'synthetic-backup'}};});
  const policy = {id:'demo',label:'Demo',ref:'SYNTHETIC_KEY',baseURL:'https://api.example.com',header:'Authorization',prefix:'Bearer '};
  await p.setConnector(policy);
  assert.deepEqual(await p.publicSnapshot(),{storage:'windows-dpapi-current-user',refs:[{ref:'SYNTHETIC_KEY',configured:true}],records:[{key:'demo/grant',kind:'grant'}],connectors:[policy]});
  assert.deepEqual(await p.listRecords(),[{key:'demo/grant',kind:'grant'}]);
  assert.equal(await p.readRecord(BACKUP),undefined);
  assert.deepEqual(await p.describeRecord(BACKUP),{configured:false,writable:true});
  await assert.rejects(p.modifyRecord(BACKUP,()=>({kind:'grant',payload:{text:'synthetic-replacement'}})));
  await assert.rejects(p.deleteRecord(BACKUP));
  await p.deleteConnector('demo'); assert.deepEqual((await p.publicSnapshot()).connectors,[]);
});
test('legacy migration stores original once, removes comments and sections and preserves foreign fields', async () => {
  const store=memoryStore(), io=legacyIO(legacy);
  assert.equal(await migrateLegacyCredentials(store,'synthetic.yaml',io),true);
  const data=await store.read();
  assert.equal(data.refs.SYNTHETIC_KEY,'synthetic-stored');
  assert.equal(data.records[BACKUP].payload.text,legacy);
  assert.deepEqual(JSON.parse(io.text),{version:1,foreign:{enabled:true}});
  assert.equal(await migrateLegacyCredentials(store,'synthetic.yaml',io),false);
  assert.equal(io.writes,1);
  assert.equal((await store.read()).records[BACKUP].payload.text,legacy);
});
test('later legacy originals including comment-only secrets are retained and independently verified', async () => {
  const store=memoryStore();
  await migrateLegacyCredentials(store,'synthetic.yaml',legacyIO(legacy));
  const second="# synthetic-new-comment-secret\nversion: 1\n";
  const io=legacyIO(second);
  let reads=0;
  const observed={transaction:fn=>store.transaction(fn),read:async()=>{reads++;return store.read();}};
  assert.equal(await migrateLegacyCredentials(observed,'synthetic.yaml',io),true);
  assert.equal(reads,2);
  assert.deepEqual((await store.read()).records[BACKUP].payload,{text:legacy,history:[{text:second}]});
  assert.deepEqual(JSON.parse(io.text),{version:1});
  const third="# synthetic-third-comment-secret\nversion: 1\n";
  const retained=await store.read(), blocked=legacyIO(third);
  let failedReads=0;
  const stale={transaction:fn=>store.transaction(fn),read:async()=>++failedReads===1?store.read():structuredClone(retained)};
  await assert.rejects(migrateLegacyCredentials(stale,'synthetic.yaml',blocked),/Legacy credential migration failed/);
  assert.equal(failedReads,2); assert.equal(blocked.text,third); assert.equal(blocked.writes,0);
});
test('later cleanup interruption retries deduplicate by text and preserve the first original', async () => {
  const store=memoryStore();
  await migrateLegacyCredentials(store,'synthetic.yaml',legacyIO(legacy));
  const second="# synthetic-retry-comment-secret\nversion: 1\nrefs: {SYNTHETIC_SECOND: synthetic-second}\n";
  const io=legacyIO(second);
  for(let attempt=0;attempt<2;attempt++) {
    await assert.rejects(migrateLegacyCredentials(store,'synthetic.yaml',{...io,writeFileAtomic:async()=>{throw Error('synthetic-interruption');}}));
    assert.equal(io.text,second);
    assert.deepEqual((await store.read()).records[BACKUP].payload,{text:legacy,history:[{text:second}]});
  }
  assert.equal(await migrateLegacyCredentials(store,'synthetic.yaml',io),true);
  assert.deepEqual((await store.read()).records[BACKUP].payload,{text:legacy,history:[{text:second}]});
  // Reintroducing the first original also needs no history entry.
  await migrateLegacyCredentials(store,'synthetic.yaml',legacyIO(legacy));
  assert.deepEqual((await store.read()).records[BACKUP].payload,{text:legacy,history:[{text:second}]});
});
test('accumulated backup budget and malformed history fail closed without changing plaintext', async () => {
  const first='# '+ 'A'.repeat(600000)+"\nversion: 1\n";
  const second='# '+ 'B'.repeat(600000)+"\nversion: 1\nrefs: {SYNTHETIC_NEW: synthetic-new}\n";
  const store=memoryStore();
  await migrateLegacyCredentials(store,'synthetic.yaml',legacyIO(first));
  const before=await store.read(), io=legacyIO(second);
  await assert.rejects(migrateLegacyCredentials(store,'synthetic.yaml',io),/Legacy credential migration failed/);
  assert.equal(io.text,second); assert.equal(io.writes,0); assert.deepEqual(await store.read(),before);
  for(const payload of [{text:legacy,history:null},{text:legacy,history:['synthetic-invalid']},{history:[]}]) {
    const bad=memoryStore(); await bad.transaction(doc=>{doc.records[BACKUP]={kind:'grant',payload};});
    const source=legacyIO(legacy);
    await assert.rejects(migrateLegacyCredentials(bad,'synthetic.yaml',source),/Legacy credential migration failed/);
    assert.equal(source.text,legacy); assert.equal(source.writes,0);
  }
});
test('legacy conflicts fail closed and leave both source and destination unchanged', async () => {
  for (const conflict of ['refs','records']) {
    const store=memoryStore(), io=legacyIO(legacy);
    await store.transaction(doc=>{ if(conflict==='refs') doc.refs.SYNTHETIC_KEY='synthetic-different'; else doc.records['demo/grant']={kind:'grant',payload:{token:'synthetic-different'}}; });
    const before=await store.read();
    await assert.rejects(migrateLegacyCredentials(store,'synthetic.yaml',io),/Legacy credential migration failed/);
    assert.deepEqual(await store.read(),before); assert.equal(io.text,legacy); assert.equal(io.writes,0);
  }
});
test('plaintext cleanup interruption recovers without replacing encrypted original', async () => {
  const store=memoryStore(), io=legacyIO(legacy);
  await assert.rejects(migrateLegacyCredentials(store,'synthetic.yaml',{...io,writeFileAtomic:async()=>{throw Error('synthetic-interruption');}}));
  assert.equal(io.text,legacy); assert.equal((await store.read()).records[BACKUP].payload.text,legacy);
  assert.equal(await migrateLegacyCredentials(store,'synthetic.yaml',io),true);
  assert.equal((await store.read()).records[BACKUP].payload.text,legacy);
});
test('verification failure, malformed YAML and invalid records never clean plaintext or echo it', async () => {
  const store=memoryStore(); let reads=0;
  const broken={transaction:fn=>store.transaction(fn), read:async()=>{reads++;const doc=await store.read();if(reads>1)delete doc.refs.SYNTHETIC_KEY;return doc;}};
  const io=legacyIO(legacy);
  await assert.rejects(migrateLegacyCredentials(broken,'synthetic.yaml',io),/Legacy credential migration failed/); assert.equal(io.writes,0);
  for(const text of ['version: 1\nrefs: {SYNTHETIC_KEY: [synthetic-secret}', 'version: 1\nrefs: {A: one, A: synthetic-secret}', 'version: 1\nrecords: {demo/grant: {kind: synthetic-secret}}']) {
    const f=legacyIO(text); await assert.rejects(migrateLegacyCredentials(memoryStore(),'synthetic.yaml',f),error=>!error.message.includes('synthetic-secret')); assert.equal(f.writes,0);
  }
});
test('migration persists through actual encrypted store reopen using synthetic AEAD key', async t => {
  const dir=await mkdtemp(path.join(os.tmpdir(),'dsh-provider-synthetic-'));t.after(()=>rm(dir,{recursive:true,force:true}));
  const key=randomBytes(32), filename=path.join(dir,'vault.bin');
  const crypto={protect(plain){const iv=randomBytes(12), c=createCipheriv('aes-256-gcm',key,iv);const data=Buffer.concat([c.update(plain),c.final()]);return Buffer.concat([iv,c.getAuthTag(),data]);},unprotect(bytes){const d=createDecipheriv('aes-256-gcm',key,bytes.subarray(0,12));d.setAuthTag(bytes.subarray(12,28));return Buffer.concat([d.update(bytes.subarray(28)),d.final()]);}};
  const file=path.join(dir,'synthetic.yaml');await writeFile(file,legacy);
  await migrateLegacyCredentials(new VaultStore(filename,crypto),file,{withFileLock:async(_file,fn)=>fn(),writeFileAtomic:async(file,text)=>writeFile(file,text)});
  const restored=await new VaultStore(filename,crypto).read();
  assert.equal(restored.records[BACKUP].payload.text,legacy);
  assert.equal((await readFile(filename)).includes(Buffer.from('synthetic-stored')),false);
  assert.deepEqual(JSON.parse(await readFile(file,'utf8')),{version:1,foreign:{enabled:true}});
  const second = '# synthetic-encrypted-second-comment-secret\nversion: 1\n';
  await writeFile(file,second);
  await migrateLegacyCredentials(new VaultStore(filename,crypto),file,{withFileLock:async(_file,fn)=>fn(),writeFileAtomic:async(file,text)=>writeFile(file,text)});
  const reopened=await new VaultStore(filename,crypto).read();
  assert.deepEqual(reopened.records[BACKUP].payload,{text:legacy,history:[{text:second}]});
  assert.equal((await readFile(filename)).includes(Buffer.from('synthetic-encrypted-second-comment-secret')),false);
  assert.deepEqual(JSON.parse(await readFile(file,'utf8')),{version:1});
});
