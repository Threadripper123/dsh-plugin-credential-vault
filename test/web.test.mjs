import test from 'node:test';
import assert from 'node:assert/strict';
import { Readable } from 'node:stream';
import { registerWeb } from '../lib/web.mjs';
function fixture(kind='owner') {
 let route,admissions=0;const calls=[];
 const provider={publicSnapshot:async()=>({refs:[{ref:'vault:test',configured:true}],connectors:[]}),set:async(...a)=>calls.push(['set',...a]),unset:async(...a)=>calls.push(['unset',...a]),setConnector:async(...a)=>calls.push(['connector-set',...a]),deleteConnector:async(...a)=>calls.push(['connector-delete',...a])};
 const dispose=()=>{};registerWeb({effect:fn=>assert.equal(fn(),dispose),webServer:{port:3335,register:r=>(route=r,dispose)},connection:{admit(){admissions++;return kind==='reject'?{rejection:401}:kind==='forbidden'?{rejection:403}:{peer:{principal:{kind}}};},admitConnection(){assert.fail('HTTP must not claim socket ownership');}}},provider);
 return {provider,calls,get admissions(){return admissions;},async request({method='GET',url='/credential-vault/api',body,headers={},chunks,onResponse}={}){
 const req=Readable.from(chunks||(body===undefined?[]:[Buffer.from(typeof body==='string'?body:JSON.stringify(body))]));req.method=method;req.url=url;req.headers={host:'127.0.0.1:3335',...headers};req.socket={remoteAddress:'127.0.0.1'};
 const res={headers:{},statusCode:200,writableEnded:false,setHeader(k,v){this.headers[k.toLowerCase()]=v;},end(v){this.body=v;this.writableEnded=true;}};onResponse?.(res);await route.handler(req,res);return res;}};
}
const post={method:'POST',headers:{origin:'http://127.0.0.1:3335','x-dsh-vault':'1','content-type':'application/json'},body:{action:'set',ref:'vault:test',value:'fake-secret-only'}};
test('numeric HTTP auth rejection and owner-only authorization',async()=>{const d=fixture('reject');assert.equal((await d.request()).statusCode,401);assert.equal((await fixture('forbidden').request()).statusCode,403);for(const k of ['guest','agent','unknown']){const f=fixture(k);assert.equal((await f.request()).statusCode,403);assert.equal(f.calls.length,0);}});
test('Host and CSRF strictly checked',async()=>{
 for(const host of ['evil.example:3335','127.0.0.1:3336','localhost.evil:3335','localhost.:3335','user@localhost:3335','127.1:3335','[::ffff:127.0.0.1]:3335']){const f=fixture();assert.equal((await f.request({headers:{host}})).statusCode,403);assert.equal(f.admissions,0);}
 for(const headers of [{...post.headers,origin:undefined},{...post.headers,origin:'null'},{...post.headers,origin:'http://localhost:3335'},{...post.headers,origin:'https://127.0.0.1:3335'},{...post.headers,'x-dsh-vault':undefined},{...post.headers,'sec-fetch-site':'cross-site'}]){const f=fixture();assert.equal((await f.request({...post,headers})).statusCode,403);assert.equal(f.calls.length,0);}
});
test('public snapshot and four commands use provider contracts',async()=>{const f=fixture();assert.equal(JSON.parse((await f.request()).body).refs[0].configured,true);const connector={action:'connector-set',id:'test',label:'Test',ref:'vault:test',baseURL:'https://example.test',header:'Authorization',prefix:'Bearer '};for(const body of [post.body,{action:'unset',ref:'vault:test'},connector,{action:'connector-delete',id:'test'}]){const r=await f.request({...post,body});assert.equal(r.statusCode,200);assert.deepEqual(JSON.parse(r.body),{ok:true});assert.ok(!r.body.includes('fake-secret'));}assert.equal(f.calls.length,4);const {action,...value}=connector;assert.deepEqual(f.calls[2][1],value);});
test('64 KiB declared and streamed body limits',async()=>{for(const options of [{...post,headers:{...post.headers,'content-length':'65537'},body:''},{...post,chunks:[Buffer.alloc(32768,32),Buffer.alloc(32769,32)]}]){const f=fixture();assert.equal((await f.request(options)).statusCode,413);assert.equal(f.calls.length,0);}});
test('errors never echo malformed input or provider exception',async()=>{const f=fixture();for(const body of ['fake-secret-invalid-json',{action:'toString'},{...post.body,secret:'should-not-echo'},null]){const r=await f.request({...post,body});assert.equal(r.statusCode,400);assert.ok(!r.body.includes('fake-secret'));}f.provider.set=async()=>{throw Error('fake-secret-provider-error');};const r=await f.request(post);assert.equal(r.statusCode,500);assert.ok(!r.body.includes('fake-secret'));});
test('HTML per-request nonce, password input, safe DOM APIs',async()=>{const f=fixture();const a=await f.request({url:'/credential-vault'}),b=await f.request({url:'/credential-vault'});assert.equal(a.statusCode,200);assert.match(a.body,/type="password"/);assert.ok(!a.body.includes('innerHTML'));assert.ok(!a.body.includes('__VAULT_NONCE__'));assert.notEqual(a.headers['content-security-policy'],b.headers['content-security-policy']);assert.match(a.headers['content-security-policy'],/frame-ancestors 'none'/);assert.equal(a.headers['cache-control'],'no-store');});
test('rate limiting bounds authentication work',async()=>{const f=fixture();for(let i=0;i<60;i++)assert.equal((await f.request()).statusCode,200);assert.equal((await f.request()).statusCode,429);assert.equal(f.admissions,60);});
test('unknown routes and methods rejected',async()=>{const f=fixture();assert.equal((await f.request({url:'/credential-vault/else'})).statusCode,404);assert.equal((await f.request({method:'PUT'})).statusCode,405);assert.equal(f.admissions,0);});
test('provider read timeout retains static error response',async t=>{
 t.mock.timers.enable({apis:['setTimeout']});const f=fixture();f.provider.publicSnapshot=()=>new Promise(()=>{});const pending=f.request();for(let i=0;i<12;i++)await Promise.resolve();t.mock.timers.tick(15001);const r=await pending;assert.equal(r.statusCode,408);t.mock.timers.reset();
});
const flush = async () => { for (let i = 0; i < 20; i++) await Promise.resolve(); };
test('late HTTP authentication times out without touching shared Peer or provider',async t=>{
 t.mock.timers.enable({apis:['setTimeout']});let route,resolveAuth;
 const peer={principal:{kind:'owner'},dispose:()=>assert.fail('HTTP must never dispose Peer')};
 registerWeb({effect:()=>{},webServer:{port:3335,register:r=>(route=r,()=>{})},connection:{admit:()=>new Promise(resolve=>{resolveAuth=resolve;}),admitConnection:()=>assert.fail('socket API')}} ,{publicSnapshot:()=>assert.fail('must not access provider')});
 const req=Readable.from([]);req.method='GET';req.url='/credential-vault/api';req.headers={host:'localhost:3335'};req.socket={remoteAddress:'127.0.0.1'};
 const res={statusCode:200,setHeader(){},end(v){this.body=v;this.writableEnded=true;}};
 const pending=route.handler(req,res);await flush();t.mock.timers.tick(15001);await pending;assert.equal(res.statusCode,408);resolveAuth({peer});await flush();assert.equal(res.statusCode,408);
});
// Real admit() is synchronous, returns {peer} or {rejection:number}, and has no lease.
test('repeated HTTP owner requests share a live Peer even with an attached socket',async()=>{
 let route,socketClaims=0;const peer={principal:{kind:'owner'},dispose:()=>assert.fail('must stay live')};const record={peer,ownsSocket:true};
 registerWeb({effect:()=>{},webServer:{port:3335,register:r=>(route=r,()=>{})},connection:{admit:()=>({peer:record.peer}),admitConnection:()=>{socketClaims++;return {rejection:409};}}},{publicSnapshot:()=>({refs:[]})});
 for(let i=0;i<2;i++){const req=Readable.from([]);Object.assign(req,{method:'GET',url:'/credential-vault/api',headers:{host:'localhost:3335'},socket:{remoteAddress:'127.0.0.1'}});const res={setHeader(){},end(){this.writableEnded=true;}};await route.handler(req,res);assert.equal(res.statusCode,200);}
 assert.equal(record.ownsSocket,true);assert.equal(socketClaims,0);
});
test('slow writes retain busy admission past 15s and return only after actual commit',async t=>{
 t.mock.timers.enable({apis:['setTimeout']});const f=fixture();let settle,started;const entered=new Promise(resolve=>{started=resolve;});let committed=false,finished=false;
 f.provider.set=()=>{started();return new Promise(resolve=>{settle=()=>{committed=true;resolve();};});};
 const pending=f.request(post).then(r=>{finished=true;return r;});await entered;t.mock.timers.tick(15001);await flush();assert.equal(finished,false);assert.equal(committed,false);
 const retry=await f.request(post);assert.equal(retry.statusCode,429);assert.equal(retry.headers['retry-after'],'1');assert.equal((await f.request()).statusCode,200);
 settle();const r=await pending;assert.equal(committed,true);assert.equal(r.statusCode,200);assert.deepEqual(JSON.parse(r.body),{ok:true});
 f.provider.set=async()=>{};assert.equal((await f.request(post)).statusCode,200);
});
test('failed writes release busy only after rejection and never echo errors',async t=>{
 t.mock.timers.enable({apis:['setTimeout']});const f=fixture();let fail,started;const entered=new Promise(resolve=>{started=resolve;});
 f.provider.set=()=>{started();return new Promise((_,reject)=>{fail=reject;});};const pending=f.request(post);await entered;t.mock.timers.tick(15001);await flush();assert.equal((await f.request(post)).statusCode,429);
 fail(Error('fake-secret-delayed-error'));const r=await pending;assert.equal(r.statusCode,500);assert.ok(!r.body.includes('fake-secret'));f.provider.set=async()=>{};assert.equal((await f.request(post)).statusCode,200);
});
test('disconnected write retains busy and active admission until settled',async t=>{
 t.mock.timers.enable({apis:['setTimeout']});const f=fixture();let settle,started;const entered=new Promise(resolve=>{started=resolve;});let response;
 f.provider.set=()=>{started();return new Promise(resolve=>{settle=resolve;});};
 const pending=f.request({...post,onResponse:r=>{response=r;}});await entered;response.destroyed=true;t.mock.timers.tick(15001);await flush();assert.equal((await f.request(post)).statusCode,429);
 const reads=[];f.provider.publicSnapshot=()=>new Promise(resolve=>{reads.push(resolve);});const pendingReads=Array.from({length:15},()=>f.request());await flush();assert.equal(reads.length,15);assert.equal((await f.request()).statusCode,429);
 settle();await pending;assert.equal(response.writableEnded,false);
 f.provider.publicSnapshot=async()=>({refs:[]});assert.equal((await f.request()).statusCode,200);for(const resolve of reads)resolve({refs:[]});await Promise.all(pendingReads);
 f.provider.set=async()=>{};assert.equal((await f.request(post)).statusCode,200);
});
