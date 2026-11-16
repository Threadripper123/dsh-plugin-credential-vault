import test from 'node:test';
import assert from 'node:assert/strict';
import { ConnectorVault, validateConnector } from '../lib/connectors.mjs';
const policy = {id:'example',ref:'EXAMPLE_KEY',baseURL:'https://api.example.com/v1'};
test('connector rejects unsafe policies', () => {
 for (const baseURL of ['http://api.example.com','https://localhost','https://127.0.0.1','https://a:b@api.example.com','https://api.example.com/?key=x','https://api.example.com/#x']) assert.throws(()=>validateConnector({...policy,baseURL}));
 assert.throws(()=>validateConnector({...policy,header:'Host'}));
 assert.equal(validateConnector(policy).prefix,'Bearer ');
});
test('trusted operation attaches key without returning it and blocks redirect', async () => {
 const secret='synthetic-vault-key-123'; let request;
 const vault=new ConnectorVault({store:{read:async()=>({connectors:{example:validateConnector(policy)}})},resolve:async()=>({value:secret})});
 const original=globalThis.fetch;
 globalThis.fetch=async(url,options)=>{request={url:String(url),options};return new Response(JSON.stringify({name:'ok',echo:secret,encoded:Buffer.from(secret).toString('base64'),headerEncoded:Buffer.from('Bearer '+secret).toString('base64'),hex:Buffer.from(secret).toString('hex')}));};
 try {
  const dispose=vault.register({connector:'example',operation:'lookup',path:'/lookup',project:x=>x});
  const result=await vault.invoke('example','lookup',{});
  assert.equal(request.url,'https://api.example.com/v1/lookup');
  assert.equal(request.options.headers.Authorization,'Bearer '+secret);
  assert.equal(request.options.redirect,'error');
  assert.equal(result.echo,'[REDACTED]');assert.equal(result.encoded,'[REDACTED]');assert.equal(result.headerEncoded,'[REDACTED]');assert.equal(result.hex,'[REDACTED]');
  dispose();await assert.rejects(vault.invoke('example','lookup',{}));
 }finally{globalThis.fetch=original;}
});
test('operation cannot traverse configured URL prefix or echo exceptions', async () => {
 const vault=new ConnectorVault({store:{read:async()=>({connectors:{example:validateConnector(policy)}})},resolve:async()=>({value:'synthetic'})});
 for (const path of ['/x%2f..%2fescape','/x%252fescape','/x y']) assert.throws(()=>vault.register({connector:'example',operation:'encoded',path,project:x=>x}));
 vault.register({connector:'example',operation:'escape',path:'/../escape',project:x=>x});
 await assert.rejects(vault.invoke('example','escape',{}),/invalid connector policy/);
 vault.register({connector:'example',operation:'error',path:'/x',encode:()=>{throw Error('synthetic');},project:x=>x});
 await assert.rejects(vault.invoke('example','error',{}),{message:'vault: connector request failed'});
});
