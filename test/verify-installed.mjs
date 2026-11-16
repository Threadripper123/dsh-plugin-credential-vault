import {readFile} from 'node:fs/promises';
import {parseDocument} from 'yaml';
import {VaultStore} from '../lib/store.mjs';
const home=process.env.USERPROFILE+'/.dsh';
const doc=await new VaultStore(home+'/credential-vault/vault.bin').read();
const legacy=parseDocument(await readFile(home+'/.credentials.yaml','utf8')).toJS()??{};
const backup=doc.records['credential-vault/legacy-backup'];
let verified=false;
if(backup?.payload?.text){const prior=parseDocument(backup.payload.text).toJS()??{};verified=Object.entries(prior.refs??{}).every(([ref,value])=>doc.refs[ref]===value)&&Object.entries(prior.records??{}).every(([key,value])=>JSON.stringify(doc.records[key])===JSON.stringify(value));}
console.log(JSON.stringify({encryptedStoreReadable:true,legacyCredentialSectionsRemoved:!Object.hasOwn(legacy,'refs')&&!Object.hasOwn(legacy,'records'),encryptedMigrationBackupVerified:verified,storedReferenceCount:Object.keys(doc.refs).length}));
