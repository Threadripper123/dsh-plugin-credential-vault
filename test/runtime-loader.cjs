const {registerHooks,createRequire}=require('node:module');
const {pathToFileURL}=require('node:url');
const path=require('node:path');
const os=require('node:os');
const appRoot=process.env.DSH_APP_ROOT||path.join(process.env.LOCALAPPDATA||'', 'Programs', 'DeepSeek Harness', 'resources', 'app.asar');
const dshHome=process.env.DSH_HOME||path.join(os.homedir(), '.dsh');
const runtime=createRequire(path.join(appRoot, 'dsh', 'package.json'));
const profile=createRequire(path.join(dshHome, 'profiles', 'desktop', 'package.json'));
registerHooks({resolve(specifier,context,next){try{return next(specifier,context);}catch(error){if(specifier.startsWith('@deepseek-ai/')||specifier==='yaml'){let found;try{found=runtime.resolve(specifier);}catch{found=profile.resolve(specifier);}return {url:pathToFileURL(found).href,shortCircuit:true};}throw error;}}});
