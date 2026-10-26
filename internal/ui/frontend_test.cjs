// Exercise the shipped UI against a small DOM surface, with no third-party
// packages or network. This catches disabled-state regressions after failures.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

function element() {
  return {value:"",textContent:"",hidden:false,disabled:false,checked:false,
    classList:{toggle(){}},replaceChildren(){},append(){},listeners:{},addEventListener(name,fn){this.listeners[name]=fn}};
}

(async () => {
  const html=fs.readFileSync(path.join(__dirname,"assets/index.html"),"utf8");
  const elements=Object.fromEntries([...html.matchAll(/id="([^"]+)"/g)].map(match=>[match[1],element()]));
  const actions=["check","candidate","arm","disarm","launch","launch-claude"].map(id=>elements[id]);
  const state={config:{mode:"feilian",expectedIPs:[],programs:[],bundleIDs:[],proxyPort:17890},status:{state:"unconfigured",reason:"missing expected IP",platform:"darwin",filterActive:false},events:[]};
  const document={getElementById(id){assert.ok(elements[id],"unknown element: "+id);return elements[id]},
    createElement:element,querySelectorAll(selector){return selector.startsWith(".status-actions")?actions:[]}};
  let offline=false,blockCheck=false,releaseCheck,pauseCalls=0,credentialBody=null,configBody=null;
  const context={document,location:{hash:"#token=unit-test"},history:{replaceState(){}},URLSearchParams,
    window:{scrollTo(){}},setInterval(){},
    async fetch(url,options){if(url==="/api/proxy-credentials")credentialBody=JSON.parse(options.body);if(url==="/api/config")configBody=JSON.parse(options.body);if(offline)throw new Error("connection refused");if(url==="/api/check"&&blockCheck)await new Promise(resolve=>releaseCheck=resolve);if(url==="/api/disarm"){pauseCalls++;state.status={...state.status,state:"stopped"}}return {ok:url!=="/api/check",async json(){return url==="/api/check"?{error:"missing expected IP"}:state}}}};
  vm.runInNewContext(fs.readFileSync(path.join(__dirname,"assets/app.js"),"utf8"),context);
  await new Promise(setImmediate);
  await elements.check.onclick();
  assert.equal(elements.check.disabled,false,"check must be usable after a failed check");
  assert.equal(elements.candidate.disabled,false,"candidate must be usable after a failed check");
  assert.equal(elements.arm.disabled,true,"failure must not enable protection");
  assert.equal(elements.launch.disabled,true,"failure must not allow browser launch");
  assert.equal(elements["launch-claude"].disabled,true,"failure must not allow Claude launch");
  state.status={...state.status,state:"armed",filterActive:true};
  await elements.refresh.onclick();
  assert.equal(elements.launch.disabled,false,"real armed state permits a launch request");
  blockCheck=true;
  const pending=elements.check.onclick();
  assert.equal(elements.disarm.disabled,false,"pause must remain available while an armed session is busy");
  await elements.disarm.onclick();
  assert.equal(pauseCalls,1,"busy operation must not swallow pause action");
  releaseCheck();await pending;blockCheck=false;
  assert.equal(elements.launch.disabled,true,"cancelled operation must not restore launch readiness");
  state.config={...state.config,mode:"remote",enforcementMode:"proxy-only",proxyURL:"https://proxy.example:8443"};
  state.status={...state.status,state:"proxy_active",enforcementMode:"proxy-only",filterActive:false,proxyAddress:"127.0.0.1:17890",sessionRevision:3};
  state.launchReady=true;
  await elements.refresh.onclick();
  assert.equal(elements.launch.disabled,false,"active proxy permits explicit launch without system filtering");
  assert.equal(elements["state-heading"].textContent,"代理运行中，系统防绕行未核验","proxy state must explain limited coverage");
  assert.equal(elements["scope-ack-row"].hidden,true,"proxy launch must not require strict program-scope acknowledgement");
  state.status.enforcementMode="required";
  await elements.refresh.onclick();
  assert.equal(elements.launch.disabled,true,"proxy-active must not satisfy required mode");
  state.status.enforcementMode="proxy-only";
  await elements.refresh.onclick();
  elements.mode.value="remote";elements["enforcement-mode"].value="proxy-only";elements["remote-type"].value="https";elements["remote-server"].value="proxy.example";elements["remote-port"].value="8443";
  elements["proxy-username"].value="private-user";elements["proxy-password"].value="private-password";
  elements["config-form"].listeners.input({target:{id:"proxy-username"}});
  state.status.state="proxy_ready";
  await elements.refresh.onclick();
  assert.equal(elements.arm.disabled,false,"entering session credentials must not leave config dirty and block activation");
  state.status.state="proxy_active";
  await elements["save-proxy-credentials"].onclick();
  assert.deepEqual(credentialBody,{username:"private-user",password:"private-password"},"credentials travel only via their session API");
  assert.equal(elements["proxy-username"].value,"");assert.equal(elements["proxy-password"].value,"");
  await elements["config-form"].listeners.submit({preventDefault(){}});
  assert.equal(configBody.proxyURL,"https://proxy.example:8443");
  assert.equal(configBody.enforcementMode,"proxy-only");
  assert.equal(JSON.stringify(configBody).includes("private-"),false,"config must never include credentials");
  assert.equal(elements["expected-ips"].value,"","candidate and credentials must not approve expected IP");
  offline=true;
  await elements.check.onclick();
  assert.equal(elements.launch.disabled,true,"lost core must not retain cached launch readiness");
  assert.equal(elements["state-label"].textContent,"本机服务离线","lost core must not show cached armed status");
  console.log("UI action-state checks passed");
})().catch(error=>{console.error(error.message);process.exitCode=1});
