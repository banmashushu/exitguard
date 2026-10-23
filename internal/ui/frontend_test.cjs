// Exercise the shipped UI against a small DOM surface, with no third-party
// packages or network. This catches disabled-state regressions after failures.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

function element() {
  return {value:"",textContent:"",hidden:false,disabled:false,checked:false,
    classList:{toggle(){}},replaceChildren(){},append(){},addEventListener(){}};
}

(async () => {
  const html=fs.readFileSync(path.join(__dirname,"assets/index.html"),"utf8");
  const elements=Object.fromEntries([...html.matchAll(/id="([^"]+)"/g)].map(match=>[match[1],element()]));
  const actions=["check","candidate","arm","disarm","launch","launch-claude"].map(id=>elements[id]);
  const state={config:{mode:"feilian",expectedIPs:[],programs:[],bundleIDs:[],proxyPort:17890},status:{state:"unconfigured",reason:"missing expected IP",platform:"darwin",filterActive:false},events:[]};
  const document={getElementById(id){assert.ok(elements[id],"unknown element: "+id);return elements[id]},
    createElement:element,querySelectorAll(selector){return selector.startsWith(".status-actions")?actions:[]}};
  let offline=false,blockCheck=false,releaseCheck,pauseCalls=0;
  const context={document,location:{hash:"#token=unit-test"},history:{replaceState(){}},URLSearchParams,
    window:{scrollTo(){}},setInterval(){},
    async fetch(url){if(offline)throw new Error("connection refused");if(url==="/api/check"&&blockCheck)await new Promise(resolve=>releaseCheck=resolve);if(url==="/api/disarm"){pauseCalls++;state.status={...state.status,state:"stopped"}}return {ok:url!=="/api/check",async json(){return url==="/api/check"?{error:"missing expected IP"}:state}}}};
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
  state.status={...state.status,state:"armed",filterActive:true};
  await elements.refresh.onclick();
  offline=true;
  await elements.check.onclick();
  assert.equal(elements.launch.disabled,true,"lost core must not retain cached launch readiness");
  assert.equal(elements["state-label"].textContent,"本机服务离线","lost core must not show cached armed status");
  console.log("UI action-state checks passed");
})().catch(error=>{console.error(error.message);process.exitCode=1});
