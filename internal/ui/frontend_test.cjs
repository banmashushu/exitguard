// Exercise the shipped UI against a small DOM surface, with no third-party
// packages or network. This catches disabled-state regressions after failures.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

function element(tag="") {
  let value="";
  return {children:[],textContent:"",hidden:false,disabled:false,checked:false,
    get options(){return this.children},get value(){return value},
    set value(next){value=tag==="select"&&!this.children.some(option=>option.value===String(next))?"":String(next)},
    classList:{toggle(){}},replaceChildren(...children){this.children=[...children];if(tag==="select")this.value=this.children[0]?.value||""},
    append(...children){this.children.push(...children)},listeners:{},addEventListener(name,fn){this.listeners[name]=fn}};
}

(async () => {
  const html=fs.readFileSync(path.join(__dirname,"assets/index.html"),"utf8");
  const elements=Object.fromEntries([...html.matchAll(/<([a-z][a-z0-9-]*)\b[^>]*\bid="([^"]+)"/g)].map(match=>[match[2],element(match[1])]));
  for(const match of html.matchAll(/<select\b[^>]*\bid="([^"]+)"[^>]*>([\s\S]*?)<\/select>/g)) {
    const select=elements[match[1]];
    for(const optionMatch of match[2].matchAll(/<option value="([^"]*)">([^<]*)<\/option>/g)) {
      const option=element("option");option.value=optionMatch[1];option.textContent=optionMatch[2];select.append(option);
    }
    select.value=select.options[0]?.value||"";
  }
  const actions=["check","candidate","arm","disarm","launch","launch-claude"].map(id=>elements[id]);
  const state={config:{mode:"feilian",expectedIPs:[],programs:[],bundleIDs:[],proxyPort:17890},status:{state:"unconfigured",reason:"missing expected IP",platform:"darwin",filterActive:false},events:[]};
  const document={getElementById(id){assert.ok(elements[id],"unknown element: "+id);return elements[id]},
    createElement:element,querySelectorAll(selector){return selector.startsWith(".status-actions")?actions:[]}};
  let offline=false,blockCheck=false,releaseCheck,pauseCalls=0,credentialBody=null,configBody=null,poll;
  const context={document,location:{hash:"#token=unit-test"},history:{replaceState(){}},URLSearchParams,
    window:{scrollTo(){}},setInterval(callback){poll=callback},
    async fetch(url,options){if(url==="/api/proxy-credentials")credentialBody=JSON.parse(options.body);if(url==="/api/config")configBody=JSON.parse(options.body);if(offline)throw new Error("connection refused");if(url==="/api/check"&&blockCheck)await new Promise(resolve=>releaseCheck=resolve);if(url==="/api/disarm"){pauseCalls++;state.status={...state.status,state:"stopped"}}return {ok:url!=="/api/check",async json(){return url==="/api/check"?{error:"missing expected IP"}:state}}}};
  vm.runInNewContext(fs.readFileSync(path.join(__dirname,"assets/app.js"),"utf8"),context);
  await new Promise(setImmediate);
  const chrome="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
  const edge="/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge";
  const claude="/Applications/Claude.app/Contents/MacOS/Claude";
  state.config.programs=[chrome,edge,claude,"/usr/bin/other"];
  await elements.refresh.onclick();
  const browser=elements["browser-path"],claudePicker=elements["claude-path"];
  assert.deepEqual(browser.options.map(option=>option.value),["",chrome,edge]);
  assert.deepEqual(claudePicker.options.map(option=>option.value),["",claude]);
  assert.equal(browser.value,"","adding programs must require an explicit browser selection");
  assert.equal(claudePicker.value,"","adding programs must require an explicit Claude selection");
  const browserOptions=[...browser.options],claudeOptions=[...claudePicker.options];
  for(let i=0;i<3;i++) {
    state.status.reason="status refresh "+i;
    poll();await new Promise(setImmediate);
    browserOptions.forEach((option,index)=>assert.equal(browser.options[index],option,"status polling must keep browser option nodes so an open native menu remains usable"));
    claudeOptions.forEach((option,index)=>assert.equal(claudePicker.options[index],option,"status polling must keep Claude option nodes"));
  }
  browser.value=edge;claudePicker.value=claude;
  state.config.programs=[chrome,edge,claude,"/usr/bin/changed-unrelated"];
  await elements.refresh.onclick();
  assert.equal(browser.value,edge,"refresh must preserve the user's browser selection");
  assert.equal(claudePicker.value,claude,"refresh must preserve the user's Claude selection");
  browserOptions.forEach((option,index)=>assert.equal(browser.options[index],option,"irrelevant program changes must keep browser options"));
  claudeOptions.forEach((option,index)=>assert.equal(claudePicker.options[index],option,"irrelevant program changes must keep Claude options"));
  state.config.programs=[edge,claude];
  await elements.refresh.onclick();
  assert.deepEqual(browser.options.map(option=>option.value),["",edge],"actual browser changes must update its choices");
  assert.equal(browser.value,edge,"a still-valid explicit selection must survive a choices update");
  claudeOptions.forEach((option,index)=>assert.equal(claudePicker.options[index],option,"browser changes must not rebuild Claude options"));
  state.config.programs=[chrome];
  await elements.refresh.onclick();
  assert.equal(browser.value,"","removing the selected browser must clear selection without choosing another");
  assert.equal(claudePicker.value,"","removing the selected Claude must clear selection");
  assert.deepEqual(browser.options.map(option=>option.value),["",chrome]);
  assert.deepEqual(claudePicker.options.map(option=>option.value),[""]);
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
  state.status={...state.status,state:"recovering",recoveryAttempt:2,recoveryMaxAttempts:3,nextRetryAt:"2026-10-30T06:20:00Z"};
  await elements.refresh.onclick();
  assert.equal(elements.disarm.disabled,false,"pause must cancel an automatic recovery episode");
  assert.match(elements["status-card"].className,/recovering/,"recovery must use a distinct paused appearance");
  assert.equal(elements.arm.disabled,true,"recovery must not permit another arm action");
  assert.equal(elements.launch.disabled,true,"recovering must keep launches disabled");
  assert.equal(elements["launch-claude"].disabled,true,"recovering must keep Claude disabled");
  assert.equal(elements["recovery-status"].hidden,false,"recovery progress must be visible");
  assert.match(elements["recovery-status"].textContent,/2\s*\/\s*3/,"recovery attempt bound must be visible");
  assert.match(elements["recovery-status"].textContent,/下次/,"scheduled retry time must be visible");
  state.status={...state.status,state:"proxy_active",recoveryAttempt:0,recoveryMaxAttempts:0,nextRetryAt:""};
  state.status.enforcementMode="required";
  await elements.refresh.onclick();
  assert.equal(elements.launch.disabled,true,"proxy-active must not satisfy required mode");
  state.status.enforcementMode="proxy-only";
  await elements.refresh.onclick();
  elements.mode.value="remote";elements["enforcement-mode"].value="proxy-only";elements["remote-type"].value="https";elements["remote-server"].value="proxy.example";elements["remote-port"].value="8443";
  elements["auto-recover"].checked=true;
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
  assert.equal(configBody.autoRecover,true,"explicit recovery preference must be submitted");
  elements["enforcement-mode"].value="required";
  elements["enforcement-mode"].listeners.change();
  assert.equal(elements["auto-recover"].disabled,true,"strict mode must not offer unsupported recovery");
  assert.equal(elements["auto-recover"].checked,false,"switching to strict mode must clear the incompatible option");
  await elements["config-form"].listeners.submit({preventDefault(){}});
  assert.equal(configBody.autoRecover,false,"strict submissions must not retain incompatible recovery intent");
  assert.match(html,/手动检查.*候选探测.*暂停当前连接/,"manual verification side effects must be explained");
  assert.match(html,/本次运行中已手动启动.*重开应用需重新提交账户并手动启动/,"recovery must not imply automatic startup or persisted credentials");
  assert.equal(JSON.stringify(configBody).includes("private-"),false,"config must never include credentials");
  assert.equal(elements["expected-ips"].value,"","candidate and credentials must not approve expected IP");
  offline=true;
  await elements.check.onclick();
  assert.equal(elements.launch.disabled,true,"lost core must not retain cached launch readiness");
  assert.equal(elements["state-label"].textContent,"本机服务离线","lost core must not show cached armed status");
  console.log("UI action-state checks passed");
})().catch(error=>{console.error(error.message);process.exitCode=1});
