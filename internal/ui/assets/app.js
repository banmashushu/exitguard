"use strict";
(() => {
  const fragment = new URLSearchParams(location.hash.slice(1));
  const token = fragment.get("token") || "";
  history.replaceState(null, "", "/");
  const $ = id => document.getElementById(id);
  let snapshot = null, busy = false, editing = false;
  const states = {
    unconfigured:["尚未配置","请先填写上游与期望 IP"],
    checking:["正在检查","正在验证出口路径"],
    recovering:["转发已暂停 · 正在恢复","核验原出口后自动恢复"],
    blocked:["连接已关闭","出口检查未通过"],
    ready:["严格检查通过","等待启用严格阻断"],
    armed:["严格阻断已启用","当前程序策略已验证"],
    proxy_ready:["代理检查通过","等待启动代理转发"],
    proxy_active:["代理转发已启动","代理运行中，系统防绕行未核验"],
    stopped:["已暂停","本机转发已关闭"]
  };
  const lines = value => value.split(/\n|,/).map(s => s.trim()).filter(Boolean);
  const mode = value => value || "required";
  const isProxy = c => mode(c.enforcementMode) === "proxy-only";
  const matchesMode = (c,s) => mode(c.enforcementMode) === mode(s.enforcementMode);
  const active = (c,s) => matchesMode(c,s) && (isProxy(c) ? s.state === "proxy_active" && !s.filterActive : s.state === "armed" && !!s.filterActive);
  const ready = (c,s) => matchesMode(c,s) && (isProxy(c) ? s.state === "proxy_ready" && !s.filterActive : s.state === "ready");
  const setText = (id,value) => { $(id).textContent = value || "—"; };
  function notice(message,success=false) { const el=$("notice");el.textContent=message;el.classList.toggle("success",success);el.hidden=false; }
  async function api(path,body) {
    if (!token) throw new Error("此页面缺少本次运行的控制凭证，请关闭窗口并重新打开 ExitGuard。");
    const response = await fetch("/api/"+path, {
      method:body===undefined?"GET":"POST",
      headers:{Authorization:"Bearer "+token,...(body===undefined?{}:{"Content-Type":"application/json"})},
      body:body===undefined?undefined:JSON.stringify(body),cache:"no-store",credentials:"omit",referrerPolicy:"no-referrer"
    });
    const data=await response.json();
    if (!response.ok) throw new Error(data.error||"本机服务请求失败");
    return data;
  }
  function disconnected() {
    snapshot=null;$("status-card").className="status-card blocked";
    setText("state-label","本机服务离线");setText("state-heading","无法连接本机服务");
    setText("reason","请重新打开 ExitGuard。旧状态不能用于继续启动应用。");
    setText("filter-note","系统过滤状态未知；当前页面没有可用的本机会话。");
    ["arm","disarm","launch","launch-claude","native-launch","save-proxy-credentials"].forEach(id=>$(id).disabled=true);
    $("check").disabled=false;$("candidate").disabled=false;
  }
  function render(data,fill=false) {
    snapshot=data;
    const c=data.config,s=data.status,proxy=isProxy(c),state=states[s.state]||[s.state,"状态未知"];
    const running=active(c,s);
    const recovering=matchesMode(c,s)&&s.state==="recovering";
    setText("state-label",state[0]);setText("state-heading",state[1]);setText("reason",s.reason);
    $("recovery-status").hidden=!recovering;
    if(recovering) {
      const attempt=(s.recoveryAttempt||1)+" / "+(s.recoveryMaxAttempts||3);
      setText("recovery-status",s.nextRetryAt?"第 "+attempt+" 次；下次核验："+new Date(s.nextRetryAt).toLocaleTimeString("zh-CN",{hour12:false}):"第 "+attempt+" 次核验中；确认同一路径和同一公网 IP 前保持暂停。");
    }
    // Proxy forwarding gets a neutral blue state, never the strict OS-proof green.
    $("status-card").className="status-card"+(s.state==="armed"&&running?" armed":s.state==="proxy_active"&&running?" proxy-active":recovering?" recovering":s.state==="blocked"||s.state==="unconfigured"?" blocked":"");
    $("native-preview").hidden=s.platform!=="windows";
    $("native-launch").disabled=busy||editing||s.platform!=="windows"||!proxy||!running||c.proxyPort!==17890;
    setText("native-status",s.nativeReason||"尚未完成 Windows 实机测试。断线、登录与应用兼容性仍需验证，当前没有完整保护证明。");
    const mac=s.platform==="darwin";
    setText("platform",mac?"◉ macOS · 本机":s.platform==="windows"?"◉ Windows · 本机":s.platform+" · 本机");
    setText("source",c.mode==="remote"?"远程代理":c.mode==="proxy"?"本地固定专用入口":c.mode==="clash"?"Clash / Mihomo（只读）":c.mode==="feilian"?"公司飞连":"尚未配置");
    setText("source-detail",c.mode==="remote"||c.mode==="proxy"?c.proxyURL||"尚未指定服务器":c.mode==="clash"?c.clashNode||"尚未指定固定节点":c.tunnelInterface||"尚未确认接口");
    setText("expected",(c.expectedIPs||[]).join(" / ")||"未设置");setText("observed",s.observedIP||"尚未观察");
    const checked=s.checkedAt?new Date(s.checkedAt).toLocaleString("zh-CN",{hour12:false}):"尚未检查";
    setText("checked-at",checked);
    setText("filter-note",proxy?"仅代理转发，系统防绕行未验证。本模式不核验或更改已有系统规则；忽略代理设置的流量不受此模式约束。":s.filterActive?"系统过滤已匹配当前策略。实际断线、DNS、辅助进程与协议覆盖仍需目标设备验证。":"严格阻断需要真实系统过滤证据。仅出口探测成功不能启用严格方式。");
    setText("scope-note",proxy?"只转发经过本机代理的 IPv4 TCP；UDP 与忽略代理设置的连接不在覆盖范围。":"系统策略按程序影响所有窗口；IPv4 TCP 经代理，IPv6 / UDP 由系统规则拒绝。完整覆盖仍需验证。");
    setText("activation-title",proxy?"启动本机代理":"部署并验证系统过滤");
    setText("install-help",proxy?"无需安装 Claude、系统扩展或 WFP。检查通过后启动代理，并显式配置需要的应用。":mac?"本地 ad-hoc 应用没有可激活的 Network Extension。严格阻断需合格签名、部署与系统授权。":"严格阻断需管理员显式安装 WFP 规则，并在真实 Windows 设备验证。保存不安装规则。");
    setText("entry-badge",proxy?"仅遵循代理的连接":"系统程序级过滤");
    setText("entry-note",proxy?"显式选择 Chrome / Edge，使用独立资料目录与本机代理。其他窗口及不遵循代理的代码可能直接联网。":"选择已列入当前系统策略的 Chrome / Edge。需要完整程序及辅助进程范围，并确认所有窗口影响。");
    $("scope-ack-row").hidden=proxy;
    setText("arm",proxy?"启动代理":"启用严格阻断");setText("disarm",proxy?"暂停代理":"暂停转发");
    setText("proxy-address",s.proxyAddress||"尚未监听");
    setText("credentials-status",s.upstreamCredentialsSet?"已提交会话账户；不显示账户或密码。更改服务器或退出后需重新提交。":"账户未提交；无需认证的代理可留空。");
    $("step-source").classList.toggle("done",!!(c.proxyURL||c.tunnelInterface));
    $("step-ip").classList.toggle("done",!!c.expectedIPs?.length);
    $("step-filter").classList.toggle("done",running);
    $("check").disabled=busy;$("candidate").disabled=busy;
    $("arm").disabled=busy||editing||!ready(c,s);
    $("disarm").disabled=!(running||recovering);
    $("launch").disabled=busy||editing||!running;$("launch-claude").disabled=busy||editing||!running;
    $("save-proxy-credentials").disabled=busy||editing||c.mode!=="remote";
    setText("diag-state",state[0]+" · "+s.state);setText("diag-filter",proxy?"本模式不核验系统防绕行":s.filterActive?"当前策略匹配":"未就绪");
    setText("diag-proxy",s.proxyAddress||"未监听");setText("diag-policy",s.policyHash||"无当前系统策略证明");setText("diag-checked",checked);
    const browserPaths=[],claudePaths=[];
    for (const path of c.programs||[]) {
      const base=path.split(/[\\/]/).pop();
      if (/^(chrome\.exe|msedge\.exe|Google Chrome|Microsoft Edge)$/i.test(base)) browserPaths.push(path);
      else if (/^(Claude|Claude\.exe)$/i.test(base)) claudePaths.push(path);
    }
    for (const [id,label,paths] of [["browser-path","显式选择已配置的浏览器程序",browserPaths],["claude-path","显式选择已配置的 Claude 程序",claudePaths]]) {
      const target=$(id);
      // Replacing options closes the native macOS menu during status polling.
      if (target.options.length===paths.length+1&&target.options[0].value===""&&target.options[0].textContent===label&&paths.every((path,index)=>target.options[index+1].value===path)) continue;
      const prior=target.value;
      target.replaceChildren();const empty=document.createElement("option");empty.value="";empty.textContent=label;target.append(empty);
      for (const path of paths) {const option=document.createElement("option");option.value=path;option.textContent=path;target.append(option);}
      target.value=paths.includes(prior)?prior:"";
    }
    setText("claude-badge",claudePaths.length?"已配置 · 待实测":"可选 · 尚未配置");
    const eventRoot=$("event-list");eventRoot.replaceChildren();eventRoot.className="";
    if (!data.events?.length) {eventRoot.className="events-empty";eventRoot.textContent="本次运行暂无事件";}
    for (const e of [...(data.events||[])].reverse()) {
      const row=document.createElement("div");row.className="event-row";
      const time=document.createElement("time");time.textContent=e.at?new Date(e.at).toLocaleTimeString("zh-CN",{hour12:false}):"—";
      const stateEl=document.createElement("span");stateEl.className="event-state";stateEl.textContent=(states[e.state]||[e.state])[0];
      const text=document.createElement("p");text.textContent=e.message;row.append(time,stateEl,text);eventRoot.append(row);
    }
    if (fill&&!editing) fillForm(c);
    toggleMode();
  }
  function fillForm(c) {
    const remote=(c.mode==="remote"&&c.proxyURL||"").match(/^(https?|socks5):\/\/([^:/?#@]+):(\d+)$/);
    const fields={mode:c.mode||"remote","enforcement-mode":mode(c.enforcementMode),"expected-ips":(c.expectedIPs||[]).join(", "),"proxy-port":c.proxyPort||17890,"probe-url":c.probeURL||"https://api.ipify.org?format=json",tunnel:c.tunnelInterface||"","dns-url":c.dnsResolverURL||"https://cloudflare-dns.com/dns-query","dns-bootstrap":c.dnsBootstrapIP||"1.1.1.1",upstream:c.mode==="clash"?c.proxyURL||"":"","fixed-upstream":c.mode==="proxy"?c.proxyURL||"":"","remote-type":remote?remote[1]:"https","remote-server":remote?remote[2]:"","remote-port":remote?remote[3]:"",controller:c.clashControllerURL||"",selector:c.clashSelector||"",node:c.clashNode||"",programs:(c.programs||[]).join("\n"),"bundle-ids":(c.bundleIDs||[]).join("\n")};
    for (const [id,value] of Object.entries(fields)) $(id).value=value;
    $("auto-recover").checked=!!c.autoRecover;
  }
  function config() {
    const source=$("mode").value;
    let proxyURL="";
    if (source==="remote") {
      const server=$("remote-server").value.trim(),port=Number($("remote-port").value),type=$("remote-type").value;
      if (!server||/[\s:/@?#\\]/.test(server)||!Number.isInteger(port)||port<1||port>65535||!["http","https","socks5"].includes(type)) throw new Error("请分别填写代理类型、服务器主机名或 IPv4，以及有效端口。账户请通过会话账户按钮单独提交。");
      proxyURL=type+"://"+server+":"+port;
    } else if (source==="proxy") proxyURL=$("fixed-upstream").value.trim();
    else if (source==="clash") proxyURL=$("upstream").value.trim();
    return {mode:source,enforcementMode:$("enforcement-mode").value,autoRecover:isProxy({enforcementMode:$("enforcement-mode").value})&&$("auto-recover").checked,expectedIPs:lines($("expected-ips").value),proxyPort:Number($("proxy-port").value),probeURL:$("probe-url").value.trim(),tunnelInterface:source==="feilian"?$("tunnel").value.trim():"",dnsResolverURL:$("dns-url").value.trim(),dnsBootstrapIP:$("dns-bootstrap").value.trim(),proxyURL,clashControllerURL:source==="clash"?$("controller").value.trim():"",clashSelector:source==="clash"?$("selector").value.trim():"",clashNode:source==="clash"?$("node").value.trim():"",programs:lines($("programs").value),bundleIDs:lines($("bundle-ids").value)};
  }
  function toggleMode() {
    const source=$("mode").value;
    const supportsRecovery=isProxy({enforcementMode:$("enforcement-mode").value});
    $("auto-recover").disabled=!supportsRecovery;
    if(!supportsRecovery)$("auto-recover").checked=false;
    for (const item of ["remote","clash","feilian","proxy"]) $(item+"-settings").hidden=source!==item;
    setText("mode-help",isProxy({enforcementMode:$("enforcement-mode").value})?"仅代理遵循者的 IPv4 TCP。本模式不核验或更改系统防绕行规则。":"必须有匹配的系统过滤证明；出口检查不会替代系统部署。");
    setText("transport-note",$("remote-type").value==="https"?"HTTPS 会验证代理服务器证书，不支持忽略证书或自动降级。":"所选协议到代理服务器本身不加密，请确认你接受该链路与认证暴露范围。");
  }
  function view(name) {
    document.querySelectorAll(".view").forEach(e=>e.hidden=e.id!==name);
    document.querySelectorAll(".nav").forEach(e=>e.classList.toggle("active",e.dataset.view===name));
    setText("page-title",{overview:"出口概览",settings:"代理设置",events:"诊断与事件"}[name]);window.scrollTo(0,0);
  }
  document.querySelectorAll("[data-view]").forEach(el=>el.addEventListener("click",()=>view(el.dataset.view)));
  document.querySelectorAll("[data-open-settings]").forEach(el=>el.addEventListener("click",()=>view("settings")));
  async function action(path,body={},success) {
    const pause=path==="disarm";
    if (busy&&!pause) return false;
    if (!pause) busy=true;
    document.querySelectorAll(".status-actions button,#launch,#launch-claude").forEach(e=>e.disabled=true);
    if (snapshot) render(snapshot);
    try {const data=await api(path,body);if(data.status)render(data);if(success)notice(success,true);return true;}
    catch(e) {notice(e.message);try{render(await api("snapshot"));}catch{disconnected();}return false;}
    finally {if(!pause)busy=false;if(snapshot)render(snapshot);}
  }
  $("candidate").onclick=async()=>{
    if(busy)return;busy=true;if(snapshot)render(snapshot);
    try {const data=await api("candidate",{});notice("候选出口："+data.candidateIP+"。仅代表当前探测；请向提供方确认后，手动填写期望 IPv4 并保存。",true);}
    catch(e){notice(e.message);}
    finally{busy=false;try{render(await api("snapshot"));}catch{disconnected();}}
  };
  $("check").onclick=()=>action("check",{},"出口检查已完成。请核对当前方式和观察 IP，再明确启用。");
  $("arm").onclick=()=>action("arm",{},snapshot&&isProxy(snapshot.config)?"代理转发已启动；系统防绕行未核验。":"严格阻断已提交启用，请核对实际系统状态。");
  $("disarm").onclick=()=>action("disarm",{},"已暂停转发，并关闭本应用持有的连接。已有系统规则需单独核对。");
  $("refresh").onclick=refresh;
  function launch(kind,id) {
    if(!snapshot||!active(snapshot.config,snapshot.status))return notice("当前会话未启用，请刷新后检查。");
    const path=$(id).value,strict=!isProxy(snapshot.config);
    if(!path)return notice(kind==="browser"?"请先在可选启动路径中添加并明确选择 Chrome / Edge 可执行文件。":"尚未安装或配置 Claude；这不影响普通代理或浏览器使用。");
    if(strict&&!$("scope-ack").checked)return notice("请确认已了解同一程序的所有窗口都会受到系统过滤。");
    return action("launch",{kind,path,acknowledgeProgramScope:strict&&$("scope-ack").checked,sessionRevision:snapshot.status.sessionRevision||0},kind==="browser"?"已启动独立浏览器。请在使用设备验证出口与断线行为。":strict?"已提交 Claude 启动；仍需验证登录、聊天、上传与系统覆盖。":"已提交 Claude 启动；只有采用代理参数的连接经此转发，其他流量可能直连。请验证当前版本的登录、聊天与上传。");
  }
  $("native-launch").onclick=()=>{
    if(!snapshot||!$("native-ack").checked)return notice("请先确认应用保护试用范围，并完全退出所选应用。");
    return action("native-launch-preview",{target:$("native-target").value,path:$("native-path").value.trim(),sessionRevision:snapshot.status.sessionRevision,acknowledgePreview:true},"已提交应用保护试用。尚未完成 Windows 实机测试，请确认新窗口出现在对应的 Sandboxie 分组中。");
  };
  $("launch").onclick=()=>launch("browser","browser-path");$("launch-claude").onclick=()=>launch("claude","claude-path");
  $("config-form").addEventListener("input",event=>{
    if (["proxy-username","proxy-password","clash-secret"].includes(event.target.id)) return;
    editing=true;if(snapshot)render(snapshot);
  });
  for(const id of ["mode","enforcement-mode","remote-type"])$(id).addEventListener("change",toggleMode);
  $("config-form").addEventListener("submit",async e=>{
    e.preventDefault();
    try {if(await action("config",config(),"设置已保存，会话已暂停。若需要账户，请单独提交，再测试或检查出口。")){editing=false;if(snapshot)render(snapshot);}}
    catch(error){notice(error.message);}
  });
  $("save-proxy-credentials").onclick=async()=>{
    const username=$("proxy-username").value,password=$("proxy-password").value;
    $("proxy-username").value="";$("proxy-password").value="";
    await action("proxy-credentials",{username,password},username||password?"账户已交给本次运行的服务；输入已清空，请重新检查。":"会话账户已清除，请重新检查。");
  };
  $("save-secret").onclick=async()=>{const secret=$("clash-secret").value;$("clash-secret").value="";await action("secret",{secret},"控制密钥仅在本次运行有效，请重新检查。");};
  async function refresh(){try{render(await api("snapshot"),!snapshot);}catch(e){notice(e.message);disconnected();}}
  refresh();setInterval(()=>{if(!busy)refresh();},3000);
})();
