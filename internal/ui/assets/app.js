"use strict";
(() => {
  const fragment = new URLSearchParams(location.hash.slice(1));
  const token = fragment.get("token") || "";
  history.replaceState(null, "", "/");
  const $ = id => document.getElementById(id);
  let snapshot = null, busy = false, editing = false;
  const states = {unconfigured:["尚未配置","保护尚未就绪"],checking:["正在检查","正在验证出口路径"],blocked:["守护入口已关闭","保护暂不可用"],ready:["检查通过","已就绪，等待启用"],armed:["保护已启用","目标程序仅允许访问守护代理"],stopped:["已暂停","受保护代理已关闭"]};
  const lines = value => value.split(/\n|,/).map(s => s.trim()).filter(Boolean);
  function notice(message, success=false) { const el=$("notice"); el.textContent=message; el.classList.toggle("success",success); el.hidden=false; }
  async function api(path,body) {
    if(!token) throw new Error("此页面缺少本次运行的控制凭证，请关闭窗口并重新打开 ExitGuard。");
    const response=await fetch("/api/"+path,{method:body===undefined?"GET":"POST",headers:{Authorization:"Bearer "+token,...(body===undefined?{}:{"Content-Type":"application/json"})},body:body===undefined?undefined:JSON.stringify(body),cache:"no-store",credentials:"omit",referrerPolicy:"no-referrer"});
    const data=await response.json(); if(!response.ok) throw new Error(data.error||"本机服务请求失败"); return data;
  }
  const setText=(id,value)=>{$(id).textContent=value||"—";};
  function disconnected(){snapshot=null;$("status-card").className="status-card blocked";setText("state-label","本机服务离线");setText("state-heading","无法连接本机服务");setText("reason","请重新打开 ExitGuard。旧状态不能作为有效保护证据。");setText("filter-note","系统过滤状态未知；当前页面没有可用的本机会话。");["arm","disarm","launch","launch-claude"].forEach(id=>$(id).disabled=true);$("check").disabled=false;$("candidate").disabled=false;}
  function render(data,fill=false) {
    snapshot=data; const c=data.config,s=data.status, state=states[s.state]||[s.state,"状态未知"];
    setText("state-label",state[0]); setText("state-heading",state[1]); setText("reason",s.reason);
    $("status-card").className="status-card"+(s.state==="armed"?" armed":s.state==="blocked"||s.state==="unconfigured"?" blocked":"");
    const mac=s.platform==="darwin"; setText("platform",mac?"◉ macOS · 本机":s.platform==="windows"?"◉ Windows · 本机":s.platform+" · 本机");
    setText("source",c.mode==="proxy"?"固定本地代理":c.mode==="clash"?"Clash / Mihomo（只读）":c.mode==="feilian"?"公司飞连":"尚未配置");
    setText("source-detail",c.mode==="proxy"?(c.proxyURL||"尚未指定专用入口"):c.mode==="clash"?(c.clashNode||"尚未指定固定节点"):(c.tunnelInterface||"尚未确认隧道接口"));
    setText("expected",(c.expectedIPs||[]).join(" / ")||"未设置"); setText("observed",s.observedIP||"尚未观察");
    const checked=s.checkedAt?new Date(s.checkedAt).toLocaleString("zh-CN",{hour12:false}):"尚未检查";
    setText("checked-at",checked); setText("filter-note",s.filterActive?"系统过滤已匹配当前策略。真实断线、辅助进程与协议覆盖仍需在目标设备验证。":"系统过滤：未验证或未安装。出口探测成功不代表目标应用已受保护。");
    setText("scope-note",s.filterActive?"当前保护范围为 IPv4 TCP；IPv6 / UDP 已阻断。":"保护范围为 IPv4 TCP；启用系统过滤后拒绝 IPv6 / UDP。");setText("install-help",mac?"当前本地 ad-hoc 应用不能启用 Network Extension。需要合格签名、扩展部署与系统授权，再执行显式过滤安装。":"需要管理员显式安装本产品的 WFP 规则，并在实际 Windows 设备验证。保存配置不会安装规则。");
    $("step-ip").classList.toggle("done",!!c.expectedIPs?.length); $("step-target").classList.toggle("done",!!(c.programs?.length||c.bundleIDs?.length)); $("step-filter").classList.toggle("done",s.filterActive);
    $("check").disabled=busy;$("candidate").disabled=busy;$("arm").disabled=busy||s.state!=="ready"; $("disarm").disabled=s.state!=="armed"; $("launch").disabled=busy||s.state!=="armed";$("launch-claude").disabled=busy||s.state!=="armed";
    setText("diag-state",state[0]+" · "+s.state); setText("diag-filter",s.filterActive?"当前策略匹配":"未就绪"); setText("diag-proxy",s.proxyAddress||"未监听"); setText("diag-policy",s.policyHash||"未验证"); setText("diag-checked",checked);
    const current=$("browser-path").value; $("browser-path").replaceChildren(); const empty=document.createElement("option"); empty.value=""; empty.textContent="显式选择已配置的浏览器程序"; $("browser-path").append(empty);
    const priorClaude=$("claude-path").value;$("claude-path").replaceChildren();const noClaude=document.createElement("option");noClaude.value="";noClaude.textContent="显式选择已配置的 Claude 程序";$("claude-path").append(noClaude);let hasClaude=false;
    for(const path of c.programs||[]){const base=path.split(/[\\/]/).pop();let target;if(/^(chrome\.exe|msedge\.exe|Google Chrome|Microsoft Edge)$/i.test(base))target=$("browser-path");else if(/^(Claude|Claude\.exe)$/i.test(base)){target=$("claude-path");hasClaude=true}if(target){const o=document.createElement("option");o.value=path;o.textContent=path;target.append(o)}} $("browser-path").value=current;$("claude-path").value=priorClaude;setText("claude-badge",hasClaude?"已配置 · 待实测":"尚未配置");
    const eventRoot=$("event-list"); eventRoot.replaceChildren(); eventRoot.className="";
    if(!data.events?.length){eventRoot.className="events-empty";eventRoot.textContent="本次运行暂无事件"}
    for(const e of [...(data.events||[])].reverse()){ const row=document.createElement("div");row.className="event-row";const time=document.createElement("time");time.textContent=e.at?new Date(e.at).toLocaleTimeString("zh-CN",{hour12:false}):"—";const stateEl=document.createElement("span");stateEl.className="event-state";stateEl.textContent=(states[e.state]||[e.state])[0];const text=document.createElement("p");text.textContent=e.message;row.append(time,stateEl,text);eventRoot.append(row) }
    if(fill&&!editing) fillForm(c); toggleMode();
  }
  function fillForm(c){ const fields={mode:c.mode||"feilian","expected-ips":(c.expectedIPs||[]).join(", "),"proxy-port":c.proxyPort||17890,"probe-url":c.probeURL||"https://api.ipify.org?format=json",tunnel:c.tunnelInterface||"","dns-url":c.dnsResolverURL||"https://cloudflare-dns.com/dns-query","dns-bootstrap":c.dnsBootstrapIP||"1.1.1.1",upstream:c.proxyURL||"","fixed-upstream":c.proxyURL||"",controller:c.clashControllerURL||"",selector:c.clashSelector||"",node:c.clashNode||"",programs:(c.programs||[]).join("\n"),"bundle-ids":(c.bundleIDs||[]).join("\n")};for(const [id,v] of Object.entries(fields)) $(id).value=v; }
  function config(){ return {mode:$("mode").value,expectedIPs:lines($("expected-ips").value),proxyPort:Number($("proxy-port").value),probeURL:$("probe-url").value.trim(),tunnelInterface:$("tunnel").value.trim(),dnsResolverURL:$("dns-url").value.trim(),dnsBootstrapIP:$("dns-bootstrap").value.trim(),proxyURL:($("mode").value==="proxy"?$("fixed-upstream"):$("upstream")).value.trim(),clashControllerURL:$("controller").value.trim(),clashSelector:$("selector").value.trim(),clashNode:$("node").value.trim(),programs:lines($("programs").value),bundleIDs:lines($("bundle-ids").value)}; }
  function toggleMode(){const mode=$("mode").value;$("clash-settings").hidden=mode!=="clash";$("feilian-settings").hidden=mode!=="feilian";$("proxy-settings").hidden=mode!=="proxy";}
  function view(name){document.querySelectorAll(".view").forEach(e=>e.hidden=e.id!==name);document.querySelectorAll(".nav").forEach(e=>e.classList.toggle("active",e.dataset.view===name));setText("page-title",{overview:"出口概览",settings:"保护设置",events:"诊断与事件"}[name]);window.scrollTo(0,0)}
  document.querySelectorAll("[data-view]").forEach(el=>el.addEventListener("click",()=>view(el.dataset.view)));document.querySelectorAll("[data-open-settings]").forEach(el=>el.addEventListener("click",()=>view("settings")));
  async function action(path,body={},success){
    const pause=path==="disarm";
    if(busy&&!pause)return;
    if(!pause)busy=true;
    document.querySelectorAll(".status-actions button,#launch,#launch-claude").forEach(e=>e.disabled=true);
    if(snapshot)render(snapshot);
    try{const data=await api(path,body);if(data.status)render(data);if(success)notice(success,true)}
    catch(e){notice(e.message);try{render(await api("snapshot"))}catch{disconnected()}}
    finally{if(!pause)busy=false;if(snapshot)render(snapshot)}
  }
  $("candidate").onclick=async()=>{if(busy)return;busy=true;try{const data=await api("candidate",{});notice("候选出口："+data.candidateIP+"。仅代表守护进程；请向出口提供方确认固定性后，手动填写期望 IP。",true);render(await api("snapshot"))}catch(e){notice(e.message)}finally{busy=false;try{render(await api("snapshot"))}catch{disconnected()}}};$("check").onclick=()=>action("check",{},"出口检查已完成，请核对系统过滤和目标覆盖范围。"); $("arm").onclick=()=>action("arm",{},"保护已由本机服务启用。");$("disarm").onclick=()=>action("disarm",{},"已暂停保护，并关闭本应用持有的连接。");$("refresh").onclick=refresh;
  $("launch").onclick=()=>{if(!$("browser-path").value)return notice("请先明确选择已经配置的 Chrome / Edge 可执行文件。");if(!$("scope-ack").checked)return notice("请确认已了解同一程序的所有窗口都会受到系统过滤。");action("launch",{kind:"browser",path:$("browser-path").value,acknowledgeProgramScope:true},"已启动独立浏览器；请在目标设备继续验证实际出口和断线行为。")};
  $("launch-claude").onclick=()=>{if(!$("claude-path").value)return notice("尚未安装或配置 Claude。请先安装客户端并添加真实程序及辅助进程路径。");if(!$("scope-ack").checked)return notice("请先确认程序级过滤范围，并手动退出已有 Claude 进程。");action("launch",{kind:"claude",path:$("claude-path").value,acknowledgeProgramScope:true},"已提交 Claude 启动。代理参数是否被当前版本采用，需要继续验证登录、聊天和上传；系统过滤仍会拒绝非代理连接。");setText("claude-note","启动后待实测：登录、聊天、上传及断线行为。")};
  $("config-form").addEventListener("input",()=>editing=true);$("mode").addEventListener("change",toggleMode);$("config-form").addEventListener("submit",async e=>{e.preventDefault();await action("config",config(),"设置已保存。请重新检查路径和系统策略。");editing=false;});
  $("save-secret").onclick=async()=>{const secret=$("clash-secret").value;$("clash-secret").value="";await action("secret",{secret},"控制密钥已交给本次运行的服务；退出应用后失效。")};
  async function refresh(){try{render(await api("snapshot"),!snapshot)}catch(e){notice(e.message);disconnected();}} refresh();setInterval(()=>{if(!busy)refresh()},3000);
})();
