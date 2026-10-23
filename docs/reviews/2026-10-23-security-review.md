# ExitGuard 独立安全审阅 — 2026-10-23

审阅角色：Astra 独立验收。仅写本报告；未修改产品、index 或 HEAD，未安装/移除过滤器，未断开飞连，未执行签名部署。范围为本轮尚未提交的整个工程，依据已批准设计、实现计划及 WORKLOG rulings。实现者正在并行修复，下面明确区分已看到源码修复、待复验和未实现的能力。

## 两个交付结论

1. **未激活开发版：可以有条件交付。** 交付必须标明没有激活本机系统保护；完成下面正在修复的确定性代码问题及主代理的最终复验后，可作为源码、普通 Mac 应用与 Windows 构建产物交付。未配置/无签名状态核心入口关闭，未发现凭 UI 字段伪造系统保护的路径。
2. **“双端强制保护已可用”：不能宣称。** 除签名、固定出口、Windows 实机、真实 Claude 和办公网络验收条件外，系统服务代发 DNS 与应用更新后新增 helper 的覆盖机制尚未完成。这两项属于实现边界，不能仅写成“尚未实测”。WFP providerless 改造在本轮截稿时仍待复审，不能给未读过的后续实现背书。

## Critical

本轮未确认 Critical 级别缺陷。此结论不等于生产安全认证，也不消除下列 Important 项。

## Important

### I1. 系统委托 DNS 没有被按目标 executable 的 WFP 规则覆盖 — 未完成的实现边界

- 位置：`internal/enforce/rules.go:22`、`internal/enforce/platform_windows_amd64.go:229`、`internal/guard/dns.go:170`、`internal/ui/launch.go:85` / `:139`。
- 触发：被选中的程序调用 Windows DNS API，DNS Client 服务代其发出查询。实际网络连接属于系统服务；规则只匹配选定的 ALE_APP_ID，代理自身的同路由 DoH 不控制此委托路径。
- 后果：即使入口处于 armed 且程序自身 UDP 被拒绝，系统服务仍可能通过普通网络解析目标域名。Claude 的非 Chromium 代码尤其不能由 Electron 参数证明覆盖。
- 主代理裁决：增加 Chromium `host-resolver-rules` 防御，但不全局封公司 DNS；完整系统委托解析列为未完成的强制覆盖阻断项。最终文档/界面应采用这一结论。
- 参数修复必须精确排除 `127.0.0.1`，否则 Chromium 映射规则也可能影响代理/面板的字面地址。截稿补充：已读到 `MAP * ~NOTFOUND, EXCLUDE 127.0.0.1` 修复。UI 实现者报告 fixture RED→GREEN，且真实 Chrome 临时 headless profile 的仅回环测试确认 `127.0.0.1` 可达、`localhost` 被拒绝且 HTTP 服务无对应请求；这份运行证据来自实现者，主代理仍需汇总最终复验。
- 依据：[Microsoft DNS Client service resolver](https://learn.microsoft.com/en-us/windows-server/networking/dns/queries-lookups)、[Chromium MappedHostResolver](https://chromium.googlesource.com/chromium/src/+/HEAD/net/dns/mapped_host_resolver.cc)、[Chromium HostMappingRules](https://chromium.googlesource.com/chromium/src/+/HEAD/net/base/host_mapping_rules.cc)。

### I2. 应用更新后新增/迁移的辅助程序不会自动使策略失效 — 未完成的实现边界

- 位置：`internal/ui/launch.go:234`、`platform/macos/FilterPolicy.swift:56` / `:68`、`platform/macos/FilterManager.swift:110`。
- 触发：启动时 helper 列表完整，但浏览器/客户端更新到新 framework version，或正在运行的程序随后启动新的 helper executable。
- 后果：helper 枚举只在受保护入口启动时执行；周期 Inspect 只验证已保存 policy/hash 与存活 provider。新路径被视为已知非目标，可能直接联网，而原策略仍可保持匹配。
- 要求：完整强制保护需有持续的应用/辅助程序清单与版本变化处理，或能阻止未认可版本的网络。仅提示“更新后请重查”不构成自动失效机制。可以作为未激活开发版的明确限制保留，不能宣称动态完整覆盖。

### I3. WFP 持久 provider 与服务生命周期含糊 — 正在改造，待复审

- 截稿位置：`internal/enforce/platform_windows_amd64.go:257`、`:280`–`:290`；此前 `provider.Service == nil`，provider/sublayer/filter 都设置持久标记。
- 风险触发：BFE 重启或机器重启。Microsoft `FWPM_PROVIDER0` / `FWPM_FILTER0` 的 disabled 字段说明，无关联 auto-start service 的 provider 可能导致过滤 disabled；主代理也查到 Object Management / ProviderAdd 有不同表述。因此本报告不把未经 Windows 实机验证的具体重启行为写成确定事实，但原设计不能仅凭 persistent 标记证明跨重启阻断。
- 原代码会拒绝 disabled 的 OS 读回，因此没有把该 disabled 状态直接伪造 active；然而关闭本地代理本身不能阻断已恢复普通网络的目标进程。
- 主代理已裁决改为 **providerless persistent sublayer + filters**，保留唯一产品 GUID、metadata、精确规则读回和严格所有权删除。该更小修复避免关联 provider 的 disabled 歧义；截稿尚未读到最终改造，必须独立复验所有权检查、回读及移除逻辑。启动前/BFE 未运行期间的保护和真实重启仍须单独验收。
- 依据：[FWPM_PROVIDER0](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_provider0)、[FWPM_FILTER0](https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0)。

### I4. Mac 签名校验失败曾被当作非目标放行 — 已见源码修复，待最终测试确认

- 原位置：`platform/macos/FilterIdentity.swift:66`–`:68`（初审版本）；当前修复位置 `:60`–`:63`、`platform/macos/FilterPolicy.swift:15`–`:19` / `:63`–`:65`、`platform/macos/FilterProcesses.swift:42`–`:44`。
- 触发：策略包含 BundleIDs，Security 能读 signing metadata，但 `SecCodeCheckValidity` 失败；原代码返回 `identifier=nil, signatureResolved=true`。如果路径未单列，provider 跳过未知身份处理，策略把它作为非目标 allow。
- 修复核对：当前 `signatureResolved` 需要有效签名和非空 identifier，provider 通过 identities verdict 对未能证明的 bundle 身份返回 unknown 并 drop；进程快照也拒绝无效/缺失签名身份。新增无效签名、nil/空 identifier 纯策略测试已存在。此修复符合严格未知身份 ruling。

### I5. Mac 入站流曾全部放行，允许目标通过该流发送非守护路径数据 — 已见源码修复，待最终测试确认

- 原位置：`platform/macos/FilterDataProvider.swift:55`、`platform/macos/FilterPolicy.swift:48`（初审版本）；当前 `FilterPolicy.swift:54`–`:60`、`FilterDataProvider.swift:54`–`:74`。
- 触发：所选程序接受一个非 guard 的入站 TCP/UDP/IPv6 流，再通过该连接发送响应。`direction` 表示流的初始方向，不表示该流永远只有入站字节。
- 修复核对：已删除 provider 的 inbound early allow；先识别是否目标，目标入站 drop，已知非目标入站 allow；未知身份继续 drop。新增入站目标/非目标/未知策略测试已存在。
- 依据：[Apple NEFilterFlow.direction](https://developer.apple.com/documentation/networkextension/nefilterflow/direction)。

### I6. Mac 辅助程序枚举漏掉独立可执行 helper — 已见源码修复，待最终测试确认

- 原位置：`internal/ui/launch.go:245`（仅匹配 `.app/Contents/MacOS`）；当前修复 `:234`–`:329`。
- 触发：Chrome 实际包含 `Frameworks/Google Chrome Framework.framework/Versions/155.0.8059.85/Helpers/chrome_crashpad_handler` 等独立 executable。初审在本机安装包只读确认该文件；原扫描完全跳过，即使未纳入系统策略也允许“受保护启动”。Crashpad 在用户开启上报时能够自行上传。
- 修复核对：现遍历整个 Contents，以 Mach-O `MH_EXECUTE` 判断实际程序，包含 fat slices，拒绝包外 symlink、无法解析的 Mach-O，排除 dylib。实际 helper canonical path 必须在策略中。已读到 standalone crashpad 与 dylib fixture，UI 实现者报告 RED→GREEN；这修复启动时已存在 helper 的漏洞，**不解决 I2 的运行期更新问题**。
- 依据：[Chromium Crashpad handler](https://github.com/chromium/crashpad/blob/main/handler/crashpad_handler.md)。

### I7. Windows 测试 fixture/权限断言不具跨平台性 — 待核心实现者修复

- 位置：`internal/guard/service_test.go:32`、`:153`。
- 触发：Windows 原生 CI 执行 guard tests。`validConfig` 固定 `/Applications/...`，Windows `filepath.IsAbs` 不接受无盘符路径，configured() 依赖的大量测试会先因配置校验失败。权限断言又无条件要求 Unix `0600`，不能表达 Windows ACL。
- 要求：使用当前平台绝对路径 fixture；Unix permission test 与 Windows ACL/继承边界分开处理。不能用 Windows 交叉编译成功代替原生测试通过。主代理已接手协调修复。

## Minor

### M1. 暂停与长操作共用互斥锁，不能立即执行

- 位置：`internal/ui/server.go:190`、`internal/ui/assets/app.js:30` / `:45`。
- 触发：已 armed 时执行程序启动检查（Claude 进程检查最长约 4 秒），或某个已鉴权 POST 正在读取请求体，用户此时点击暂停。
- 当前结果：前端 busy 禁用暂停，API 也返回 409；已有代理连接仍可继续，直到前一个操作结束或其超时。核心 Disarm 本身具备取消验证与关闭连接能力，UI/API 不应把该能力挡在普通操作锁后。
- 建议：鉴权/输入验证后把 Disarm 作为独立立即操作，允许取消其他操作；启动完成前仍应检查入口当前状态。已通知 UI 实现者。此项不构成已确认的直接出口绕过。

## 已核对且未发现确定漏洞的路径

- `Service.validate` 在启用前要求监听器归属、完整配置、两次 exact policy proof、同路由探测与前后指纹一致。配置、secret、暂停及阻断递增 generation；旧任务不能重新打开入口。
- 目标连接在 admission 后进入连接跟踪；Disarm/配置变化/health failure 关闭已持有连接；后完成的 dial 也由 generation 检查拒绝。不使用上游失败后的直接 dial 回退。
- 固定本地 proxy 模式仅连接配置的回环上游；Clash 普通 controller 不能证明 listener-node binding 时明确不支持启用。
- Feilian 上游使用字面 IPv4 socket、连接前 `IP_BOUND_IF`，绑定/接口验证失败终止。同一路径 DoH 使用字面 bootstrap，不调用系统 DNS；只发 A 查询。此证据仅覆盖守护自身连接，不能扩大成 I1 的目标系统委托解析证明。
- control/proxy 共享端口以 origin-form + exact local Host 分类；CONNECT/absolute-form 不进入控制 handler。API 所有操作要求随机 bearer token，foreign Origin/Host 和 cross-site 被拒绝；未发现由网页构造请求取得控制权限的路径。
- 本地 UI 渲染配置/事件使用 textContent；未发现配置反射脚本执行或密钥持久化。
- Mac proof 同时核对 pinned signing team、manager 身份、OS preferences、双向签名 XPC live provider、nonce/hash/strict build。默认 unsigned build 不可能通过 trustedManager；未用 receipt 或 JSON checkbox 替代系统证明。
- WFP 的 IPv4 complement 规则分别阻止地址/端口/协议不符并阻止全部 IPv6，避免“宽泛 BLOCK + 窄 PERMIT”优先级错误。常量 UINT8/16/32、NOT_EQUAL 和 host-order IP/port 与 Microsoft 主源一致；x64结构尺寸有编译断言。**未在本机执行 Windows ABI 系统调用或流量测试。** [FWP_VALUE0](https://learn.microsoft.com/en-us/windows/win32/api/fwptypes/ns-fwptypes-fwp_value0)、[FWP_MATCH_TYPE](https://learn.microsoft.com/en-us/windows/win32/api/fwptypes/ne-fwptypes-fwp_match_type)。

## 验收证据与尚未发生的事项

本轮以完整源码、测试源码、本机 Chrome 文件布局和少量官方 API 主源做独立审阅；全套 Go/race/vet/build 的复跑由主代理承担。看到测试代码不等于声称测试已执行。未运行任何系统过滤安装、移除、BFE 重启、公司 VPN 断开或真实 Claude 流量。没有签名身份、固定IP节点、Windows设备和实际客户端时，不能给出“阻断已验证/强制保护可用”的最终验收。

后续定向复审只需覆盖：providerless WFP 最终改造；DNS flag loopback exception 与本机回环验证；Windows测试fixture；最终文档/界面对 I1/I2 的明确未完成说明；本轮已见源码修复对应测试的最终结果。

## 最终定向复审结果（同日，覆盖前文待复审状态）

本轮只复审主代理指定的最终修复，没有扩大功能审阅或修改产品代码。

- **I3 providerless WFP：源码审阅通过。** `platform_windows_amd64.go:249`–`:281` 创建无 provider 的持久 filter/sublayer；`:340`–`:364` 精确回读 flags、nil provider、product sublayer、layer/action/weight、metadata、app identity 与条件；`:464`–`:499` 的枚举仅认领产品 sublayer 内、nil provider 且 metadata 与稳定 GUID 相符的对象，任何陌生对象使操作失败；`:531`–`:561` 先验证 sublayer，再在事务中删除拥有的 filters 与 sublayer，不删除任意 provider。`rules.go:45`–`:61` 拒绝未知字段、多份 JSON、无效 hash/path/rule index 与不匹配稳定 key。未发现此次去 provider 改造放宽所有权删除范围。对应 metadata 单测通过，Windows native readback 测试源码含 foreign-provider 拒绝；本机没有执行 Windows 系统调用或重启测试。
- **I4 / I5 Mac 身份与入站流：源码及本地策略测试通过。** 有效签名与非空 identifier 才构成已解析身份；bundle 规则下失败身份返回 unknown，provider drop。目标 inbound drop、非目标已知 inbound allow、未知身份 drop；kernel audit-token 路径解析仍保留。已运行本轮构建的 `filter-policy-tests` 与只读 `filter-process-tests`，均通过。
- **I6 / DNS 参数：修复通过源码核对。** 全 Contents 的 Mach-O `MH_EXECUTE` / fat slices 纳入 helper 清单，standalone crashpad fixture 与 dylib 排除测试通过；两种启动路径均使用 `MAP * ~NOTFOUND, EXCLUDE 127.0.0.1`。真实 Chrome 临时 profile 的回环验证沿用 UI 实现者和主代理提供的运行证据，本审阅没有重复启动浏览器。此项仍不解决 I1/I2。
- **I7 Windows fixture：修复通过。** `service_test.go:32` 改用 `validConfig(t)` 与 `t.TempDir()` 构造平台绝对路径；`:146`–`:171` 只在非 Windows 断言 0600，同时所有平台继续检查配置不会持久化 armed。注释明确 Unix mode 不证明 Windows DACL。已定向重跑该测试通过；Windows 原生执行仍待实际平台。
- **M1 立即暂停：修复通过。** `server.go:190`–`:198` 在鉴权及请求校验后、普通 action 锁前处理 Disarm；`app.js:45`–`:53` 允许 busy 时暂停；`launch.go:151`–`:160` 在创建进程前复核当前 armed/filter/hash/proxy 状态。后台长操作暂停与最后启动检查测试通过，前端 busy/恢复/服务断开状态测试通过。
- **能力边界：已明确披露。** `README.md:5`、`:70`、`:74`，`docs/validation.md:5`–`:12` 及固定 UI 开发版横幅均明确系统代发 DNS、运行中更新后新增 helper 的完整机制尚未实现，不把它们仅称为待测试。BFE/开机验收、签名部署和实际目标客户端仍列未验证。

本轮独立执行的定向证据：enforce 规则补集与 metadata 所有权测试、UI standalone helper/立即暂停/最终启动状态测试、前端 DOM 状态测试、Swift policy/process 测试均通过。第一次 guard 测试在沙箱内因 `bind: operation not permitted` 失败；仅针对该回环测试获取环境执行权限后重跑通过，属于运行环境限制，未认定为代码回归。全套 Go tests/race/vet、双端构建和最终打包结果由主代理独立运行并写入交付记录。

**最终结论：未激活开发版可以交付，本次指定修复没有剩余的交付阻断代码发现；不能宣称真实生产强制保护已经可用。** I1/I2 仍是明确未完成的机制，另需固定出口、有效 Mac 签名与授权、Windows 实机、真实 Claude/浏览器和逐项断线/重启验收。主代理最终重新打包及补全验证记录后即可交付开发产物，整个强制保护目标保持未完成。
