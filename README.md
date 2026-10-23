# ExitGuard · 固定出口守护

ExitGuard 在本机核对指定出口，并通过系统过滤将明确选择的程序限制到守护代理。当前实现范围为 **IPv4 TCP**；受保护程序的 IPv6、UDP 和其他网络旁路应由系统过滤拒绝。它不会修改全局代理、默认路由、系统 DNS 或飞连配置，也不解密 HTTPS。

**当前交付是未激活开发版，强制完整保护目标尚未完成，不能作为已验证的保护工具。** 当前 Mac 没有合格签名的 Network Extension，入口保持未就绪；Windows 尚未实机验收。系统服务代发 DNS 与运行中更新新增辅助程序的全面覆盖机制尚未实现，不只是缺少测试。现有系统规则只约束明确列出的目标，不能证明整个 Claude 安全。固定节点、平台权限、真实客户端与逐项验证仍然必需；固定出口不能保证账号不被封禁。

## 本地启动

需要 Go 1.23 或更新版本。Mac 应用需要 macOS 13+、Apple 命令行开发工具和 Swift 编译器，无第三方运行时。

```sh
sh scripts/build-local.sh
open dist/ExitGuard.app
```

Mac 窗口使用 WKWebView，启动同一应用包里的 Go 核心，不另开普通浏览器。本地构建仅使用 ad-hoc 签名，不包含可激活的系统过滤；构建过程不安装扩展、不弹出系统网络授权、不改变办公网络。

```sh
sh scripts/build-windows.sh
```

得到 `dist/ExitGuard-windows-amd64.exe`。复制到 Windows 后启动即可打开本机控制面板；保留程序进程运行。此文件是在 Mac 上交叉编译的产物，不能据此认定 Windows 过滤或实际网络已验证。

不使用图形外壳时：

```sh
go run ./cmd/exitguard serve --no-open
```

`serve`（别名 `server`）只在成功独占监听后输出一次 ready JSON。URL 的 fragment 含本次运行的控制凭证，**不要转发或公开此输出**。浏览器加载后凭证从地址栏移除，仅保存在页面会话内；刷新整个页面或核心重启后需重新打开应用。控制 API 与本机代理复用 `127.0.0.1:17890`，无需为受保护浏览器另外放行控制端口。未验证时只允许经鉴权的控制请求，代理仍拒绝转发。

## 在控制面板中配置

1. 选择出口来源。Mac 选择公司飞连；Windows 建议选择已手工配置的“固定本地代理（专用入口）”。
2. 填写由节点服务商或公司网关确认的固定公网 IPv4。两台设备可使用各自的 IP。候选出口探测只展示本应用的观察值，不自动保存为期望 IP，不启用保护。
3. 明确添加程序的实际、规范化绝对路径，包括网络辅助程序。不会默认选中普通 Chrome，不会自动接管已有窗口。Mac Bundle ID 等细节在高级设置中。
4. 完成平台签名、权限与系统过滤部署，再检查当前策略。配置变更、会话密钥变更、出口变化或检查失败都会关闭入口，需要重新检查和启用。
5. 保护启用后，显式选择浏览器或 Claude 的入口启动，并在真实设备验证实际网络行为。

默认配置位置：macOS `~/Library/Application Support/ExitGuard/config.json`；Windows `%AppData%\ExitGuard\config.json`。可用 `--config PATH` 指定其他文件。配置不会保存 `armed` 状态或控制密钥；Clash 控制密钥只保留在本次核心进程的内存中，退出后需重新提交。

### Windows：Clash / Mihomo 专用入口

普通 Clash 控制 API 可以读取策略组，却不能证明任意代理端口始终绑定到一个固定节点。因此 `clash` 模式只做兼容检查，不能直接启用保护。使用支持 `listeners` 的 Mihomo 版本时，由用户在自己的配置中加入专用 HTTP 入口：

```yaml
listeners:
  - name: exitguard-in
    type: http
    listen: 127.0.0.1
    port: 17891
    proxy: "你的固定叶子节点名称"
    users: []
```

`proxy` 必须填写已有的具体单一节点名称，不能填写自动测速、故障转移、负载均衡、嵌套策略组或 `DIRECT`。`users: []` 避免继承全局代理认证；该入口只监听回环地址。此语法核对自 [Mihomo HTTP 入站文档](https://wiki.metacubex.one/en/config/inbound/listeners/http/) 和 [listeners 通用字段](https://wiki.metacubex.one/en/config/inbound/listeners/)。不同 Clash 客户端不一定使用兼容内核，请先确认自己的版本支持，不要覆盖原有订阅或公司配置。

然后在 ExitGuard 中选择“固定本地代理（专用入口）”，代理地址填写 `http://127.0.0.1:17891`。ExitGuard 自己使用的 `17890` 与上游 `17891` 不能冲突。应用不会修改其他 Clash 规则；节点和中继配置仍由用户管理。专用入口本身必须固定，且服务商确实提供固定公网出口，轮询检测无法保证网关从不在两次检查之间更换 NAT 地址。

### Mac：公司飞连

手动填写经确认允许使用的隧道接口。本应用的所有上游 IPv4 连接在连接前绑定该接口；绑定、接口指纹或路由检查失败时拒绝连接，不改用未绑定路径。`utun` 编号和“扩展已启用”都不证明飞连已连接、全局转发或提供固定公网出口。

所有出口通过同一路径使用 HTTPS DNS，只查询 IPv4 A 记录。默认是 `https://cloudflare-dns.com/dns-query` 与字面引导 IP `1.1.1.1`，可在高级设置中改为允许使用的服务；不会修改系统 DNS。公司出口不允许该 DNS 服务时需要填写合规且可达的地址，不能关闭验证来绕过。

## 受保护入口的范围

浏览器入口支持实际安装的 Chrome / Edge 可执行文件。只有当前策略已经启用、该规范化路径确实列入目标、用户明确确认程序级过滤范围时才会启动。使用独立的 `user-data-dir`、单一 `127.0.0.1` HTTP 代理、禁用 QUIC 与非代理 WebRTC UDP；公网代理列表没有 DIRECT 回退。只对本机控制端口保留明确的控制访问例外，其余连接仍须经过守护代理。

**独立资料目录不等于系统进程隔离。** WFP / Network Extension 按程序路径或应用身份过滤，同一程序的普通窗口也会受到限制。建议先关闭普通窗口，再启用此程序的系统策略；应用不会替你关闭或杀死它们。Mac 会遍历整个应用包的 Mach-O `MH_EXECUTE` 文件，包含不在 `.app/Contents/MacOS` 下的 `chrome_crashpad_handler` 等辅助程序，通用二进制的切片也会检查；这些实际路径必须全部列入策略。框架动态库不作为独立可执行程序。包外链接或无法解析的 Mach-O 布局会拒绝启动。运行中的自动更新可能引入新的辅助程序路径，目前没有自动把它们纳入系统策略的机制；不能继续认定覆盖完整。更新浏览器或客户端后需要重新核对路径、身份与规则。

Claude 入口要求实际安装的 `Claude.exe` 或 `Claude.app/Contents/MacOS/Claude`，主程序和 Mac 辅助程序都需在当前策略中。发现已有 Claude 实例或无法可靠核对进程时拒绝重复启动，需用户手动完全退出。启动时传入 Electron 代理参数，但当前 Claude 版本是否采用这些参数仍需验证；系统过滤会继续拒绝非代理连接。**启动成功只表示进程已启动，需要继续验证登录、聊天、上传、长连接与断线后的行为。** 当前 Mac 未发现 Claude 客户端，因此该路径尚未实测。

Chrome / Edge 与 Claude Electron 入口还设置 `--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1`，避免 Chromium 栈另行调用本机域名解析；守护代理和控制面板使用字面回环地址。Windows DNS Client 服务可能代其他代码发起解析，目标可执行文件的 WFP 规则不等于该系统服务也被限制。Claude 的非 Chromium 网络代码与系统代发 DNS 尚无完整覆盖机制，需要先补实现再做真实设备验证；当前不能宣称完整应用 DNS 覆盖。

参数行为参考 [Chromium 代理说明](https://chromium.googlesource.com/chromium/src/+/HEAD/net/docs/proxy.md) 与 [Electron 命令行开关](https://www.electronjs.org/docs/latest/api/command-line-switches)。产品不把参数本身视为系统过滤证据。

## 系统过滤部署与移除

以下是部署时由用户明确执行的命令，应用不会自动执行：

```sh
exitguard inspect --config /absolute/path/config.json
exitguard filter-install --config /absolute/path/config.json
exitguard filter-remove --config /absolute/path/config.json
```

Windows 在管理员终端中使用对应 `.exe`。只安装或移除 ExitGuard 自己的持久 WFP 规则，不重置其他防火墙策略。程序退出后持久过滤可能继续阻断被保护程序；需要恢复普通网络访问时，明确执行 `filter-remove`。安装时保留所用配置与程序路径，以便之后核对和移除。

Mac 需要合格的 Apple 签名、Network Extension / System Extension entitlement、应用和扩展的 provisioning profile、用户系统授权，以及对公司管理设备部署的许可。Go 核心还需在签名构建时固定 Apple Team ID；默认本地构建没有该值，不会信任外部伪造的 manager JSON。原生构建与签名脚本为 `platform/macos/filter-build.sh`、`platform/macos/filter-sign.sh`，部署细节见 `platform/macos/README-filter.md`。部署位置固定为 `/Applications/ExitGuard.app`，应用身份为 `com.exitguard.app`。

严格 Mac 过滤对无法确定来源身份的出站 socket 会逐条拒绝并报告异常，部署后可能影响少量其他未识别流量。这必须在安排好的真实设备验收中确认；当前未签名应用没有激活过滤，不会因此影响飞连或办公网络。普通 `.app` 的 ad-hoc 签名不能满足这些条件。

## 验证与尚未完成的验收

```sh
go test ./...
go test -race ./...
go vet ./...
sh scripts/build-local.sh
sh scripts/build-windows.sh
```

测试覆盖本机鉴权、Origin / Host、防配置注入、请求大小、控制与代理请求分类、系统策略匹配、禁止直接回退和断流时关闭本应用连接。CI 在 Mac / Windows 原生运行构建和确定性测试；CI 不安装系统过滤，也不发布应用。

必须在有权限且合适的测试时段，分别验证实际 Windows WFP、签名 Mac Network Extension、所选浏览器和真实 Claude：代理/内核/管理应用退出，VPN 断开恢复，Wi-Fi 切换、睡眠唤醒，IPv6 / UDP / DNS，辅助进程、上传和长连接。不能用交叉编译、一次公网 IP 探测或过滤配置回读代替这些验收。当前没有自动断开飞连、安装过滤或进行影响办公连接的测试。

精确验证记录与剩余条件见 `docs/validation.md`。
