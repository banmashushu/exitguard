# ExitGuard · 固定出口代理

## 当前原生桌面版

桌面入口为 `cmd/exitguard-desktop`，使用 MyGo 原生 Go 控件，不使用 WebView。Mac 与 Windows 均支持最多保存 32 份远程代理及各自的账户。保存或选择代理不会自动切换或启动连接；点击“使用此代理”后，仍需检查出口并手动启动。账户以受本机文件权限限制的明文保存，请勿分享配置目录中的凭据或代理列表文件。

构建固定使用 Go 1.27.3 与 MyGo v0.7.3：Mac 运行 `sh scripts/package-macos-desktop.sh`；Windows 运行 `sh scripts/package-windows-desktop.sh`，另需 NSIS 3.13。工具路径与 Windows 便携包、安装器说明见 [Windows 原生桌面交付](docs/windows-desktop.md)，Mac 使用说明见 [原生桌面说明](platform/macos/README-native.txt)。

Windows 当前交付版本为 v0.2.1；已发布的 Mac 应用保持 v0.2.0。普通代理只处理明确经过它的流量，系统级防绕行与真实 Windows 运行验收仍需单独完成。

## 工作方式与边界

ExitGuard 本身是一个仅监听 `127.0.0.1` 的 HTTP / CONNECT 代理。它可以直接连接你指定的 **HTTP、HTTPS 或 SOCKS5 上游代理**，支持账户认证，核对期望公网 IPv4，并在暂停、配置变化或出口检查失败时关闭本应用持有的连接。普通“代理转发”可在 Mac 和 Windows 独立运行，不需要安装 Claude、Network Extension 或 WFP。

面板明确区分两种方式：

| 方式 | 能做什么 | 启用条件 |
| --- | --- | --- |
| 代理转发 `proxy-only` | 转发明确经过本机代理的 IPv4 TCP；状态为 `proxy_ready` / `proxy_active` | 有效上游、手动确认的期望 IPv4、检查通过 |
| 严格阻断 `required` | 在代理之外核验目标程序的系统过滤策略；状态为 `ready` / `armed` | 还需平台部署、真实系统过滤证据及完整目标范围 |

**代理运行中不表示整个应用受保护。** UDP、忽略代理设置的代码、其他窗口或应用的直连不受普通代理模式约束。此模式不核验或更改系统规则；`filterActive:false` 表示没有当前系统过滤证明。若以前安装过持久 WFP 等规则，它们可能继续生效，切换方式或暂停代理不会自动卸载规则。

严格阻断仍是未完成真实设备验收的开发功能：本地 Mac ad-hoc 构建没有可激活的 Network Extension，Windows WFP 尚需实机验证；系统服务代发 DNS 与运行中更新新增辅助程序的全面覆盖仍有实现缺口。不能据此宣称完整 Claude 保护。固定出口也不能保证账号不被封禁。

本应用不会修改全局代理、默认路由、系统 DNS、公司飞连或订阅，不安装根证书，不解密目标 HTTPS。

Windows 的 Chrome / Edge / Claude 另有 **原生沙箱预览**：`sh scripts/package-windows-native.sh` 生成 `dist/ExitGuard-Windows-Native-Preview.zip`。它使用单独安装的官方 Sandboxie Plus v1.18.8，在现有桌面上仅通过产品箱启动应用；不使用虚拟机或整机分流。运行时有效策略与四个 WFP 回调均需实际核对，DNS broker 和三款应用仍待 Windows 验收，状态始终为 `preview-incomplete`。普通快捷方式和已有窗口不自动归组。详见 [原生预览说明](docs/windows-native-preview.md)。

## 构建原生桌面版

使用固定版本 Go 1.27.3 与 MyGo v0.7.3。Mac 目标为 Apple 芯片、macOS 13+；Windows 目标为 Windows 10 / 11 x64，安装器另需 NSIS 3.13。界面不依赖 WebView2 或浏览器运行时。脚本默认使用项目内的预检工具；其他机器可设置 `EXITGUARD_GO`、`EXITGUARD_MYGO`，Windows 另可设置 `EXITGUARD_MAKENSIS` 与 `NSISDIR`。

```sh
sh scripts/build-local.sh
```

此命令准备 Mac 原生应用与压缩包到 `.work/macos-native-release/`，不会安装、启动应用或替换已发布的 `dist` 产物。默认应用路径为 `.work/macos-native-release/ExitGuard.app`；本地 ad-hoc 签名构建未经过 Apple 公证，不安装系统扩展，也不改变办公网络。

```sh
sh scripts/package-windows-desktop.sh
```

得到 `dist/ExitGuard-Windows-x64.zip`、`dist/ExitGuard-Windows-x64-Setup.exe` 与 SHA-256 校验文件。便携版完整解压后运行 `ExitGuard.exe`；安装器按当前用户安装，提供桌面快捷方式与完成后启动选项。交叉编译和静态包检查不能代替真实 Windows 运行验收，详见 [Windows 原生桌面交付](docs/windows-desktop.md)。

## 可选 CLI / Web 面板

旧 `cmd/exitguard` 保留为独立 CLI 与 Web 面板入口；桌面主程序不接受这些子命令。原生桌面版的界面与代理核心在同一进程，回环端口仅处理代理流量，不提供 HTTP 控制面板。需要旧 Web 面板时单独运行：

```sh
go run ./cmd/exitguard serve --no-open
```

`serve`（别名 `server`）只在独占监听后输出一次 ready JSON。URL fragment 含本次运行的控制凭证，**不要转发或公开此输出**。页面读取后移除地址栏凭证，仅保存在页面会话中；完整刷新页面或重启核心后需重新打开应用。未启用会话时，只允许经鉴权的控制请求，代理拒绝转发。

Windows CLI 可用 `sh scripts/build-windows.sh` 单独构建为 `dist/ExitGuard-windows-amd64.exe`。它与桌面版是不同入口，不包含在当前原生 GUI 发行包内；同一代理监听端口不能同时被两个实例占用。

## 第一次使用原生桌面版：直接连接远程代理

1. 打开“代理设置”，点击“新建”，填写便于区分的代理名称。
2. 分栏填写协议、服务器 IPv4 / 主机名、明确端口、代理用户名、代理密码和期望出口 IP，点击一次“保存代理”。无需认证可将账户留空；新账户需同时填写用户名和密码，不要把账户放进服务器栏或 URL。
3. 每份代理独立保存并记住自己的账户，最多 32 份。保存或选择列表条目只进入编辑，不会切换或启动连接。编辑已有代理时，账户两栏都留空会保留原账户；密码不会回填。更换服务器需替换或明确勾选清除旧账户后保存。
4. 点击“使用此代理”，再到“出口概览”检查出口，通过后手动启动代理。概览也可选择已保存代理并点击“使用所选代理”；切换后保持关闭，需要重新检查和手动启动。同一时间仅使用一份代理。
5. 期望 IP 暂不确定时可先留空：保存并使用代理后，到概览测试候选 IP。候选值只用于展示，不自动保存或启动；向提供方核对出口与固定性后，**手动填写期望公网 IPv4** 并保存。
6. 保存当前使用的代理会暂停连接；删除需确认，删除当前代理也会关闭连接，不会自动切换到其他代理。重开应用恢复当前代理及其已保存账户，仍需检查并手动启动。
7. 将支持 HTTP 代理的应用手动指向界面显示的回环地址（默认 `http://127.0.0.1:17890`），或在“可选启动入口”明确选择 Chrome / Edge / Claude。无需先安装或登录 Claude；未安装只影响该入口。`proxy_active` 只表示本机转发已开启，不证明系统防绕行。

HTTP / SOCKS5 到上游代理服务器的连接本身**没有 TLS**，链路观察者可能读到账户认证；目标 HTTPS 的内容加密仍然保留。HTTPS 上游会先建立并正常验证 TLS，再认证，不支持忽略证书或自动降级。

目标域名通过选定上游使用 HTTPS DNS，只查询 IPv4 A 记录。默认 DNS 为 `https://cloudflare-dns.com/dns-query`，引导 IPv4 为 `1.1.1.1`；可在高级设置中使用获准且可达的其他服务。**上游代理服务器自身的主机名**可以通过系统 DNS 定位，并为活动路由固定一个 IPv4；目标域名不使用这条系统 DNS 路径。协议、认证、证书或连接错误不会直接回退到目标服务器。

出口检查是周期探测，存在检测时间窗口，不能证明两次检查之间上游 NAT 永不变化。请使用获准的上游与网络路径。

默认配置位置：macOS `~/Library/Application Support/ExitGuard/config.json`；Windows `%AppData%\ExitGuard\config.json`。可用 `--config PATH` 指定其他文件。普通配置不包含账户密码、控制密钥或启用状态；原生桌面版将代理列表及各自账户写入独立的 `config.json.profiles.json`（自定义配置对应 `PATH.profiles.json`）。Mac 使用 `0600` 文件权限，Windows 使用受限文件 ACL；这些是本机明文文件，不是加密保险箱，请勿分享。首次打开会导入原有远程代理及匹配的旧 `config.json.credentials.json` 账户记录，迁移或读取失败会报告错误并保持关闭。状态、事件和 API 响应不会返回账户密码。独立的 Clash 控制密钥仍只在当前进程有效。

## 可选启动入口

原生桌面版在启动时与明确点击“重新发现应用”时查找 Chrome、Edge 和 Claude Desktop；刷新状态不重新扫描。Mac 检查 `/Applications` 与 `~/Applications` 的应用包元数据；Windows 读取限定的 App Paths 注册项、已知安装目录与当前用户 Claude MSIX 清单。不会搜索任意用户文件、读取客户端账户或自动启动程序。Claude Code CLI 和 URL Handler 不会被当作桌面端候选；Windows MSIX 候选仍需实机验证。未发现时可填写实际可执行文件的完整路径。发现只提供选择，不会加入严格模式策略，普通代理本身不依赖此列表。

Chrome / Edge 使用独立 `user-data-dir`、单一回环 HTTP 代理，并禁用 QUIC 和非代理 WebRTC UDP，设置 `--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1`。代理列表没有公网 DIRECT 回退，仅为本机控制地址保留明确例外。发起启动前核对当前方式、状态、会话版本与代理地址；暂停、重新配置或重新启用后，旧会话启动请求会被拒绝。

Claude 入口要求实际安装的 `Claude.exe` 或 `Claude.app/Contents/MacOS/Claude`。发现已有 Claude 或无法可靠核对进程时，需用户手动完全退出后再启动；应用不会关闭已有进程。入口传入 Electron 代理参数，**当前 Claude 版本及 Code 标签页子进程是否采用这些参数仍需验证**。由 Desktop 管理提供方连接的部分会话对代理设置有独立读取规则；本应用不会修改 Claude 配置。代理模式中，未采用参数的代码可能直接联网。进程启动成功不能代替登录、聊天、上传、长连接和断线验证；当前没有使用真实 Claude 账户完成这项验收。

严格阻断保留更严格的启动条件：目标规范化路径必须列入当前策略，用户明确确认程序级范围，Mac 主程序及整个应用包中的 Mach-O `MH_EXECUTE` 辅助程序均需覆盖；包外链接或无法解析的 Mach-O 会拒绝启动。独立资料目录不隔离 OS 程序策略，同一程序的普通窗口也会受影响。更新可能新增辅助程序，目前没有自动覆盖机制。浏览器和 Electron 代理参数也不能证明系统代发 DNS 或非 Chromium 网络代码已被完整限制。

Claude Code 的代理和桌面端范围参考：[官方网络配置](https://code.claude.com/docs/en/network-config)、[Code 桌面端说明](https://code.claude.com/docs/en/desktop)。

参数依据：[Chromium 代理说明](https://chromium.googlesource.com/chromium/src/+/HEAD/net/docs/proxy.md)、[Electron 命令行开关](https://www.electronjs.org/docs/latest/api/command-line-switches)。

## 高级：已有本地 Mihomo / 公司飞连

可以继续使用已获准的现有路径，无需为了直接远程代理模式安装其他软件。

Clash 通用控制 API 无法证明任意端口固定绑定某节点，`clash` 来源只做只读兼容诊断，不能启用转发。已有 Mihomo 支持 `listeners` 时，用户可手动配置专用本地 HTTP 入口：

```yaml
listeners:
  - name: exitguard-in
    type: http
    listen: 127.0.0.1
    port: 17891
    proxy: "你的固定叶子节点名称"
    users: []
```

选择“本地 Mihomo 固定专用入口”，填写 `http://127.0.0.1:17891`。`proxy` 必须指向具体单一节点，不能是自动测速、故障转移、负载均衡、嵌套组或 `DIRECT`。ExitGuard 的 `17890` 与上游 `17891` 不可冲突。入口、订阅和传输由你管理，应用不会自动导入或改写。语法参考 [Mihomo HTTP 入站](https://wiki.metacubex.one/en/config/inbound/listeners/http/) 与 [listeners 字段](https://wiki.metacubex.one/en/config/inbound/listeners/)。

公司飞连来源需要手动确认获准的隧道接口。上游 IPv4 连接在连接前绑定该接口；绑定、接口指纹或路由检查失败会拒绝连接，不改用未绑定路径。`utun` 编号不证明飞连已连接或提供固定公网出口；应用不更改公司网络设置。

## Windows 上手包与环境检查

`dist/ExitGuard-Windows-MihomoParty-starter.zip` 包含 `1-check-environment.cmd` 和 `2-open-panel.cmd`。可先双击环境检查，无需购买代理、登录 Claude 或管理员权限；再打开面板按普通代理流程设置。Mihomo Party 目前更名为 Clash Party，它不是直接远程代理的必需依赖。

环境检查只读取系统版本、BFE / 提权状态、四类相关应用的运行进程线索，并对七个固定回环端口做无内容 TCP 连接；不访问公网、不读订阅或凭证、不安装或移除过滤、不修改系统设置。未发现进程不等于未安装，端口可达不等于服务身份或保护证明。报告会脱敏用户资料路径，`protection_assessed:false` 表示未评估系统保护。

```sh
sh scripts/package-windows-starter.sh
exitguard doctor --output 新报告.json
```

完整说明见 [Windows 上手向导](platform/windows/starter/START-HERE-zh-CN.txt)。导出报告只创建新文件；没有指定 `--output` 时输出 JSON 到终端。

## 可选的系统过滤部署与移除

严格阻断需要由用户明确部署，应用不会自动执行这些命令：

```sh
exitguard inspect --config /absolute/path/config.json
exitguard filter-install --config /absolute/path/config.json
exitguard filter-remove --config /absolute/path/config.json
```

部署前应明确选择 `required` 并核对完整目标。Windows 在管理员终端中使用对应 `.exe`；只管理 ExitGuard 自己的持久 WFP 规则，不重置其他防火墙策略。退出、暂停或切回普通代理后，持久规则可能继续阻断目标程序。需要恢复普通访问时，用安装时保留的配置与路径明确执行 `filter-remove`。

Mac 需要合格 Apple 签名、Network Extension / System Extension entitlement、应用与扩展 provisioning profile、系统授权及公司设备部署许可。Go 核心还需固定 Apple Team ID；默认本地构建没有此值，不信任伪造的外部 manager JSON。脚本为 `platform/macos/filter-build.sh`、`platform/macos/filter-sign.sh`，细节见 [Mac 过滤部署说明](platform/macos/README-filter.md)。部署位置固定为 `/Applications/ExitGuard.app`，身份为 `com.exitguard.app`。

严格 Mac 过滤会拒绝无法确定来源身份的出站 socket，部署后可能影响其他未识别流量，需要安排真实设备验收。本地未激活过滤的普通代理不需要这些条件。

## 验证范围与剩余工作

```sh
go test ./...
go test -race ./...
go vet ./...
node internal/ui/frontend_test.cjs
sh scripts/build-local.sh
sh scripts/build-windows.sh
```

自动化验证使用本机协议夹具，无需购买代理或真实账户。覆盖控制鉴权、Host / Origin、大小与配置注入限制、代理 / 控制分类、普通代理与严格方式分离、HTTP / HTTPS / SOCKS5 认证与失败行为、证书验证、凭证不回显、禁止直接回退、暂停断流与启动会话失效。它证明受控条件下的实现行为，不能替代真实服务商线路或客户端验收；不宣称已验证任何第三方节点。

真实上游、Chrome / Edge 和 Claude 仍需在使用设备验证出口、认证、上传和长连接。严格方式还需实际 Windows WFP、签名 Mac Network Extension 的断线、VPN 恢复、Wi-Fi / 睡眠切换、IPv6 / UDP / DNS 与辅助进程测试，并补齐上述系统代发 DNS 与更新覆盖缺口。CI 不安装系统过滤，也不发布应用；不会自动断开飞连或测试影响办公连接的操作。

历史严格过滤验证记录见 [验证记录](docs/validation.md)；其中未激活开发版的限制针对严格系统覆盖，不表示普通代理必须部署系统过滤才能使用。
