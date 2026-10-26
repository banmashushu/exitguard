# Windows / Mihomo Party starter 定向安全审阅

审阅日期：2026-10-25。角色：Astra/xhigh，只读代码验收；本报告是唯一写入文件。范围限 `internal/diagnostics/*`、doctor CLI、Mihomo Party 覆写例子、Windows CMD/说明、打包脚本与 README 的 Windows 新增段。未重审旧网络内核，未安装过滤、修改 Windows/Mac 网络或访问真实订阅。

## Critical

未发现。

## Important

### W1. 自动安装位置探测可能访问远端文件系统 — 已修复并定向复核

- 初审位置：`internal/diagnostics/platform_windows.go:89`–`:94`。
- 触发：`LOCALAPPDATA` / `ProgramFiles` 等环境候选根目录指向 UNC、映射网络盘，或其子目录经 reparse 指向远端。`filepath.IsAbs` 接受 Windows UNC，随后 `os.Stat` 可发起 SMB 等远端文件访问；输出端省略 UNC 路径不能消除已经发生的访问。
- 影响：违背本次 doctor 仅本机元数据与固定回环握手的网络边界，也可能触发 Windows 对远端共享的身份验证。这不是 Windows 交叉编译能验证的行为。
- 已与主代理确认最小修复：去掉全部环境候选文件探测，只保留 CIM allowlist 的运行进程事实，不读取可执行文件；discovery 改为 `limited_running_processes`，说明未检测不等于未安装，不要求开启或登录 Claude。最终修复结果见本文末尾。

## Minor

本轮未发现需要阻断只读 starter 交付的其他问题。

## 已核对边界

- **doctor 与保护操作隔离。** `cmd/exitguard/main.go:44`–`:47` 在查找配置目录和 `guard.New` 前单独分派 doctor；其参数只接受 `--output`，不进入 inspect/install/remove/serve。测试用损坏的 guard 配置验证它不读取、改写或创建 guard 状态。
- **不采集订阅/密钥。** diagnostics 不导入 guard/enforce，不打开配置、订阅或凭证。PowerShell 只在本地查询 OS 版本/build、BFE State、当前提权布尔状态，以及四类 allowlist 应用的 Name/ExecutablePath；不输出 CommandLine、电脑/域名称、网卡或其他进程。输出解析再次白名单过滤，错误信息不回显原始 PowerShell 输出。
- **不自动提权或改系统。** 固定系统目录 PowerShell 使用 NoProfile/NonInteractive，无 ExecutionPolicy bypass、RunAs、服务启动/停止、注册表/代理/防火墙写入。CMD 第一入口只执行 doctor；第二入口只打开既有 serve 面板并隐藏 ready token 输出，均无 filter-install/remove。
- **回环探测范围明确。** `diagnostics.go:92`–`:111` 仅对 127.0.0.1 的七个固定端口做 120ms TCP4 握手，成功即关闭，不读写协议字节。只有明确 connection-refused 为 false；权限不足、超时、取消及未知错误为 null。报告固定 `protection_assessed=false`，不以 TCP 可达或 BFE running 推断服务身份/保护有效。
- **路径隐私。** 报告只容纳 allowlist 应用路径，省略 UNC/device 路径；当前 user-profile 前缀和标准 `C:\Users\name` 前缀被替换为 `%USERPROFILE%`。没有完整环境转储。说明要求分享前自行查看报告；有限运行线索不等于完整安装清单。
- **报告不覆写。** `main.go:176`–`:181` 使用 `O_CREATE|O_EXCL` 创建显式输出文件，已有文件及已有输出 symlink 失败；无 output 时仅写 stdout。Unix 0600 不被宣传为 Windows DACL 保证。写入失败返回固定错误，不能被误当成功报告。
- **CMD 与打包。** 已检查两个 CMD 为 UTF-8/CRLF，路径和报告名加引号；正常双击不会提权、改执行策略或安装 WFP。打包在独立临时目录交叉编译、复制五个固定文件、产生专用 starter ZIP，不替换旧开发包；只清理自身 mktemp 目录。Windows 运行与 WFP 验收明确未完成。
- **覆写默认 no-op。** `TARGET_PROXY=""` 在任何配置访问前原样返回。显式目标必须是唯一现存叶子，拒绝内置 DIRECT/REJECT/PASS 等、策略组、重复/未知节点、未知协议和 dialer-proxy 链。规则、proxies、proxy-groups、认证、系统代理及其他 listener 不修改。
- **覆写冲突与幂等。** 验证先于唯一写入 `config.listeners`。专用入口严格为 HTTP / 127.0.0.1:17891 / users:[] / 指定 leaf；端口/名称冲突或无法可靠理解的 listener port range/list/空白格式抛错且原配置不变。已存在且所有字段精确相同的入口原样返回；不自动导入。

## 本轮独立验证

- diagnostics 白名单/脱敏、固定回环无内容探测、unknown 处理、元数据过滤，以及 doctor 配置隔离/显式输出测试：通过。
- `node examples/mihomo-party-exitguard.test.cjs`：通过，覆盖默认 no-op、只改 listener、幂等、无效目标和冲突后不变。
- `sh -n scripts/package-windows-starter.sh`：通过；CMD 字节格式已只读检查。
- 以上不是 Windows 实机测试，本轮没有在 Windows 执行 CMD、PowerShell/WMI 或 WFP；没有自动导入 Mihomo 覆写，没有真实公网节点请求。

## 交付结论

W1 收束后，可交付 **只读 Windows 环境诊断 starter**；它不是完成了强制保护的产品。用户可普通双击第一入口收集最小报告，当前不需要购买固定节点、登录 Claude或管理员权限。最终修复复核与结论追加于下。

## 最终修复复核

W1 已收束。`internal/diagnostics/platform_windows.go:39`–`:68` 已删除全部环境候选路径扫描与 `os.Stat`，只执行固定本地 CIM 查询；USERPROFILE / UserHomeDir 的值仅作字符串脱敏前缀，不访问这些目录或程序文件。复核未发现 diagnostics 产品代码中残留的 Stat/Lstat/Open/ReadFile/ReadDir/Walk 调用，也不再读取 LOCALAPPDATA/ProgramFiles 进行发现。

`diagnostics.go:74` 将发现范围标记为 `limited_running_processes`；`:145` 拒绝任何非运行进程候选。新增报告层回归测试包含 UNC 与本地文件候选，确保不会冒充运行进程。README 和 `START-HERE-zh-CN.txt` 已明确不扫描安装目录、未发现不代表未安装，并说明无需为诊断开启或登录 Claude。

修复后独立重跑 diagnostics 与 doctor 的定向测试全部通过，包括 `TestReportUsesOnlyRunningProcessEvidence`。新增 `platform_windows_test.go` 的原生回归已读过源码，但本轮未在 Windows 执行，不能将它列为原生运行通过。Node 覆写测试和打包脚本语法检查沿用前述本轮已通过结果；修复未触及这两部分。

**最终结论：本次范围没有剩余的 Important/Critical 交付阻断问题，可交付只读 Windows / Mihomo Party starter。** 仅授权正常诊断和可选打开本机面板，不安装系统过滤、不自动导入覆写，也不证明任何客户端已受保护。Windows 实机行为、真实固定出口和整体强制保护能力仍未验收，不因 starter 可交付而改变。
