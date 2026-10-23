# ExitGuard 原生进程过滤：构建与部署

当前交付是可编译的原生过滤实现及部署候选源码。当前机器没有可用的 Apple 开发签名，过滤器没有安装或激活，普通本地构建始终不能产生有效保护证明。没有变更飞连、公司凭证、系统代理、DNS、默认路由或其他过滤产品。

## 覆盖与严格行为

macOS 使用公开 Network Extension `NEFilterDataProvider`，不是 TUN 或 TLS 解密代理。它对来自内核的完整应用/进程审计 token 解析真实可执行路径与有效签名 identifier，防止仅按 PID 查询时发生复用。选中的程序只可主动建立 TCP/IPv4 到 `127.0.0.1:guardPort` 的连接；其他目的、端口、UDP/QUIC、原始 socket 和 IPv6 都拒绝。选中程序的入站连接也拒绝，防止利用入站连接发送直连响应。已知且不匹配目标的应用流量放行。

严格模式无法安全归属的 socket 会逐条拒绝，并使扩展健康证明失效。**这可能影响少量不能归属的非目标应用流量。** 系统过滤部署前必须理解并测试这项边界。含 `bundleIDs` 的策略还要求有效且完整的动态签名身份；签名失败或 identifier 缺失不会被当作安全的非目标。当前机器的混合进程签名环境不能证明 bundle-ID 策略完整覆盖，因此建议先配置明确的可执行文件和辅助程序路径，并完成实测。

一个路径会影响该可执行文件的所有实例，浏览器的独立资料目录不会改变这一事实。必须列出需要保护的辅助进程；主程序路径不是整个应用全部进程的证明。系统服务代发 DNS 与运行中更新引入新 helper 的完整覆盖机制尚未实现，不能仅归为缺少测试；扩展进程崩溃和系统重启行为也未完成实机验收。此版本不承诺恶意本机管理员无法移除规则或其他本机程序无法冒用回环监听端口。

过滤器首次部署或更换策略前先退出全部目标程序及 helper；安装前后管理器都会只读检查进程。管理器还核对运行扩展的启动时刻，拒绝把早于该扩展运行的目标进程和既有连接认作受保护会话。不自动关闭、终止或复用普通浏览器。进程路径/身份不能安全读取时拒绝就绪；不会跳过疑似目标。

## 只构建，不激活

在项目根目录执行：

```sh
platform/macos/filter-build.sh dist/native-macos
```

脚本编译 macOS 13+ 的 provider、管理器、策略测试及只读进程测试，输出未签名的 `.systemextension` 和管理器。当前 CPU 的测试实际执行；设置 `EXITGUARD_FILTER_ARCH=x86_64` 只做对应架构交叉编译时不声称运行过测试。脚本不会安装、签名或激活系统组件。SDK 对 `filterBrowsers=false` 的显式设置/检查会报告 macOS 弃用警告；macOS 不支持此浏览器过滤选项，实际使用 `filterSockets=true`。

## 签名部署条件

需要 Apple Developer 团队、有 Network Extension 能力的 Developer ID Application 签名、匹配的容器应用和过滤扩展 provisioning profiles、系统扩展安装 entitlement，以及公司允许的部署和真实设备测试。ad-hoc 签名不提供该能力。本机当前没有这些身份，因此不能部署。

容器 identifier 固定为 `com.exitguard.app`；过滤扩展为 `com.exitguard.Filter`。管理器与容器使用同一签名 identifier，以保持 Network Extension 配置拥有者和容器身份一致。管理器的固定可信路径为：

```text
/Applications/ExitGuard.app/Contents/MacOS/ExitGuardFilterManager
```

源码附带 `filter-sign.sh`，仅准备签名构建，不复制到 `/Applications`、不激活过滤器。先用主应用构建脚本生成 `dist/ExitGuard.app`，再提供真实签名资料：

```sh
export EXITGUARD_SIGN_IDENTITY='Developer ID Application: YOUR LEGAL NAME (YOURTEAMID)'
export EXITGUARD_SIGN_TEAM='YOURTEAMID'
export EXITGUARD_APP_PROFILE='/absolute/path/app.provisionprofile'
export EXITGUARD_FILTER_PROFILE='/absolute/path/filter.provisionprofile'
platform/macos/filter-sign.sh dist/ExitGuard.app
```

示例中的身份和 TEAM ID 必须替换为真实值。该脚本重建 core 并把团队 ID 固定在二进制中、嵌入 profiles、设置 Mach 服务名，并从内到外签名；不接受环境变量在运行时替换可信团队。脚本和 entitlements 尚未在真实开发者身份下验证，分发还需 Apple 公证及 profile/entitlement 验收。

只有后续明确部署时，才把该签名 `.app` 安装到 `/Applications/ExitGuard.app`，然后在退出目标应用后执行 `filter-install --config PATH`。OSSystemExtensionManager/系统设置可能要求系统批准。安装前管理器会输出严格过滤影响说明。不得在办公连接中直接做断开飞连等破坏性测试。

## 证明和移除

`inspect --config PATH` 先验证固定管理器路径的 Apple 证书、identifier 与构建固定团队。管理器从 `NEFilterManager.loadFromPreferences` 读取真实启用配置，检查 sockets、strict-build 和完整策略哈希；再通过双向签名约束的只读 XPC 请求随机 nonce、运行扩展策略哈希、健康状态和启动时刻。文件回执或客户端上报的 active 字段不能替代这些检查。

Go 普通构建没有固定团队 ID，会在启动外部管理器前返回 inactive；当前未签名管理器自身也明确拒绝 ad-hoc 身份。`filter-remove --config PATH` 只移除 identifier 为本产品的调用者 NE 配置，不操作飞连配置。系统扩展二进制可能仍保留在 OS 扩展列表；禁用/卸载应使用系统提供的产品授权流程，不能手工重置全部系统过滤。

## Windows 实现与验证边界

`internal/enforce` 的 Windows x64 实现直接调用 WFP。使用产品唯一 sublayer GUID、稳定 filter GUID 和 OS 内元数据标记，安装与移除均在事务中进行。对象为 **providerless persistent**，避免官方文档对“无 service 的 provider 是否启用”的冲突说法；Microsoft 明确列出未关联 provider 的 persistent 对象会在 BFE 启动时加载，不需要新增 SCM 服务或让 SYSTEM 执行用户目录中的程序。

每个目标 exe 有六类 BLOCK：IPv4 非 `127.0.0.1`、非 guard 端口、非 TCP 各一条；所有 IPv6；IPv4/IPv6 入站。允许集合是三项同时成立，阻断集合是它们的补集，没有“阻全部再用 allow 覆盖”的错误优先级。IPv4 数值按 WFP 要求以 host-order `0x7f000001` 表达。安装前要求目标 exe/helper 已退出。

Inspect 从 BFE 枚举实际产品 sublayer 中的完整规则集合，重算 OS 元数据对应的稳定 GUID，并 GetByKey 核对持久/非禁用 flags、provider 为空、层、sublayer、action、权重、App ID blob、地址、端口、协议与 policy hash。缺项、陌生关联、额外 permit 或篡改均不就绪。移除也要求产品标记和稳定键可确认，不执行全局防火墙重置。

当前只完成 Windows x64 交叉构建与规则规划测试；Windows ABI 测试可构建但未在本机执行。BFE 停止/重启、系统启动到 BFE 加载前的窗口、实际回环/IPv6/UDP/DNS、helper 覆盖和客户端真实连接均未在 Windows 验收。WFP ALE 策略变更会触发现有 flow 重新授权，但不能把此文档语义替代设备断流测试。其他 Windows 架构返回 unsupported。

## 官方依据

- [Apple Network Extension 部署条件](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment)
- [Apple Network Extension entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.networkextension)
- [Apple NEFilterDataProvider](https://developer.apple.com/documentation/networkextension/nefilterdataprovider)
- [Microsoft WFP 对象持久性](https://learn.microsoft.com/en-us/windows/win32/fwp/object-management)
- [Microsoft FwpmProviderAdd0 启动规则](https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmprovideradd0)
- [Microsoft ALE 重新授权](https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization)
- [Microsoft 官方 SDK ABI 定义](https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/shared/fwpmtypes.h)
