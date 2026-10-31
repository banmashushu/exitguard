# Release 构建

v0.2.1 统一提供 Mac Apple 芯片版和 Windows x64 版。Mac 最低 macOS 13，应用为 ad-hoc 签名、未经过 Apple 公证；Windows 未签名。打包不安装应用、修改系统网络或读取用户配置与账号。

先将发布源码合入 `main`，保持工作区干净（本地 `.idea` 可保留），记录完整提交 SHA。使用 Go 1.27.3、MyGo v0.7.3、NSIS 3.13 和 macOS 自带的 `hdiutil`：

```sh
EXITGUARD_RELEASE_COMMIT=完整main提交SHA sh scripts/package-release.sh
```

脚本只读核对当前提交等于本地 `main` 和指定 SHA，不执行 Git 提交、合并、推送或打标签。产物暂存在 `.work/release-v0.2.1/`，由发布者确认后上传：

- `ExitGuard-macOS-arm64.dmg`
- `ExitGuard-macOS-arm64.zip`
- `ExitGuard-Windows-x64-Setup.exe`
- `ExitGuard-Windows-x64.zip`
- `SHA256SUMS.txt`

DMG 的安装内容仅为 `ExitGuard.app` 和指向 `/Applications` 的 `Applications` 快捷链接。脚本用 `hdiutil` 创建并验证镜像，只读挂载到自己的临时目录核对内容、应用版本、签名及 ZIP 一致性，然后卸载；不启动应用或使用 Finder/AppleScript。

二进制包内的 `THIRD-PARTY-NOTICES.txt` 先列 ExitGuard 自有代码的 MIT 许可原文（Copyright 2026 banmashushu），再保留全部第三方许可。公开包不包含源码、用户配置、凭据或代理资料库。Windows 包保持桌面快捷方式和完成页运行选项，只有成功安装后勾选并点完成才运行；静默安装、失败、取消和卸载不运行。

`logs/` 保存两平台构建、DMG 验证、卸载器静态检查及资产元数据，不作为 Release 下载附件。失败的临时构建目录会保留用于诊断；成功后只保留一个对应版本的发布目录，不上传、不自动发布。Windows 实机安装及系统级防绕行仍需单独验收。
