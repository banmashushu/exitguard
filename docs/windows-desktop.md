# Windows 原生桌面交付

主程序来自 `cmd/exitguard-desktop`，使用 MyGo 的 `WindowOptions.Content` 原生控件。旧 `cmd/exitguard` 仍是单独的 CLI，不能把它的子命令传给桌面主程序。普通固定出口代理与受控浏览器启动不证明系统级防绕行；Windows 实机验收仍待完成。

Windows v0.2.1 修复安装向导选项和品牌图标。Mac 已发布应用和压缩包保持 v0.2.0，本次不重建或替换。

## 构建

固定 Go 1.27.3、MyGo v0.7.3、NSIS 3.13，`CGO_ENABLED=0`。默认复用项目 `.work/mygo-preflight` 内的 MyGo / NSIS 和本机已有的 Go 工具链，不安装全局软件、不改写 Go 全局环境。其他机器可分别设置 `EXITGUARD_GO`、`EXITGUARD_MYGO`、`EXITGUARD_MAKENSIS`、`NSISDIR` 指向相同版本。

```sh
sh scripts/package-windows-desktop.sh
```

产物：

- `dist/ExitGuard-Windows-x64.zip`
- `dist/ExitGuard-Windows-x64-Setup.exe`
- `dist/ExitGuard-Windows-x64-SHA256SUMS.txt`

可用 `EXITGUARD_OUTPUT_DIR` 指定输出位置。只构建 MyGo 应用且不交付时：

```sh
sh scripts/build-desktop.sh windows/amd64 .work/mygo-windows-build
```

MyGo 在发现 `makensis` 时会自动生成默认安装器。最终交付流程只从其暂存结果复制 `ExitGuard.exe`，无损提取它的品牌图标为 `ExitGuard.ico`，再用 `platform/windows/desktop/installer.nsi` 编译项目安装器：按当前用户安装、检查 Windows 10+ 与 64 位系统，没有开机启动和自动更新。

组件页的“创建桌面快捷方式”默认选中，可取消；升级时取消此选项只是不创建或更新桌面快捷方式，保留已有快捷方式，不进行安装阶段的桌面删除。完成页的“启动 ExitGuard”默认选中，只有成功安装后勾选并点击“完成”才运行。静默安装、失败、取消和卸载均不会启动。卸载删除命名的发行文件、开始菜单与桌面上的 `ExitGuard.lnk` 以及当前用户的卸载注册项，保留 `%APPDATA%\ExitGuard` 和安装目录中的其他文件。

## 内容与验证

便携包和安装包的应用载荷都只包括 `ExitGuard.exe`、`ExitGuard.ico`、中文使用说明、第三方许可和文件校验值。不会复制用户目录、配置、凭据、源码、旧安装产物或任意资源目录。Sandboxie、CLI、NativeProbe 与原生预览脚本不包含在本次 GUI 发行包内。第三方许可由固定版本源码中的许可原文汇集；升级依赖时应同步更新。

打包先在独立临时目录完成，构建或检查失败不发布新产物。检查器验证便携包的精确文件列表、常规文件、CRC、SHA-256、AMD64 GUI 主程序、版本、Windows 10 / DPI 清单、无提权请求和无静态 WebView 导入。还检查图标组的每个引用、图像大小与 PNG CRC，以及程序、安装器、卸载器与便携 ICO 的品牌图像一致性，包含 16/24/32/48/64/128/256 像素尺寸。卸载器通过 NSIS 编译时导出检查，构建时不会执行它。MyGo 自身的主程序清单不包含 `requestedExecutionLevel`，沿用调用者令牌；项目 NSIS 安装器明确使用 `asInvoker`。安装器的 NSIS 启动桩是 x86 GUI，应用载荷为 x64。

`assets/app-icon.ico` 是同一品牌 PNG 经 MyGo 官方尺寸转换后，从主程序图标资源无损封装的标准 ICO。无需重绘，复现方式：

```sh
python3 scripts/extract-windows-icon.py MYGO_BUILT.exe assets/app-icon.ico
```

重新检查现有产物：

```sh
python3 scripts/verify-windows-desktop.py dist/ExitGuard-Windows-x64.zip dist/ExitGuard-Windows-x64-Setup.exe
```

可在第三个参数传入编译时导出的 `Uninstall.exe`，额外重查它的图标与清单。打包时始终检查导出的卸载器；设置 `EXITGUARD_WINDOWS_VALIDATION_DIR` 可保留该文件用于复核，它不会加入便携包或作为独立卸载器发布。

此版本没有 Windows 数字签名，也没有包含 WebView2 安装程序。交叉构建和静态检查不等于运行验收；Windows GUI、安装 / 卸载、账户 ACL、MSIX / 注册表发现以及真实代理和客户端流量仍需真实 Windows 主机验证。
