@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"
set "REPORT=%~dp0ExitGuard-environment-%RANDOM%-%RANDOM%.json"
echo ExitGuard 环境检查（只读；普通双击即可）
echo 不需要固定代理、Claude 登录或管理员权限。
echo 正在检查，请稍候……
"%~dp0ExitGuard.exe" doctor --output "%REPORT%"
if errorlevel 1 (
  echo 检查未完成。请解压到可写文件夹后重试，并保留窗口中的错误提示。
  pause
  exit /b 1
)
echo.
echo 报告已保存到："%REPORT%"
echo 请先查看此 JSON 文件；需要协助时只分享这个报告。
echo 这份报告不判断保护是否启用，也不证明端口属于哪个服务。
pause
endlocal
