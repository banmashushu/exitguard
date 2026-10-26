@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"
echo 正在打开 ExitGuard 控制面板；请保留此窗口运行。
echo 本步骤不安装或移除系统过滤，也不会自动启用保护。
echo 就绪输出含本次会话凭证，已隐藏；不要分享面板地址。
"%~dp0ExitGuard.exe" serve >nul
if errorlevel 1 (
  echo 面板未能启动。若已有 ExitGuard 在运行，请使用原来的窗口。
  pause
  exit /b 1
)
endlocal
