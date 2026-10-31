@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"
echo ExitGuard Windows 原生预览；尚未完成实机验收。
"%~dp0ExitGuard.exe" native-apply --plan "%~dp0ExitGuard-native-plan.json"
if errorlevel 1 echo 本步骤未完成。请保留以上原因；不会自动改用普通启动。
pause
endlocal
