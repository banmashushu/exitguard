; Per-user release installer. Run is offered only on the successful finish page.
; Silent install, failure, cancel and uninstall never launch the application.
Unicode true
ManifestDPIAware true
RequestExecutionLevel user
SetCompressor /SOLID lzma
Name "ExitGuard"
OutFile "${OUTPUT_FILE}"
InstallDir "$LOCALAPPDATA\Programs\ExitGuard"
InstallDirRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\com.exitguard.app" "InstallLocation"
BrandingText " "
VIProductVersion "0.2.1.0"
VIAddVersionKey /LANG=1033 "ProductName" "ExitGuard"
VIAddVersionKey /LANG=1033 "FileDescription" "ExitGuard per-user installer"
VIAddVersionKey /LANG=1033 "FileVersion" "0.2.1"
VIAddVersionKey /LANG=1033 "LegalCopyright" "ExitGuard"

!include "MUI2.nsh"
!include "x64.nsh"
!include "WinVer.nsh"
!define MUI_ICON "${PACKAGE_DIR}/ExitGuard.ico"
!define MUI_UNICON "${PACKAGE_DIR}/ExitGuard.ico"
!define MUI_ABORTWARNING
!define MUI_FINISHPAGE_RUN "$INSTDIR\ExitGuard.exe"
!define MUI_FINISHPAGE_RUN_TEXT "$(RunExitGuard)"
!define MUI_FINISHPAGE_RUN_FUNCTION LaunchExitGuard
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "SimpChinese"
!insertmacro MUI_LANGUAGE "English"

LangString RunExitGuard ${LANG_SIMPCHINESE} "启动 ExitGuard"
LangString RunExitGuard ${LANG_ENGLISH} "Launch ExitGuard"
LangString CoreComponent ${LANG_SIMPCHINESE} "ExitGuard（必需）"
LangString CoreComponent ${LANG_ENGLISH} "ExitGuard (required)"
LangString DesktopComponent ${LANG_SIMPCHINESE} "创建桌面快捷方式"
LangString DesktopComponent ${LANG_ENGLISH} "Create a desktop shortcut"
Var InstallSucceeded

; Export the same generated uninstaller for inspection during cross-builds.
!ifdef UNINSTALLER_EXPORT
  !uninstfinalize '"${PYTHON_EXE}" "${CAPTURE_SCRIPT}" "%1" "${UNINSTALLER_EXPORT}"' = 0
!endif

Function .onInit
  StrCpy $InstallSucceeded 0
  SetShellVarContext current
  ${IfNot} ${RunningX64}
    MessageBox MB_ICONSTOP "ExitGuard requires 64-bit x64 Windows."
    Abort
  ${EndIf}
  ${IfNot} ${AtLeastWin10}
    MessageBox MB_ICONSTOP "ExitGuard requires Windows 10 or later."
    Abort
  ${EndIf}
FunctionEnd

Function .onInstFailed
  StrCpy $InstallSucceeded 0
FunctionEnd

Function LaunchExitGuard
  IfSilent launch_done
  StrCmp $InstallSucceeded 1 0 launch_done
  SetOutPath "$INSTDIR"
  Exec '"$INSTDIR\ExitGuard.exe"'
  launch_done:
FunctionEnd

Section "$(CoreComponent)" SecCore
  SectionIn RO
  SetShellVarContext current
  SetOutPath "$INSTDIR"
  SetOverwrite try
  ClearErrors
  File "${PACKAGE_DIR}/ExitGuard.exe"
  File "${PACKAGE_DIR}/ExitGuard.ico"
  File "${PACKAGE_DIR}/README-zh-CN.txt"
  File "${PACKAGE_DIR}/THIRD-PARTY-NOTICES.txt"
  File "${PACKAGE_DIR}/SHA256SUMS.txt"
  IfErrors 0 +3
    MessageBox MB_ICONSTOP "Please close ExitGuard and retry the installation."
    Abort
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  CreateShortCut "$SMPROGRAMS\ExitGuard.lnk" "$INSTDIR\ExitGuard.exe" "" "$INSTDIR\ExitGuard.ico" 0
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\com.exitguard.app" "DisplayName" "ExitGuard"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\com.exitguard.app" "DisplayVersion" "0.2.1"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\com.exitguard.app" "DisplayIcon" '$\"$INSTDIR\ExitGuard.ico$\",0'
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\com.exitguard.app" "InstallLocation" "$INSTDIR"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\com.exitguard.app" "UninstallString" '$\"$INSTDIR\Uninstall.exe$\"'
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\com.exitguard.app" "QuietUninstallString" '$\"$INSTDIR\Uninstall.exe$\" /S'
  WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\com.exitguard.app" "NoModify" 1
  WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\com.exitguard.app" "NoRepair" 1
  IfErrors 0 +3
    MessageBox MB_ICONSTOP "Could not finish installing ExitGuard. Please retry."
    Abort
SectionEnd

; Default selected. If omitted during an upgrade, leave existing shortcuts alone.
Section "$(DesktopComponent)" SecDesktop
  SetShellVarContext current
  ClearErrors
  CreateShortCut "$DESKTOP\ExitGuard.lnk" "$INSTDIR\ExitGuard.exe" "" "$INSTDIR\ExitGuard.ico" 0
  IfErrors 0 +3
    MessageBox MB_ICONSTOP "Could not create the desktop shortcut. Please retry."
    Abort
SectionEnd

Section "-Finalize"
  StrCpy $InstallSucceeded 1
SectionEnd

Section "Uninstall"
  SetShellVarContext current
  ClearErrors
  Delete "$INSTDIR\ExitGuard.exe"
  IfErrors 0 +3
    MessageBox MB_ICONSTOP "Please close ExitGuard and retry the uninstall."
    Abort
  Delete "$INSTDIR\README-zh-CN.txt"
  Delete "$INSTDIR\ExitGuard.ico"
  Delete "$INSTDIR\THIRD-PARTY-NOTICES.txt"
  Delete "$INSTDIR\SHA256SUMS.txt"
  Delete "$SMPROGRAMS\ExitGuard.lnk"
  Delete "$DESKTOP\ExitGuard.lnk"
  DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\com.exitguard.app"
  Delete "$INSTDIR\Uninstall.exe"
  RMDir "$INSTDIR"
SectionEnd
