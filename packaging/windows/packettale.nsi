Unicode true
!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "x64.nsh"
!include "FileFunc.nsh"
!include "nsDialogs.nsh"

Var PurgeData
Var PurgeCheckbox
Var InstallLog
Var InstallLogHandle
Var ExistingInstall
!addplugindir "${__FILEDIR__}/service-plugin"

; Build with -DINPUT=<payload-root> -DOUTPUT=<exe-path> -DVERSION=<version>.
!define ICON "${__FILEDIR__}/../../assets/data/icons/packettale.ico"

Name "PacketTale"
OutFile "${OUTPUT}"
InstallDir "$PROGRAMFILES64\packettale"
RequestExecutionLevel admin
ShowInstDetails show
ShowUninstDetails show
VIProductVersion "${VERSION}.0"
VIAddVersionKey "LegalCopyright" "GPLv3 contributors"
VIAddVersionKey "ProductName" "PacketTale"
VIAddVersionKey "FileDescription" "PacketTale endpoint installer"
VIAddVersionKey "FileVersion" "${VERSION}.0"

!define MUI_ICON "${ICON}"
!define MUI_UNICON "${ICON}"
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "${__FILEDIR__}/../../LICENSE"
!define MUI_PAGE_CUSTOMFUNCTION_PRE DirectoryPagePre
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
UninstPage custom un.DataOptions un.DataOptionsLeave
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

!macro InstallDiagnostic MESSAGE
  FileOpen $InstallLogHandle "$InstallLog" a
  FileSeek $InstallLogHandle 0 END
  FileWrite $InstallLogHandle "${MESSAGE}$\r$\n"
  FileClose $InstallLogHandle
  ClearErrors
!macroend

Function .onInit
  StrCpy $InstallLog "$EXEDIR\installation.log"
  !insertmacro InstallDiagnostic "Installer initialization"
  ${IfNot} ${IsNativeAMD64}
    !insertmacro InstallDiagnostic "Unsupported Windows architecture"
    SetErrorLevel 1
    MessageBox MB_ICONSTOP|MB_OK "This installer requires an x64 version of Windows." /SD IDOK
    Abort
  ${EndIf}
  SetRegView 64
  StrCpy $ExistingInstall 0
  ReadRegStr $0 HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\packettale" "UninstallString"
  ${If} $0 != ""
    ReadRegStr $1 HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\packettale" "DisplayName"
    ${If} $1 != "packettale"
      !insertmacro InstallDiagnostic "Unrecognized installation registration"
      SetErrorLevel 1
      Abort
    ${EndIf}
    StrCpy $1 $0 1
    ${If} $1 != '"'
      !insertmacro InstallDiagnostic "Invalid registration quote prefix"
      SetErrorLevel 1
      Abort
    ${EndIf}
    StrCpy $1 $0 1 -1
    ${If} $1 != '"'
      !insertmacro InstallDiagnostic "Invalid uninstall path quoting"
      SetErrorLevel 1
      Abort
    ${EndIf}
    StrLen $2 $0
    IntOp $2 $2 - 2
    StrCpy $0 $0 $2 1
    ${GetFileName} "$0" $1
    ${If} $1 != "uninstall.exe"
      !insertmacro InstallDiagnostic "Invalid registered uninstaller name"
      SetErrorLevel 1
      Abort
    ${EndIf}
    ${GetParent} "$0" $INSTDIR
    StrCpy $ExistingInstall 1
  ${EndIf}
  ReadEnvStr $R0 "ProgramData"
  IfFileExists "$R0\packettale\management.json" enrollment_found
  IfFileExists "$EXEDIR\packettale-enrollment.json" enrollment_found
    MessageBox MB_ICONSTOP|MB_OK "Place packettale-enrollment.json beside this installer." /SD IDOK
    !insertmacro InstallDiagnostic "Missing enrollment file"
    SetErrorLevel 1
    Abort
  enrollment_found:
FunctionEnd

Function DirectoryPagePre
  ${If} $ExistingInstall == 1
    Abort
  ${EndIf}
FunctionEnd

Section "packettale" InstallSection
  ReadEnvStr $R0 "ProgramData"
  ${If} $R0 == ""
    SetErrorLevel 1
    MessageBox MB_ICONSTOP|MB_OK "Windows ProgramData directory was not found." /SD IDOK
    Abort
  ${EndIf}
  ; Stop only this installation before replacing any payload. The same helper
  ; verifies service paths, terminates owned processes and unloads its own driver.
  SimpleSC::ExistsService "packettale-core"
  Pop $0
  ${If} $0 == 0
    ${If} $ExistingInstall != 1
      SetErrorLevel 1
      MessageBox MB_ICONSTOP|MB_OK "The existing PacketTale installation could not be verified. Repair it or contact your administrator." /SD IDOK
      Abort
    ${EndIf}
    !insertmacro InstallDiagnostic "Updating existing installation: $INSTDIR"
    InitPluginsDir
    SetOutPath "$PLUGINSDIR"
    File /oname=stop-agent.ps1 "${__FILEDIR__}/stop-agent.ps1"
    ; The NSIS System.dll is native, not the framework assembly used by Add-Type.
    ; Do not let PowerShell's compiler resolve assemblies from the plugin folder.
    SetOutPath "$WINDIR"
    nsExec::ExecToStack '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$PLUGINSDIR\stop-agent.ps1" -InstallDirectory "$INSTDIR"'
    Pop $0
    Pop $1
    !insertmacro InstallDiagnostic "$1"
    !insertmacro InstallDiagnostic "Stop result: $0"
    ${If} $0 != 0
      SetErrorLevel $0
      MessageBox MB_ICONSTOP|MB_OK "Could not stop the agent. Restart Windows and run this installer again." /SD IDOK
      Abort
    ${EndIf}
  ${EndIf}
  ClearErrors
  !insertmacro InstallDiagnostic "Copy endpoint payload"
  SetOutPath "$INSTDIR"
  File "${INPUT}/windows_amd64/packettale-core.exe"
  File "${INPUT}/windows_amd64/packettale-core.dll"
  File "${INPUT}/windows_amd64/packettale-kext.sys"
  File /oname=LICENSE.txt "${__FILEDIR__}/../../LICENSE"
  File /oname=purge-data.ps1 "${__FILEDIR__}/purge-data.ps1"
  WriteUninstaller "$INSTDIR\uninstall.exe"
  ${If} ${Errors}
    SetErrorLevel 3010
    MessageBox MB_ICONSTOP|MB_OK "Windows has locked an agent file. Restart Windows and run this installer again." /SD IDOK
    Abort
  ${EndIf}

  SetOutPath "$R0\packettale"
  IfFileExists "$R0\packettale\management.json" EnrollmentConfigPresent
    CopyFiles /SILENT "$EXEDIR\packettale-enrollment.json" "$R0\packettale\management.json"
    IfErrors 0 +4
      SetErrorLevel 1
      MessageBox MB_ICONSTOP|MB_OK "Could not copy the enrollment file." /SD IDOK
      Abort
    ExecWait '"$SYSDIR\icacls.exe" "$R0\packettale\management.json" /inheritance:r /grant:r "*S-1-5-18:F" "*S-1-5-32-544:F"' $0
    ${If} $0 != 0
    SetErrorLevel 1
      MessageBox MB_ICONSTOP|MB_OK "Could not protect the enrollment file. Installation stopped." /SD IDOK
      Abort
    ${EndIf}
  EnrollmentConfigPresent:

  SetOutPath "$R0\packettale\intel"
  File "${INPUT}/intel/index.json"
  File "${INPUT}/intel/base.dsdl"
  File "${INPUT}/intel/geoipv4.mmdb"
  File "${INPUT}/intel/geoipv6.mmdb"
  File "${INPUT}/intel/index.dsd"
  File "${INPUT}/intel/intermediate.dsdl"
  File "${INPUT}/intel/urgent.dsdl"
  File "${INPUT}/intel/main-intel.yaml"
  File "${INPUT}/intel/notifications.yaml"
  File "${INPUT}/intel/news.yaml"

  !insertmacro InstallDiagnostic "Install firewall service"
  SimpleSC::ExistsService "packettale-core"
  Pop $0
  ${If} $0 == 0
    SimpleSC::SetServiceStartType "packettale-core" 2
  ${Else}
  SimpleSC::InstallService "packettale-core" "packettale Core" 16 2 '"$INSTDIR\packettale-core.exe" --log-dir=%PROGRAMDATA%\packettale\logs' "" "" ""
  ${EndIf}
  Pop $0
  ${If} $0 != 0
    SetErrorLevel 1
    MessageBox MB_ICONSTOP|MB_OK "Could not install the PacketTale service (error $0)." /SD IDOK
    Abort
  ${EndIf}
  SimpleSC::SetServiceDescription "packettale-core" "packettale Core Service"
  WriteRegStr HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\packettale" "DisplayName" "packettale"
  WriteRegStr HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\packettale" "DisplayIcon" '"$INSTDIR\packettale-core.exe",0'
  WriteRegStr HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\packettale" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\packettale" "DisplayVersion" "${VERSION}"
  WriteRegDWORD HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\packettale" "NoModify" 1
  WriteRegDWORD HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\packettale" "NoRepair" 1
  !insertmacro InstallDiagnostic "Start firewall service"
  SimpleSC::StartService "packettale-core" "" 180
  Pop $0
  ${If} $0 != 0
    SetErrorLevel 1
    MessageBox MB_ICONSTOP|MB_OK "The PacketTale service did not start (error $0)." /SD IDOK
    Abort
  ${EndIf}

  !insertmacro InstallDiagnostic "Installation completed"
SectionEnd

Function un.onInit
  SetRegView 64
  StrCpy $PurgeData 0
  ${GetParameters} $0
  ClearErrors
  ${GetOptions} $0 "/PURGE" $1
  ${IfNot} ${Errors}
    ${If} $1 != ""
      SetErrorLevel 2
      MessageBox MB_ICONSTOP|MB_OK "Use /PURGE without a value to request local data deletion." /SD IDOK
      Abort
    ${EndIf}
    StrCpy $PurgeData 1
  ${EndIf}
FunctionEnd

Function un.DataOptions
  !insertmacro MUI_HEADER_TEXT "Local data" "Choose whether to retain history and enrollment data."
  nsDialogs::Create 1018
  Pop $0
  ${If} $0 == error
    Abort
  ${EndIf}
  ${NSD_CreateCheckbox} 0 12u 100% 30u "Delete all local data, including history and enrollment"
  Pop $PurgeCheckbox
  ${If} $PurgeData == 1
    ${NSD_Check} $PurgeCheckbox
  ${EndIf}
  nsDialogs::Show
FunctionEnd

Function un.DataOptionsLeave
  ${NSD_GetState} $PurgeCheckbox $PurgeData
FunctionEnd

; Return 0 only after the owned payload is absent. Do not queue reboot deletion.
Function un.RemovePayload
  Exch $R3
  Push $R0
  StrCpy $R0 0
  payload_delete_retry:
    Delete "$INSTDIR\$R3"
    IfFileExists "$INSTDIR\$R3" 0 payload_delete_done
    ${If} $R0 >= 30
      StrCpy $R3 1
      Goto payload_delete_return
    ${EndIf}
    Sleep 1000
    IntOp $R0 $R0 + 1
    Goto payload_delete_retry
  payload_delete_done:
    StrCpy $R3 0
  payload_delete_return:
    Pop $R0
    Exch $R3
FunctionEnd

!macro RemoveOwnedPayload Filename
  Push "${Filename}"
  Call un.RemovePayload
  Pop $0
  ${If} $0 != 0
    SetErrorLevel 3010
    SetRebootFlag true
    MessageBox MB_ICONSTOP|MB_OK "Windows has not released ${Filename}. Reboot Windows and run this uninstaller again. Local data and removal files were retained." /SD IDOK
    Abort
  ${EndIf}
!macroend

Section "Uninstall"
  ; Cleanup is embedded so binary updates cannot remove it.
  InitPluginsDir
  SetOutPath "$PLUGINSDIR"
  File /oname=stop-agent.ps1 "${__FILEDIR__}/stop-agent.ps1"
  SetOutPath "$WINDIR"
  DetailPrint "Stopping PacketTale services and unloading the driver..."
  nsExec::ExecToLog '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$PLUGINSDIR\stop-agent.ps1" -InstallDirectory "$INSTDIR"'
  Pop $0
  ${If} $0 != 0
    SetErrorLevel 1
    ${If} $0 == 3010
      SetErrorLevel 3010
      SetRebootFlag true
    ${EndIf}
    MessageBox MB_ICONSTOP|MB_OK "Agent cleanup did not complete. See the removal details. If Windows has not released a process or driver, reboot and run this uninstaller again. No application files or local data were removed." /SD IDOK
    Abort
  ${EndIf}
  !insertmacro RemoveOwnedPayload "packettale-core.exe"
  SimpleSC::RemoveService "packettale-core"
  Pop $0
  ${If} $0 != 0
  ${AndIf} $0 != 1060
    SetErrorLevel 1
    MessageBox MB_ICONSTOP|MB_OK "The firewall service registration could not be removed (error $0)." /SD IDOK
    Abort
  ${EndIf}
  ; Check owned runtime files before touching data or the removal registration.
  !insertmacro RemoveOwnedPayload "packettale-core.dll"
  !insertmacro RemoveOwnedPayload "packettale-kext.sys"
  !insertmacro RemoveOwnedPayload "LICENSE.txt"
  SetShellVarContext all
  ${If} $PurgeData == 1
    IfFileExists "$INSTDIR\purge-data.ps1" purge_helper_ready
    ; A previous cleanup can have removed the helper after all data was purged.
    IfFileExists "$APPDATA\packettale\." purge_helper_missing
    IfFileExists "$INSTDIR\index.json" purge_helper_missing
    IfFileExists "$INSTDIR\upgrade_obsolete_binaries\." purge_helper_missing
    Goto purge_data_done
    purge_helper_missing:
      SetErrorLevel 1
      MessageBox MB_ICONSTOP|MB_OK "Local data deletion is unavailable. Repair the installation before trying again." /SD IDOK
      Abort
    purge_helper_ready:
      ExecWait '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\purge-data.ps1" -ConfirmPurge -RemoveReleaseCache' $0
      ${If} $0 != 0
        SetErrorLevel 1
        MessageBox MB_ICONSTOP|MB_OK "Local data could not be completely removed. See the removal details and retry after rebooting if files remain locked. Remaining data and uninstall files were retained." /SD IDOK
        Abort
      ${EndIf}
    purge_data_done:
  ${EndIf}
  ClearErrors
  Delete "$INSTDIR\purge-data.ps1"
  Delete "$INSTDIR\uninstall.exe"
  ${If} ${Errors}
    SetErrorLevel 3010
    SetRebootFlag true
    MessageBox MB_ICONSTOP|MB_OK "Windows has not released the removal files. Reboot Windows and run this uninstaller again." /SD IDOK
    Abort
  ${EndIf}
  DeleteRegKey HKLM "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\packettale"
  RMDir "$INSTDIR"
  ; Default removal retains local data; /PURGE or the explicit checkbox removes it.
SectionEnd
