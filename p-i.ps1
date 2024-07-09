# Function to check if running as administrator
function Test-IsAdmin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Function to prompt for UAC if not running as administrator
function Prompt-UAC {
    if (-not (Test-IsAdmin)) {
        Start-Process powershell.exe "-File `"$PSCommandPath`"" -Verb RunAs
        exit
    }
}

Prompt-UAC

# Define error handling function
function Handle-Error {
    param(
        [string]$ErrorMessage
    )
    Add-Type -AssemblyName PresentationFramework
    [System.Windows.MessageBox]::Show($ErrorMessage, "Error", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Error)
    exit 1
}

# Set Wallpaper
try {
    $wallpaperUrl = "https://github.com/CRYPTXMNESIA/BirdOS/raw/main/w.png"
    $lockscreenUrl = "https://github.com/CRYPTXMNESIA/BirdOS/raw/main/l.png"
    $wallpaperPath = "$env:USERPROFILE\wallpaper.png"
    $lockscreenPath = "$env:USERPROFILE\lockscreen.png"

    Invoke-WebRequest -Uri $wallpaperUrl -OutFile $wallpaperPath -ErrorAction Stop
    Invoke-WebRequest -Uri $lockscreenUrl -OutFile $lockscreenPath -ErrorAction Stop

    $code = @"
[DllImport("user32.dll", CharSet = CharSet.Auto)]
public static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);
"@

    $type = Add-Type -MemberDefinition $code -Name "Win32" -Namespace "Wallpaper" -PassThru
    $type::SystemParametersInfo(0x0014, 0, $wallpaperPath, 0x0001)
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name Wallpaper -Value $wallpaperPath
    RUNDLL32.EXE user32.dll,UpdatePerUserSystemParameters

    # Set lock screen wallpaper using registry
    $regKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization'
    if (!(Test-Path -Path $regKey)) {
        New-Item -Path $regKey -Force
    }
    Set-ItemProperty -Path $regKey -Name LockScreenImage -Value $lockscreenPath -Force
} catch {
    Handle-Error "Failed to set wallpaper or lock screen wallpaper: $_"
}

# Disable sending samples to Microsoft in Windows Defender
try {
    Set-MpPreference -SubmitSamplesConsent 2 -ErrorAction Stop
} catch {
    Handle-Error "Failed to disable sending samples to Microsoft in Defender: $_"
}

# Set system to dark mode
try {
    New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name AppsUseLightTheme -PropertyType DWord -Value 0 -Force -ErrorAction Stop
    New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name SystemUsesLightTheme -PropertyType DWord -Value 0 -Force -ErrorAction Stop
} catch {
    Handle-Error "Failed to set system to dark mode: $_"
}

# Create and run batch script to fix Windows search
try {
    $batchScriptPath = "$env:temp\fix_search.bat"
    $batchScriptContent = @"
:: BatchGotAdmin
:-------------------------------------
REM  --> Check for permissions
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"

REM --> If error flag set, we do not have admin.
if '%errorlevel%' NEQ '0' (
    echo Requesting administrative privileges...
    goto UACPrompt
) else ( goto gotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    echo UAC.ShellExecute "%~s0", "", "", "runas", 1 >> "%temp%\getadmin.vbs"

    "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    if exist "%temp%\getadmin.vbs" ( del "%temp%\getadmin.vbs" )
    pushd "%CD%"
    CD /D "%~dp0"

reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Search /v BingSearchEnabled /t REG_DWORD /d 0 /f
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Search /v CortanaConsent /t REG_DWORD /d 0 /f
taskkill /f /im SearchUI.exe

exit
"@

    Set-Content -Path $batchScriptPath -Value $batchScriptContent -Force
    Start-Process -FilePath $batchScriptPath -Wait
    Remove-Item -Path $batchScriptPath -Force
} catch {
    Handle-Error "Failed to execute batch script to fix Windows search: $_"
}

# Notify completion
Add-Type -AssemblyName PresentationFramework
[System.Windows.MessageBox]::Show("BirdOS Post-Install was successful.", "Success", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)

exit
