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

# Define error logging function
function Log-Error {
    param(
        [string]$ErrorMessage
    )
    Add-Content -Path "$env:temp\BirdOS_PostInstall_Errors.log" -Value $ErrorMessage
}

# Reset Windows Search functions from the Microsoft script
function T-R {
    Param([String] $n)
    $o = Get-Item -LiteralPath $n -ErrorAction SilentlyContinue
    return ($o -ne $null)
}

function R-R {
    Param([String] $l)
    $m = T-R $l
    if ($m) {
        Remove-Item -Path $l -Recurse -ErrorAction SilentlyContinue
    }
}

function S-D {
    R-R "HKLM:\SOFTWARE\Microsoft\Cortana\Testability"
    R-R "HKLM:\SOFTWARE\Microsoft\Search\Testability"
}

function K-P {
    Param([String] $g)
    $h = Get-Process $g -ErrorAction SilentlyContinue
    $i = $(get-date).AddSeconds(2)
    $k = $(get-date)

    while ((($i - $k) -gt 0) -and $h) {
        $k = $(get-date)
        $h = Get-Process $g -ErrorAction SilentlyContinue
        if ($h) {
            $h.CloseMainWindow() | Out-Null
            Stop-Process -Id $h.Id -Force
        }
        $h = Get-Process $g -ErrorAction SilentlyContinue
    }
}

function D-FF {
    Param([string[]] $e)
    foreach ($f in $e) {
        if (Test-Path -Path $f) {
            Remove-Item -Recurse -Force $f -ErrorAction SilentlyContinue
        }
    }
}

function D-W {
    $d = @(
        "$Env:localappdata\Packages\Microsoft.Cortana_8wekyb3d8bbwe\AC\AppCache",
        "$Env:localappdata\Packages\Microsoft.Cortana_8wekyb3d8bbwe\AC\INetCache",
        "$Env:localappdata\Packages\Microsoft.Cortana_8wekyb3d8bbwe\AC\INetCookies",
        "$Env:localappdata\Packages\Microsoft.Cortana_8wekyb3d8bbwe\AC\INetHistory",
        "$Env:localappdata\Packages\Microsoft.Windows.Cortana_cw5n1h2txyewy\AC\AppCache",
        "$Env:localappdata\Packages\Microsoft.Windows.Cortana_cw5n1h2txyewy\AC\INetCache",
        "$Env:localappdata\Packages\Microsoft.Windows.Cortana_cw5n1h2txyewy\AC\INetCookies",
        "$Env:localappdata\Packages\Microsoft.Windows.Cortana_cw5n1h2txyewy\AC\INetHistory",
        "$Env:localappdata\Packages\Microsoft.Search_8wekyb3d8bbwe\AC\AppCache",
        "$Env:localappdata\Packages\Microsoft.Search_8wekyb3d8bbwe\AC\INetCache",
        "$Env:localappdata\Packages\Microsoft.Search_8wekyb3d8bbwe\AC\INetCookies",
        "$Env:localappdata\Packages\Microsoft.Search_8wekyb3d8bbwe\AC\INetHistory",
        "$Env:localappdata\Packages\Microsoft.Windows.Search_cw5n1h2txyewy\AC\AppCache",
        "$Env:localappdata\Packages\Microsoft.Windows.Search_cw5n1h2txyewy\AC\INetCache",
        "$Env:localappdata\Packages\Microsoft.Windows.Search_cw5n1h2txyewy\AC\INetCookies",
        "$Env:localappdata\Packages\Microsoft.Windows.Search_cw5n1h2txyewy\AC\INetHistory"
    )
    D-FF $d
}

function R-L {
    Param([String] $c)
    K-P $c 2>&1 | Out-Null
    D-W
    K-P $c 2>&1 | Out-Null
    Start-Sleep -s 5
}

function Reset-WindowsSearch {
    Write-Output "Resetting Windows Search Box"
    S-D 2>&1 | Out-Null

    $a = "searchui"
    $b = "$Env:localappdata\Packages\Microsoft.Windows.Search_cw5n1h2txyewy"
    if (Test-Path -Path $b) {
        $a = "searchapp"
    }

    R-L $a
    Write-Output "Windows Search reset completed."
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
    Log-Error "Failed to set wallpaper or lock screen wallpaper: $_"
}

# Disable sending samples to Microsoft in Windows Defender
try {
    Set-MpPreference -SubmitSamplesConsent 2 -ErrorAction Stop
} catch {
    Log-Error "Failed to disable sending samples to Microsoft in Defender: $_"
}

# Set system to dark mode
try {
    New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name AppsUseLightTheme -PropertyType DWord -Value 0 -Force -ErrorAction Stop
    New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name SystemUsesLightTheme -PropertyType DWord -Value 0 -Force -ErrorAction Stop
} catch {
    Log-Error "Failed to set system to dark mode: $_"
}

# Reset Windows Search
try {
    Reset-WindowsSearch
} catch {
    Log-Error "Failed to reset Windows Search: $_"
}

# Add ctfmon.exe to startup
try {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name ctfmon -Value "C:\Windows\System32\ctfmon.exe" -Force -ErrorAction Stop
} catch {
    Log-Error "Failed to add ctfmon.exe to startup: $_"
}

# Notify completion
Add-Type -AssemblyName PresentationFramework
[System.Windows.MessageBox]::Show("BirdOS Post-Install was successful.", "Success", [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information)

exit
