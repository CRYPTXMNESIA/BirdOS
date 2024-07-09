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

# Function to reset Windows Search
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

# Function to find and kill the process locking the file
function Get-LockingProcess {
    param (
        [string]$filePath
    )

    # Find the process locking the file
    try {
        $lockingProcess = Get-Process | Where-Object {
            $_.Modules -ErrorAction SilentlyContinue | Where-Object { $_.FileName -eq $filePath }
        }
        return $lockingProcess
    } catch {
        Log-Error "Error finding the process locking ${filePath}: $_"
        return $null
    }
}

# Function to kill the process using the file and delete the file
function Delete-WebCacheFile {
    param (
        [string]$filePath
    )

    $attempt = 0
    $maxAttempts = 3

    while ((Test-Path -Path $filePath) -and ($attempt -lt $maxAttempts)) {
        $attempt++
        # Get the process locking the file
        $lockingProcess = Get-LockingProcess -filePath $filePath

        # Kill the process if found
        if ($lockingProcess) {
            try {
                Stop-Process -Id $lockingProcess.Id -Force
                Write-Output "Killed process $($lockingProcess.Name) with ID $($lockingProcess.Id) that was locking ${filePath}"
            } catch {
                Log-Error "Failed to kill process $($lockingProcess.Name) with ID $($lockingProcess.Id): $_"
                return
            }
        }

        # Attempt to delete the file
        try {
            Remove-Item -Path $filePath -Force
            Write-Output "Deleted file ${filePath}"
        } catch {
            Log-Error "Failed to delete file ${filePath}: $_"
            Start-Sleep -Seconds 5
        }
    }
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

# Delete WebCacheV01.dat
try {
    $webCacheFilePath = "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat"
    Delete-WebCacheFile -filePath $webCacheFilePath
} catch {
    Log-Error "Failed to delete WebCacheV01.dat: $_"
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
