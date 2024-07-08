# Define error handling function
function Handle-Error {
    param(
        [string]$ErrorMessage
    )
    Write-Host $ErrorMessage -ForegroundColor Red
    exit 1
}

# Set Wallpaper
try {
    $wallpaperUrl = "https://github.com/CRYPTXMNESIA/BirdOS/w.png"
    $lockscreenUrl = "https://github.com/CRYPTXMNESIA/BirdOS/l.png"
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

    # Set lock screen wallpaper
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v RotatingLockScreenOverlayEnabled /t REG_DWORD /d 0 /f
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v RotatingLockScreenEnabled /t REG_DWORD /d 0 /f
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Lock Screen" /v Creative /t REG_SZ /d $lockscreenPath /f
} catch {
    Handle-Error "Failed to set wallpaper or lock screen wallpaper: $_"
}

# Remove Microsoft Store
try {
    Get-AppxPackage -Name Microsoft.WindowsStore | Remove-AppxPackage -ErrorAction Stop
} catch {
    Handle-Error "Failed to uninstall Microsoft Store: $_"
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

Write-Host "All tasks completed successfully." -ForegroundColor Blue
