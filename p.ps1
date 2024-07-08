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

# Set the execution policy
try {
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force -ErrorAction Stop
} catch {
    Write-Host "Failed to set execution policy: $_" -ForegroundColor Red
    Read-Host "Press any key to exit..."
    exit 1
}

# URL to the latest version of the script
$scriptUrl = "https://raw.githubusercontent.com/CRYPTXMNESIA/BirdOS/main/p-i.ps1"

# Path to download the latest script
$scriptPath = "$env:USERPROFILE\latest-script.ps1"

# Download the latest version of the script
try {
    Invoke-WebRequest -Uri $scriptUrl -OutFile $scriptPath -ErrorAction Stop
} catch {
    Write-Host "Failed to download the latest script: $_" -ForegroundColor Red
    Read-Host "Press any key to exit..."
    exit 1
}

# Execute the downloaded script
try {
    & $scriptPath
} catch {
    Write-Host "Failed to execute the script: $_" -ForegroundColor Red
    Read-Host "Press any key to exit..."
    exit 1
}

# Clean up the downloaded script after execution
Remove-Item -Path $scriptPath -Force
