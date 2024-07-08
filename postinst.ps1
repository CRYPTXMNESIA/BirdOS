# URL to the latest version of the script
$scriptUrl = "https://raw.githubusercontent.com/CRYPTXMNESIA/BirdOS/main/p-i.ps1"

# Path to download the latest script
$scriptPath = "$env:USERPROFILE\latest-postinst.ps1"

# Download the latest version of the script
Invoke-WebRequest -Uri $scriptUrl -OutFile $scriptPath -ErrorAction Stop

# Execute the downloaded script
& $scriptPath

# Clean up the downloaded script after execution
Remove-Item -Path $scriptPath -Force
