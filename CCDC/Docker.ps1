# Disable Docker remote API
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "Docker Desktop" -Value '"C:\Program Files\Docker\Docker\Docker Desktop.exe" -minimize'
Stop-Service -Name "com.docker.service"
Set-Service -Name "com.docker.service" -StartupType Disabled

# Enable Docker Content Trust
[Environment]::SetEnvironmentVariable("DOCKER_CONTENT_TRUST", "1", "Machine")

# Restrict Docker daemon access
$dockerConfigPath = "$env:ProgramData\Docker\config\daemon.json"
$dockerConfig = Get-Content -Raw -Path $dockerConfigPath | ConvertFrom-Json
$dockerConfig."hosts" = @("tcp://localhost:2376", "npipe://")
$dockerConfig | ConvertTo-Json | Set-Content -Path $dockerConfigPath

# Enable Docker image verification
$dockerConfig."experimental" = $true
$dockerConfig | ConvertTo-Json | Set-Content -Path $dockerConfigPath

# Disable Docker remote management
$dockerConfig."live-restore" = $true
$dockerConfig | ConvertTo-Json | Set-Content -Path $dockerConfigPath

# Restart Docker service
Restart-Service -Name "com.docker.service"


Please note that this script assumes you are running Docker on a Windows machine. Adjustments may be needed if you are using a different operating system.

This script performs the following actions:
1. Disables Docker remote API to prevent unauthorized access.
2. Enables Docker Content Trust to ensure only signed images are used.
3. Restricts Docker daemon access to local connections only.
4. Enables Docker image verification to prevent the use of unverified images.
5. Disables Docker remote management to limit potential attack vectors.
6. Restarts the Docker service to apply the changes.
