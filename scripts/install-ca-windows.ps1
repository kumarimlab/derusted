# Install Derusted CA certificate on Windows
#
# Usage (PowerShell as Administrator):
# .\install-ca-windows.ps1 [path-to-ca.crt]

param(
    [string]$CertPath = ".\ca.crt"
)

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Error "This script must be run as Administrator"
    exit 1
}

# Check if certificate file exists
if (-not (Test-Path $CertPath)) {
    Write-Error "CA certificate not found at $CertPath"
    exit 1
}

Write-Host "Installing Derusted CA certificate to Trusted Root Certification Authorities..."

try {
    # Import certificate to Trusted Root CA store
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CertPath)
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
    $store.Open("ReadWrite")
    $store.Add($cert)
    $store.Close()

    Write-Host "✓ Derusted CA certificate installed successfully" -ForegroundColor Green
    Write-Host ""
    Write-Host "You may need to restart your applications for changes to take effect."
}
catch {
    Write-Error "Failed to install certificate: $_"
    exit 1
}
