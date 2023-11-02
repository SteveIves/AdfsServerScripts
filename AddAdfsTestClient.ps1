#================================================================================================
# This script requires AD FS admin role or equivalent permissions

# Start with a clear screen
cls

# Add active directory commands
import-module ActiveDirectory

$ok = $true

#================================================================================================
# Define parameters

$clientUri = "https://adfstest.si.local"
$clientName = "ADFSTestClient"
$clientDescription = "ADFS Test Client"
$clientId = "9366768c-2951-4a7b-8c59-149a32a3fe0b"
$clientRedirectUri = "https://adfstest.si.local/loginresponse"
$clientLogoutUri = "https://adfstest.si.local"
$adfsEndpoint = "https://sidc01.si.local/adfs/ls/"

#================================================================================================
# Delete any existing client application definition

try {
    Remove-AdfsClient -TargetName $clientName
    Write-Host "Removed client $clientName" -ForegroundColor Green
} catch {
    # It's OK if the remove failed, maybe it just wasn't there
}

#================================================================================================
# Add a new client application definition

try {
    # Register the client application
    Add-ADFSClient -Name $clientName -Description $clientDescription -ClientId $clientId -RedirectUri $clientRedirectUri -LogoutUri $clientLogoutUri
    Write-Host "Added client $clientName" -ForegroundColor Green
    # Display the client definition
    # Get-AdfsClient -Name $clientName

}
catch {
    Write-Host "Failed to add client $clientName. Error was: $_" -ForegroundColor Red
    $ok = $false
}

#================================================================================================
# Delete any existing relying party trust

if ($ok -eq $true) {
    try {
        Remove-AdfsRelyingPartyTrust -TargetIdentifier $clientUri
        Write-Host "Removed relying party trust $clientUri" -ForegroundColor Green
    }
    Catch {
        # It's OK if the remove failed, maybe it just wasn't there
    }
}

#================================================================================================
# Add a new relying party trust

if ($ok -eq $true) {
    try {
        Add-AdfsRelyingPartyTrust -Identifier $clientUri -Name $clientDescription -Enabled $true -WSFedEndpoint $adfsEndpoint -Notes "Trust for $clientUri"
        Write-Host "Added relying party trust $clientUri" -ForegroundColor Green
        # Display the relaying party trust
        # Get-AdfsRelyingPartyTrust -Identifier $clientUri
    } catch {
        Write-Host "Failed to add relying party trust $clientUri. Error was: $_" -ForegroundColor Red
        $ok = $false
    }
}

#================================================================================================
# Clear existing AD FS response headers

if ($ok -eq $true) {
    try {
        Set-AdfsResponseHeaders -ClearHeaders
    } catch {

    }
}

#================================================================================================
# https://dirteam.com/sander/2019/12/19/howto-change-the-security-response-headers-on-ad-fs

if ($ok -eq $true) {
    Set-AdfsResponseHeaders -EnableResponseHeaders $true
    Set-AdfsResponseHeaders -SetHeaderName "Strict-Transport-Security" -SetHeaderValue "max-age31536000; includeSubDomains"
    Set-AdfsResponseHeaders -SetHeaderName "X-XSS-Protection" -SetHeaderValue "1; mode=block"
    Set-AdfsResponseHeaders -SetHeaderName "Content-Security-Policy" -SetHeaderValue "default-src 'self' 'unsafe-inline' 'unsafe-eval'; img-src 'self' data:"
}

#================================================================================================
# https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/operations/customize-http-security-headers-ad-fs

if ($ok -eq $true) {
    Set-AdfsResponseHeaders -EnableCORS $true
    Set-AdfsResponseHeaders -CORSTrustedOrigins https://adfstest.si.local
}

if ($ok -eq $true) {
        Write-Host "Result: OK" -ForegroundColor Green
} else {
        Write-Host "Result: ERROR" -ForegroundColor Red    
}