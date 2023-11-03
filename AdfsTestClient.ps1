#================================================================================================
# This script requires AD FS admin role or equivalent permissions

#Define our command line parameter (add or remove, default to add)
param (
    [string]$Mode
)

# Check we have administrator rights
if (-not (IsAdmin)) {
    Write-Host "Not running with administrator permissions." -ForegroundColor Red
    exit
}

# Add active directory commands
import-module ActiveDirectory

& {
    $ok = $true
    $clientUri = "https://adfstest.si.local"
    $clientName = "ADFSTestClient"
    $clientDescription = "ADFS Test Client"
    $clientId = "9366768c-2951-4a7b-8c59-149a32a3fe0b"
    $clientRedirectUri = "https://adfstest.si.local/loginresponse"
    $clientLogoutUri = "https://adfstest.si.local"
    $adfsEndpoint = "https://sidc01.si.local/adfs/ls/"

    if ($Mode.ToLower() -eq "add")
    {
        AddTestClient
    } elseif ($Mode.ToLower() -eq "remove")
    {
        RemoveTestClient
    } else {
        Write-Host "Parameter 1 should be 'add' or 'remove'"
        do {
            $option = Read-Host "(A)dd, (R)emove or (Q)uit? "

            switch ($option.ToLower()) {
                'a' {
                    AddTestClient
                    exit
                }
                'r' {
                    RemoveTestClient
                    exit
                }
                'q' {
                    exit
                }
                default {
                    Write-Host "Invalid choice, try again!"
                }
            }
        } while ($true)
    }

    if ($ok -eq $true) {
        Write-Host "Result: OK" -ForegroundColor Green
    } else {
        Write-Host "Result: ERROR" -ForegroundColor Red
    }
}

#================================================================================================
# Function to check if the script is running with administrator permissions

function IsAdmin {
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    $adminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator
    $principal.IsInRole($adminRole)
}

#================================================================================================
# Function to add a client definition

function AddTestClient {

    # Client application definition

    try {
        # Register the client application
        Add-ADFSClient -Name $clientName -Description $clientDescription -ClientId $clientId -RedirectUri $clientRedirectUri -LogoutUri $clientLogoutUri
        Write-Host "Added client definition" -ForegroundColor Green
        # Display the client definition
        # Get-AdfsClient -Name $clientName

    }
    catch {
        Write-Host "Failed to add client definition. Error was: $_" -ForegroundColor Red
        $ok = $false
    }

    # Relying party trust

    try {
        Add-AdfsRelyingPartyTrust -Identifier $clientUri -Name $clientDescription -Enabled $true -WSFedEndpoint $adfsEndpoint -Notes "Trust for $clientUri"
        Write-Host "Added relying party trust" -ForegroundColor Green
        # Display the relaying party trust
        # Get-AdfsRelyingPartyTrust -Identifier $clientUri
    } catch {
        Write-Host "Failed to add relying party trust. Error was: $_" -ForegroundColor Red
        $ok = $false
    }

    # Response headers
    # https://dirteam.com/sander/2019/12/19/howto-change-the-security-response-headers-on-ad-fs

    #try {
    #    Set-AdfsResponseHeaders -EnableResponseHeaders $true
    #    Set-AdfsResponseHeaders -SetHeaderName "Strict-Transport-Security" -SetHeaderValue "max-age31536000; includeSubDomains"
    #    Set-AdfsResponseHeaders -SetHeaderName "X-XSS-Protection" -SetHeaderValue "1; mode=block"
    #    Set-AdfsResponseHeaders -SetHeaderName "Content-Security-Policy" -SetHeaderValue "default-src 'self' 'unsafe-inline' 'unsafe-eval'; img-src 'self' data:"
    #    Write-Host "Set response headers" -ForegroundColor Green
    #} catch {
    #    Write-Host "Failed to set response headers. Error was: $_" -ForegroundColor Red
    #}

    # CORS
    # https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/operations/customize-http-security-headers-ad-fs

    try {
        Set-AdfsResponseHeaders -EnableCORS $true
        Set-AdfsResponseHeaders -CORSTrustedOrigins $clientUri
        Write-Host "Enabled CORS" -ForegroundColor Green
    } catch {
        Write-Host "Failed to disable CORS. Error was: $_" -ForegroundColor Red
    }

}

#================================================================================================
# Function to remove a client definition

function RemoveTestClient {

    # Client application definition

    try {
        Remove-AdfsClient -TargetName $clientName
        Write-Host "Removed client $clientName" -ForegroundColor Green
    } catch {
        Write-Host "Failed to remove client $clientName. Error was: $_" -ForegroundColor Red
        $ok = $false
    }

    # Relying party trust

    try {
        Remove-AdfsRelyingPartyTrust -TargetIdentifier $clientUri
        Write-Host "Removed relying party trust $clientUri" -ForegroundColor Green
    }
    Catch {
        Write-Host "Failed to remove rekying party trust $clientUri. Error was: $_" -ForegroundColor Red
        $ok = $false
    }

    # Response headers
    # https://dirteam.com/sander/2019/12/19/howto-change-the-security-response-headers-on-ad-fs

    #try {
    #    Set-AdfsResponseHeaders -EnableResponseHeaders $false
    #    Set-AdfsResponseHeaders -RemoveHeaders "Strict-Transport-Security"
    #    Set-AdfsResponseHeaders -RemoveHeaders "X-XSS-Protection"
    #    Set-AdfsResponseHeaders -RemoveHeaders "Content-Security-Policy"
    #    Write-Host "Removed response headers" -ForegroundColor Green
    #} catch {
    #    Write-Host "Failed to remove response headers. Error was: $_" -ForegroundColor Red
    #    $ok = $false
    #}

    # CORS
    # https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/operations/customize-http-security-headers-ad-fs

    try {
        Set-AdfsResponseHeaders -EnableCORS $false
        Set-AdfsResponseHeaders -CORSTrustedOrigins ""
        Write-Host "Disabled CORS" -ForegroundColor Green
    } catch {
        Write-Host "Failed to disable CORS. Error was: $_" -ForegroundColor Red
        $ok = $false
    }
}
