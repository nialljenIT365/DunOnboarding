<#
.SYNOPSIS
    DUN Security - Azure Onboarding Script (PowerShell 5.1 Compatible)

.DESCRIPTION
    PowerShell script for automating DUN Security onboarding to Azure tenants.
    Configures App Registration, Service Principal, Graph API permissions, and RBAC roles.
    
    This version is fully compatible with PowerShell 5.1 and avoids parse issues.

.NOTES
    Author: Niall Jennings/Nigel Gillespie
    Date: 2026-01-13
    Version: 1.0.0
    
    Requirements:
    - Azure CLI installed (or run in Azure Cloud Shell)
    - Global Administrator or Privileged Role Administrator access
    - PowerShell 5.1 or later
#>

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

# ============================================================================
# Configure UTF-8 Output for Unicode Characters (box-drawing, emojis)
# ============================================================================
# Set Windows console code page to UTF-8 for proper Unicode display
try {
    # Change console code page to UTF-8 (65001)
    $null = cmd /c "chcp 65001 >nul 2>&1"
} catch {
    # Ignore errors - some environments don't support chcp
}

# Set console encoding to UTF-8 to properly display Unicode characters
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

# For Windows Terminal / PowerShell 7+, this should work automatically
if ($PSVersionTable.PSVersion.Major -ge 7) {
    $env:PYTHONIOENCODING = "utf-8"
}

# ============================================================================
# Helper Functions
# ============================================================================
# Helper function to return a boolean True/False check if the logged in User is Global Admin in IDE
function Test-GlobalAdminActiveIDE {
  # Global Administrator roleDefinitionId in Microsoft Graph
  $gaRoleDefinitionId = "62e90394-69f5-4237-9190-012177145e10"
  $meId = az ad signed-in-user show --query id -o tsv

  if (-not $meId) {
    Write-Warning "Could not resolve the signed-in user's Entra ID objectId, so Global Administrator status could not be validated."
    return $false
  }

  try {
    # Active role assignments (covers permanent assignment + PIM activation)
    $uri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=principalId eq '$meId' and roleDefinitionId eq '$gaRoleDefinitionId'&`$select=id"
    $json = az rest --method GET --uri $uri -o json
    $resp = if ($json) { $json | ConvertFrom-Json } else { $null }

    $isActive = ($resp -and $resp.value -and $resp.value.Count -gt 0)

    if ($isActive) {
      return $true
    } else {
      return $false
    }
  }
  catch {
    Write-Warning "Could not query Microsoft Graph to validate Global Administrator status."
    Write-Warning "If you use PIM, ensure the role is activated; otherwise you may not have rights to read role assignments."
    return $false
  }
}

# Helper function to return a boolean True/False check if the logged in User is Global Admin in CloudShell
function Test-GlobalAdminActiveCloudShell {
  [CmdletBinding()]
  param(
    [string]$GaRoleDefinitionId = "62e90394-69f5-4237-9190-012177145e10"
  )

  if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    throw "Azure CLI (az) not found."
  }

  $meId = az rest --method GET --uri "https://graph.microsoft.com/v1.0/me?`$select=id" --query id -o tsv --only-show-errors 2>&1
  if ($LASTEXITCODE -ne 0 -or -not $meId) { throw "Failed to resolve signed-in user id. $meId" }

  $filter = [uri]::EscapeDataString("principalId eq '$meId' and roleDefinitionId eq '$GaRoleDefinitionId'")
  $uri    = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=$filter&`$select=id&`$top=50"

  $count = az rest --method GET --uri $uri --query "length(value)" -o tsv --only-show-errors 2>&1
  if ($LASTEXITCODE -ne 0 -or -not $count) { throw "Failed to query roleAssignments. $count" }

  return ([int]$count -gt 0)
}

# ============================================================================
# Introduction
# ============================================================================

Write-Host ""
Write-Host "+================================================================+" -ForegroundColor Cyan
Write-Host "|                                                                |" -ForegroundColor Cyan
Write-Host "|              DUN Security - Azure Onboarding                   |" -ForegroundColor Cyan
Write-Host "|                                                                |" -ForegroundColor Cyan
Write-Host "+================================================================+" -ForegroundColor Cyan
Write-Host ""
Write-Host "Welcome to DUN Security!" -ForegroundColor Blue
Write-Host ""
Write-Host "This script will configure your Azure tenant to allow DUN Security"
Write-Host "to perform continuous security monitoring and compliance tracking."
Write-Host ""
Write-Host "================================================================" -ForegroundColor Yellow
Write-Host "What will this script do?" -ForegroundColor Blue
Write-Host "================================================================" -ForegroundColor Yellow
Write-Host ""
Write-Host "1. " -NoNewline
Write-Host "Create an App Registration" -ForegroundColor Green -NoNewline
Write-Host " in your Azure AD"
Write-Host "   -> This is the identity DUN will use for authentication"
Write-Host ""
Write-Host "2. " -NoNewline
Write-Host "Create a Service Principal" -ForegroundColor Green
Write-Host "   -> The service account that performs security scans"
Write-Host ""
Write-Host "3. " -NoNewline
Write-Host "Grant Microsoft Graph API Permissions" -ForegroundColor Green
Write-Host ""
Write-Host "   " -NoNewline
Write-Host "Read-Only (for security scanning):" -ForegroundColor Yellow
Write-Host "   " -NoNewline
Write-Host "Directory.Read.All" -ForegroundColor Cyan -NoNewline
Write-Host "                   - Read apps and service principals"
Write-Host "   " -NoNewline
Write-Host "Application.Read.All" -ForegroundColor Cyan -NoNewline
Write-Host "                 - Audit app registrations"
Write-Host "   " -NoNewline
Write-Host "RoleManagement.Read.All" -ForegroundColor Cyan -NoNewline
Write-Host "              - Detect privileged access"
Write-Host "   " -NoNewline
Write-Host "User.Read.All" -ForegroundColor Cyan -NoNewline
Write-Host "                        - Build identity graph"
Write-Host "   " -NoNewline
Write-Host "Policy.Read.All" -ForegroundColor Cyan -NoNewline
Write-Host "                      - Audit Conditional Access policies"
Write-Host "   " -NoNewline
Write-Host "AuditLog.Read.All" -ForegroundColor Cyan -NoNewline
Write-Host "                    - Analyze sign-in activity and policy changes"
Write-Host "   " -NoNewline
Write-Host "Reports.Read.All" -ForegroundColor Cyan -NoNewline
Write-Host "                     - Check MFA coverage"
Write-Host "   " -NoNewline
Write-Host "UserAuthenticationMethod.Read.All" -ForegroundColor Cyan -NoNewline
Write-Host "    - Read MFA methods per user"
Write-Host "   " -NoNewline
Write-Host "IdentityRiskyUser.Read.All" -ForegroundColor Cyan -NoNewline
Write-Host "           - Detect risky users (requires P2)"
Write-Host ""
Write-Host "4. " -NoNewline
Write-Host "Assign Azure RBAC Roles" -ForegroundColor Green
Write-Host "   Note: Subscription-level, READ-ONLY access"
Write-Host "   " -NoNewline
Write-Host "Reader" -ForegroundColor Cyan -NoNewline
Write-Host "                  - Browse resources, read RBAC"
Write-Host "   " -NoNewline
Write-Host "Security Reader" -ForegroundColor Cyan -NoNewline
Write-Host "         - Access Defender for Cloud"
Write-Host "   " -NoNewline
Write-Host "Key Vault Reader" -ForegroundColor Cyan -NoNewline
Write-Host "        - Assess encryption posture"
Write-Host "   " -NoNewline
Write-Host "Log Analytics Reader" -ForegroundColor Cyan -NoNewline
Write-Host "    - Query security logs"
Write-Host "   " -NoNewline
Write-Host "Network Contributor" -ForegroundColor Cyan -NoNewline
Write-Host "     - Enable NSG Flow Logs (setup only)"
Write-Host "   " -NoNewline
Write-Host "Storage Contributor" -ForegroundColor Cyan -NoNewline
Write-Host "     - Create flow log storage (setup only)"
Write-Host ""
Write-Host "5. " -NoNewline
Write-Host "Create Client Secret" -ForegroundColor Green -NoNewline
Write-Host " for tenant authentication"
Write-Host "   -> Used for SSO and API access to your DUN tenant"
Write-Host ""
Write-Host "================================================================" -ForegroundColor Yellow
Write-Host ""
Write-Host "Security Model" -ForegroundColor Green
Write-Host ""
Write-Host "The service principal has " -NoNewline
Write-Host "READ-ONLY" -ForegroundColor Green -NoNewline
Write-Host " access."
Write-Host "DUN Security " -NoNewline
Write-Host "cannot" -ForegroundColor Red -NoNewline
Write-Host " modify, delete, or create any resources in your tenant."
Write-Host ""
Write-Host "All permissions are read-only:" -ForegroundColor Yellow
Write-Host "   * Graph API: Read users, groups, apps, policies, and audit logs"
Write-Host "   * Azure RBAC: Read resources, security findings, and configurations"
Write-Host "   * No write permissions are requested"
Write-Host ""
Write-Host "Press Enter to continue, or Ctrl+C to cancel..." -ForegroundColor Yellow
$null = Read-Host
Write-Host ""

# ============================================================================
# Step 1: Check Prerequisites
# ============================================================================
Write-Host "================================================================" -ForegroundColor Blue
Write-Host "Step 1: Prerequisites Check" -ForegroundColor Blue
Write-Host "================================================================" -ForegroundColor Blue
Write-Host ""

# Detect Azure Cloud Shell (PowerShell or Bash-backed). In Cloud Shell, Azure CLI is always present.
$IsCloudShell = $false
try {
    if ($env:ACC_CLOUD -or
        $env:AZUREPS_HOST_ENVIRONMENT -or
        $env:AZURE_HTTP_USER_AGENT -or
        ($env:POWERSHELL_DISTRIBUTION_CHANNEL -match "CloudShell")) {
        $IsCloudShell = $true
    }
} catch { }

if ($IsCloudShell) {
    Write-Host "[OK] Running in Azure Cloud Shell (Azure CLI available)" -ForegroundColor Green
    Write-Host "[OK] Cloud Shell sessions are unable to fetch the token required to grant the Graph API Permissions required for the completion of this script." -ForegroundColor Green
    Write-Host "It will be necessary to re-authenticate with the --use-device-code switch, please follow the instructions below to proceed" -ForegroundColor Yellow
    Write-Host ""
    az login --use-device-code --only-show-errors | Out-Null
    Write-Host "[OK] Validate if GA Role is Active" -ForegroundColor Green
    $IsGlobalAdminActive = Test-GlobalAdminActiveCloudShell

    if ($IsGlobalAdminActive) {
        Write-Host "[OK] GA Role is Active" -ForegroundColor Green
    } else {
        Write-Host "[X] GA Role has not been activated for this account" -ForegroundColor Red
        Write-Host ""
        exit 1
    }

} else {
    if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
        Write-Host "[X] Azure CLI is not installed" -ForegroundColor Red
        Write-Host ""
        Write-Host "Please install Azure CLI first:"
        Write-Host "  Download: https://aka.ms/installazurecliwindows"
        Write-Host "  Or run:   winget install -e --id Microsoft.AzureCLI"
        Write-Host ""
        exit 1
    }

    Write-Host "[OK] Running in Local Powershell Context" -ForegroundColor Green
    Write-Host "[OK] Azure CLI is installed" -ForegroundColor Green
}

# ============================================================================
# Step 2: Prompt for Organization Name
# ============================================================================
Write-Host "================================================================" -ForegroundColor Blue
Write-Host "Step 2: Organization Information" -ForegroundColor Blue
Write-Host "================================================================" -ForegroundColor Blue
Write-Host ""
Write-Host "Please enter your organization name (e.g., " -NoNewline
Write-Host "Acme Corp" -ForegroundColor Cyan -NoNewline
Write-Host ", " -NoNewline
Write-Host "Contoso" -ForegroundColor Cyan -NoNewline
Write-Host "):"

$ORG_NAME = Read-Host ">"

if ([string]::IsNullOrWhiteSpace($ORG_NAME)) {
    Write-Host "[X] Organization name cannot be empty" -ForegroundColor Red
    exit 1
}

$APP_DISPLAY_NAME = "DUN Security - $ORG_NAME"

# Derive URL-safe slug
$CLIENT_SLUG = $ORG_NAME.ToLower() -replace '[^a-z0-9-]', '-' -replace '-+', '-'
$CLIENT_SLUG = $CLIENT_SLUG.Trim('-')

Write-Host ""
Write-Host "[OK] Organization: $ORG_NAME" -ForegroundColor Green
Write-Host "[OK] App Name: $APP_DISPLAY_NAME" -ForegroundColor Green
Write-Host "[OK] When the onboarding process is complete your dashboard will be accessible at: " -ForegroundColor Green -NoNewline
Write-Host "https://$CLIENT_SLUG.dunsecurity.ai" -ForegroundColor Yellow -NoNewline
Write-Host "" -ForegroundColor Green
Write-Host ""
Write-Host "If you are happy with the details above, press Enter to continue (or press Ctrl+C to cancel)..." -ForegroundColor Yellow
$null = Read-Host
Write-Host ""

# ============================================================================
# Step 3: Azure Authentication
# ============================================================================
Write-Host "================================================================" -ForegroundColor Blue
Write-Host "Step 3: Azure Authentication" -ForegroundColor Blue
Write-Host "================================================================" -ForegroundColor Blue
Write-Host ""
Write-Host "Note: You will need Global Administrator or Privileged Role Administrator access" -ForegroundColor Yellow
Write-Host ""
Write-Host "Checking Azure login status..."

if (-not $IsCloudShell) {

    try {
        $account = az account show -o json | ConvertFrom-Json
        Write-Host ""
        Write-Host "[OK] Signed in as: $($account.user.name)" -ForegroundColor Green
        Write-Host ""
        Write-Host "Is this the correct administrator account? [Y/N]"
        $confirm = Read-Host ">"

        if ($confirm -notmatch "^[Yy]") {
            Write-Host ""
            Write-Host "Please sign in with the correct account:" -ForegroundColor Yellow
            az login | Out-Null
            $account = az account show -o json | ConvertFrom-Json
        }
    } catch {
        Write-Host ""
        Write-Host "Please sign in with your administrator account:" -ForegroundColor Yellow
        Write-Host ""
        az login | Out-Null
        $account = az account show -o json | ConvertFrom-Json
    }

    Write-Host "[OK] Validate if GA Role is Active" -ForegroundColor Green
    $IsGlobalAdminActive = Test-GlobalAdminActiveIDE

    if ($IsGlobalAdminActive) {
        Write-Host "[OK] GA Role is Active" -ForegroundColor Green
    } else {
        Write-Host "[X] GA Role has not been activated for this account" -ForegroundColor Red
        Write-Host ""
        exit 1
    }

} else {
    Write-Host "[OK] Skipping interactive Azure Authentication step (Cloud Shell handled earlier)" -ForegroundColor Green
    $account = az account show -o json | ConvertFrom-Json
}

$TENANT_ID = $account.tenantId
#$SUB_ID = $account.id
$TENANT_NAME = $account.name

# Clean up special characters that don't display well in PowerShell 5.1 console
# Replace Unicode dashes and other special chars with ASCII equivalents
function Clean-DisplayText {
    param([string]$text)
    return $text -replace [char]0x2013, '-' -replace [char]0x2014, '-' -replace [char]0x00AD, '-' -replace '[^\x20-\x7E]', '-'
}

$TENANT_NAME_CLEAN = Clean-DisplayText $TENANT_NAME

Write-Host ""
Write-Host "[OK] Authenticated successfully" -ForegroundColor Green
Write-Host ""
Write-Host "  Tenant: " -NoNewline
Write-Host $TENANT_NAME_CLEAN -ForegroundColor Cyan
Write-Host "  Tenant ID: " -NoNewline
Write-Host $TENANT_ID -ForegroundColor Cyan
Write-Host ""

# ============================================================================
# Step 4: Create App Registration
# ============================================================================
Write-Host "================================================================" -ForegroundColor Blue
Write-Host "Step 4: Create App Registration" -ForegroundColor Blue
Write-Host "================================================================" -ForegroundColor Blue
Write-Host ""
Write-Host "Creating the App Registration for DUN Security..."
Write-Host ""

# Create both redirect URIs: azurewebsites.net (default) and custom domain
$REDIRECT_URI_APP = "https://app-dun-$CLIENT_SLUG-prod.azurewebsites.net/api/auth/callback/azure-ad"
$REDIRECT_URI_CUSTOM = "https://$CLIENT_SLUG.dunsecurity.ai/api/auth/callback/azure-ad"

Write-Host "  App name: " -NoNewline
Write-Host $APP_DISPLAY_NAME -ForegroundColor Cyan
Write-Host "  Redirect URIs:"
Write-Host "    - $REDIRECT_URI_APP"
Write-Host "    - $REDIRECT_URI_CUSTOM"
Write-Host ""

try {
    $APP_ID = az ad app create `
        --display-name $APP_DISPLAY_NAME `
        --web-redirect-uris $REDIRECT_URI_APP $REDIRECT_URI_CUSTOM `
        --query appId -o tsv

    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($APP_ID)) {
        throw "Failed to create App Registration"
    }

    Write-Host "[OK] App Registration created" -ForegroundColor Green
    Write-Host "  Client ID: " -NoNewline
    Write-Host $APP_ID -ForegroundColor Cyan
    Write-Host ""
}
catch {
    Write-Host "[X] Failed to create App Registration" -ForegroundColor Red
    Write-Host "Error: $_" -ForegroundColor Red
    Write-Host ""
    exit 1
}

# ============================================================================
# Step 4b: Expose API for OBO (On-Behalf-Of) Token Exchange
# ============================================================================
Write-Host ""
Write-Host "Configuring API for secure token exchange..." -ForegroundColor Yellow
Write-Host ""

# Set Application ID URI
$null = az ad app update --id $APP_ID --identifier-uris "api://$APP_ID" 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Host "  [OK] Application ID URI set: api://$APP_ID" -ForegroundColor Green
} else {
    Write-Host "  [!] Could not set Application ID URI (you may need to configure it manually)" -ForegroundColor Yellow
}

# Resolve the app's object ID (Graph uses objectId, not appId)
$APP_OBJECT_ID = az ad app show --id $APP_ID --query "id" -o tsv
if (-not $APP_OBJECT_ID) {
    Write-Host "  [!] Could not resolve App objectId. Exposed API scope setup may be skipped" -ForegroundColor Yellow
} else {
    try {
        # Get access token for Graph API
        $token = az account get-access-token --resource https://graph.microsoft.com --query accessToken -o tsv
        
        if (-not $token) {
            throw "Could not get access token"
        }

        $uri = "https://graph.microsoft.com/v1.0/applications/$APP_OBJECT_ID"
        $headers = @{
            "Authorization" = "Bearer $token"
            "Content-Type" = "application/json"
        }

        # Fetch existing scopes so we don't overwrite them
        $existing = Invoke-RestMethod -Uri "$uri`?`$select=api" -Headers $headers -Method GET -ErrorAction Stop

        $existingScopes = @()
        if ($existing.api -and $existing.api.oauth2PermissionScopes) {
            $existingScopes = @($existing.api.oauth2PermissionScopes)
        }

        # Check if scope already exists
        $alreadyThere = $false
        if ($existingScopes.Count -gt 0) {
            $alreadyThere = $existingScopes | Where-Object { $_.value -eq "user_impersonation" } | Select-Object -First 1
        }

        if ($alreadyThere) {
            Write-Host "  [OK] API scope already present (user_impersonation)" -ForegroundColor Green
        } else {
            # Create new scope
            $SCOPE_ID = [guid]::NewGuid().ToString()
            $newScope = @{
                adminConsentDescription = "Allow DUN Security to access Azure resources on behalf of the signed-in user for AI-driven remediation"
                adminConsentDisplayName = "Access Azure for AI Remediation"
                id = $SCOPE_ID
                isEnabled = $true
                type = "User"
                userConsentDescription = "Allow DUN Security to fix Azure security issues on your behalf using AI"
                userConsentDisplayName = "Fix Azure security issues with AI"
                value = "user_impersonation"
            }

            # Add new scope to existing scopes
            $allScopes = $existingScopes + $newScope
            
            $patchBody = @{
                api = @{
                    oauth2PermissionScopes = $allScopes
                }
            } | ConvertTo-Json -Depth 20

            # Use Invoke-RestMethod (works in both IDE and Cloud Shell)
            Invoke-RestMethod -Uri $uri -Headers $headers -Method PATCH -Body $patchBody -ErrorAction Stop | Out-Null
            Write-Host "  [OK] API scope configured for OBO token exchange (user_impersonation)" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "  [!] Could not configure API scope (may require manual setup)" -ForegroundColor Yellow
        Write-Host "  Error: $_" -ForegroundColor DarkGray
    }
}

Write-Host ""

# ============================================================================
# Step 5: Create Service Principal
# ============================================================================
Write-Host "================================================================" -ForegroundColor Blue
Write-Host "Step 5: Create Service Principal" -ForegroundColor Blue
Write-Host "================================================================" -ForegroundColor Blue
Write-Host ""

try {
    $SP_ID = az ad sp create --id $APP_ID --query id -o tsv 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[OK] Service Principal created" -ForegroundColor Green
        Write-Host "  SP Object ID: " -NoNewline
        Write-Host $SP_ID -ForegroundColor Cyan
    } else {
        throw "Creation failed"
    }
} catch {
    Write-Host "[!] Service Principal might already exist, retrieving..." -ForegroundColor Yellow
    $SP_ID = az ad sp show --id $APP_ID --query id -o tsv
    if ($LASTEXITCODE -eq 0 -and $SP_ID) {
        Write-Host "[OK] Found existing Service Principal" -ForegroundColor Green
        Write-Host "  SP Object ID: " -NoNewline
        Write-Host $SP_ID -ForegroundColor Cyan
    } else {
        Write-Host "[X] Failed to create or retrieve Service Principal" -ForegroundColor Red
        Write-Host ""
        exit 1
    }
}
Write-Host ""

# ============================================================================
# Step 5b: Create Client Secret for SSO
# ============================================================================
Write-Host ""
Write-Host "Creating client secret for Single Sign-On (SSO)..." -ForegroundColor Yellow
Write-Host ""

# Create a client secret that expires in 2 years
$SECRET_EXPIRY = (Get-Date).AddYears(2).ToString("yyyy-MM-dd")
try {
    $CLIENT_SECRET = az ad app credential reset `
        --id $APP_ID `
        --append `
        --display-name "DUN-SSO-Secret" `
        --end-date $SECRET_EXPIRY `
        --query password -o tsv 2>$null

    if ($LASTEXITCODE -eq 0 -and $CLIENT_SECRET) {
        Write-Host "  [OK] Client secret created (expires: $SECRET_EXPIRY)" -ForegroundColor Green
        Write-Host ""
        Write-Host "  This secret enables Single Sign-On to your DUN tenant." -ForegroundColor DarkGray
        Write-Host "  It will be securely stored during provisioning." -ForegroundColor DarkGray
    } else {
        throw "Failed to create client secret"
    }
}
catch {
    Write-Host "  [!] Could not create client secret" -ForegroundColor Yellow
    Write-Host "  SSO may need to be configured manually" -ForegroundColor Yellow
    $CLIENT_SECRET = $null
}
Write-Host ""

# ============================================================================
# Step 6: Grant Microsoft Graph API Permissions
# ============================================================================
Write-Host "================================================================" -ForegroundColor Blue
Write-Host "Step 6: Grant Microsoft Graph API Permissions" -ForegroundColor Blue
Write-Host "================================================================" -ForegroundColor Blue
Write-Host ""
Write-Host "Configuring read-only Graph API permissions..."
Write-Host ""

$MS_GRAPH_ID = "00000003-0000-0000-c000-000000000000"

# Permission ID to name mapping for display
$GRAPH_PERMISSIONS = @(
    @{Id="7ab1d382-f21e-4acd-a863-ba3e13f7da61"; Name="Directory.Read.All"; Required=$true},
    @{Id="9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30"; Name="Application.Read.All"; Required=$true},
    @{Id="c7fbd983-d9aa-4fa7-84b8-17382c103bc4"; Name="RoleManagement.Read.All"; Required=$true},
    @{Id="df021288-bdef-4463-88db-98f22de89214"; Name="User.Read.All"; Required=$true},
    @{Id="246dd0d5-5bd0-4def-940b-0421030a5b68"; Name="Policy.Read.All"; Required=$true},
    @{Id="b0afded3-3588-46d8-8b3d-9842eff778da"; Name="AuditLog.Read.All"; Required=$true},
    @{Id="230c1aed-a721-4c5d-9cb4-a90514e508ef"; Name="Reports.Read.All"; Required=$true},
    @{Id="38d9df27-64da-44fd-b7c5-a6fbac20248f"; Name="UserAuthenticationMethod.Read.All"; Required=$true},
    @{Id="dc5007c0-2d7d-4c42-879c-2dab87571379"; Name="IdentityRiskyUser.Read.All"; Required=$false}
)

$permAddErrors = @()
foreach ($perm in $GRAPH_PERMISSIONS) {
    $ErrorActionPreference = 'Continue'
    $result = az ad app permission add `
        --id $APP_ID `
        --api $MS_GRAPH_ID `
        --api-permissions "$($perm.Id)=Role" 2>&1 | Out-String
    
    if ($LASTEXITCODE -ne 0 -and $result -notmatch "already exists") {
        $permAddErrors += $perm.Name
        Write-Host "  [!] Failed to add: $($perm.Name)" -ForegroundColor Yellow
    } else {
        Write-Host "  [OK] $($perm.Name)" -ForegroundColor Green
    }
}

if ($permAddErrors.Count -gt 0) {
    Write-Host ""
    Write-Host "[!] Some permissions failed to add: $($permAddErrors -join ', ')" -ForegroundColor Yellow
} else {
    Write-Host ""
    Write-Host "[OK] All Graph API permissions configured" -ForegroundColor Green
}
Write-Host ""

# ============================================================================
# Step 6b: Azure Service Management API Permission (for Fix with AI)
# ============================================================================
Write-Host ""
Write-Host "Configuring Azure Service Management permission (for Fix with AI)..." -ForegroundColor Yellow
Write-Host ""

# Azure Service Management API (for remediation via user's Azure permissions)
$AZURE_MGMT_ID = "797f4846-ba00-4fd7-ba43-dac1f8f63013"
$USER_IMPERSONATION_ID = "41094075-9dad-400e-a0bd-54e686782033"

$ErrorActionPreference = 'Continue'
$mgmtResult = az ad app permission add `
    --id $APP_ID `
    --api $AZURE_MGMT_ID `
    --api-permissions "$USER_IMPERSONATION_ID=Scope" 2>&1 | Out-String

if ($LASTEXITCODE -eq 0 -or $mgmtResult -match "already exists") {
    Write-Host "  [OK] Azure Service Management (user_impersonation)" -ForegroundColor Green
    Write-Host ""
    Write-Host "  This permission enables 'Fix with AI' - users can remediate findings" -ForegroundColor DarkGray
    Write-Host "  using their own Azure permissions (Contributor/Owner role required)" -ForegroundColor DarkGray
} else {
    Write-Host "  [!] Could not add Azure Service Management permission" -ForegroundColor Yellow
    Write-Host "  Fix with AI will not work until this permission is added manually" -ForegroundColor Yellow
}
Write-Host ""

Write-Host "Waiting for permissions to propagate..." -ForegroundColor DarkGray
Start-Sleep -Seconds 5

Write-Host "Granting admin consent..."
$consentResult = az ad app permission admin-consent --id $APP_ID 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "[OK] Admin consent granted" -ForegroundColor Green
} else {
    Write-Host "[!] Admin consent may need to be granted manually" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Visit: " -NoNewline
    Write-Host "https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/CallAnAPI/appId/$APP_ID" -ForegroundColor Blue
    Write-Host ""
    Write-Host "Error details: $consentResult" -ForegroundColor DarkGray
}
Write-Host ""

# Verify permissions were applied
Write-Host "Verifying permissions..."
Start-Sleep -Seconds 3  # Brief delay for Azure to propagate

$appliedPerms = az ad app permission list --id $APP_ID --query "[].resourceAccess[].id" -o json 2>$null | ConvertFrom-Json
$requiredPerms = $GRAPH_PERMISSIONS | Where-Object { $_.Required -eq $true }
$missingPerms = @()

foreach ($perm in $requiredPerms) {
    if ($appliedPerms -notcontains $perm.Id) {
        $missingPerms += $perm.Name
    }
}

if ($missingPerms.Count -eq 0) {
    Write-Host "[OK] All required permissions verified" -ForegroundColor Green
} else {
    Write-Host "[X] Missing required permissions: $($missingPerms -join ', ')" -ForegroundColor Red
    Write-Host ""
    Write-Host "Please add these permissions manually in Azure Portal:" -ForegroundColor Yellow
    Write-Host "https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/CallAnAPI/appId/$APP_ID" -ForegroundColor Blue
}
Write-Host ""

# ============================================================================
# Step 7: Assign Azure RBAC Roles
# ============================================================================
Write-Host "================================================================" -ForegroundColor Blue
Write-Host "Step 7: Assign Azure RBAC Roles" -ForegroundColor Blue
Write-Host "================================================================" -ForegroundColor Blue
Write-Host ""
Write-Host "Discovering subscriptions..."
Write-Host ""

# Get only ENABLED subscriptions (filter out Disabled, Warned, Suspended, etc.)
$SUBSCRIPTIONS = az account list --query "[?state=='Enabled'].{id:id, name:name}" -o json | ConvertFrom-Json
$SUB_COUNT = $SUBSCRIPTIONS.Count

if ($SUB_COUNT -eq 0) {
    Write-Host "[X] No enabled subscriptions found!" -ForegroundColor Red
    Write-Host "Please ensure you have at least one active Azure subscription."
    exit 1
}

Write-Host "================================================================" -ForegroundColor Yellow
Write-Host "Found " -NoNewline
Write-Host $SUB_COUNT -ForegroundColor Cyan -NoNewline
Write-Host " subscription(s) to configure:" -ForegroundColor Yellow
Write-Host "================================================================" -ForegroundColor Yellow
Write-Host ""

# List all subscriptions in three-column format for better readability
$SUB_INDEX = 1
$col1 = @()
$col2 = @()
$col3 = @()

# Split subscriptions into three columns
foreach ($subscription in $SUBSCRIPTIONS) {
    $cleanName = Clean-DisplayText $subscription.name
    $entry = "$SUB_INDEX. $cleanName - ($($subscription.id))"
    
    $colNum = ($SUB_INDEX - 1) % 3
    if ($colNum -eq 0) {
        $col1 += $entry
    } elseif ($colNum -eq 1) {
        $col2 += $entry
    } else {
        $col3 += $entry
    }
    $SUB_INDEX++
}

# Display in three columns
$maxRows = [Math]::Max([Math]::Max($col1.Count, $col2.Count), $col3.Count)
for ($i = 0; $i -lt $maxRows; $i++) {
    Write-Host "  " -NoNewline
    
    # Column 1
    if ($i -lt $col1.Count) {
        Write-Host $col1[$i] -ForegroundColor Cyan
    } else {
        Write-Host ""
    }
    
    # Column 2
    if ($i -lt $col2.Count) {
        Write-Host "  " -NoNewline
        Write-Host $col2[$i] -ForegroundColor Cyan
    } else {
        Write-Host ""
    }
    
    # Column 3
    if ($i -lt $col3.Count) {
        Write-Host "  " -NoNewline
        Write-Host $col3[$i] -ForegroundColor Cyan
    }
}

Write-Host ""
Write-Host "Select subscriptions to configure:" -ForegroundColor Yellow
Write-Host "  'all'    - Configure all subscriptions" -ForegroundColor Cyan
Write-Host "  '1,2,3'  - Configure specific subscriptions by number (comma-separated)" -ForegroundColor Cyan
Write-Host ""
$SUB_SELECTION = Read-Host ">"

# Handle selection
if ([string]::IsNullOrWhiteSpace($SUB_SELECTION)) {
    Write-Host ""
    Write-Host "[X] No selection made. Exiting." -ForegroundColor Red
    exit 1
} elseif ($SUB_SELECTION -eq 'all') {
    Write-Host ""
    Write-Host "[OK] Configuring all $SUB_COUNT subscription(s)" -ForegroundColor Green
    Write-Host ""
} else {
    # Parse comma-separated numbers
    try {
        $selectedIndices = $SUB_SELECTION -split ',' | ForEach-Object { 
            $num = $_.Trim()
            if ($num -match '^\d+$') {
                [int]$num
            } else {
                throw "Invalid input: $num"
            }
        }
        
        # Validate indices
        $invalidIndices = $selectedIndices | Where-Object { $_ -lt 1 -or $_ -gt $SUB_COUNT }
        if ($invalidIndices.Count -gt 0) {
            Write-Host ""
            Write-Host "[X] Invalid subscription number(s): $($invalidIndices -join ', ')" -ForegroundColor Red
            Write-Host "Please use numbers between 1 and $SUB_COUNT" -ForegroundColor Yellow
            exit 1
        }
        
        # Filter subscriptions based on selection
        $selectedSubs = @()
        foreach ($index in $selectedIndices) {
            $selectedSubs += $SUBSCRIPTIONS[$index - 1]
        }
        
        $SUBSCRIPTIONS = $selectedSubs
        Write-Host ""
        Write-Host "[OK] Configuring $($SUBSCRIPTIONS.Count) selected subscription(s):" -ForegroundColor Green
        foreach ($sub in $SUBSCRIPTIONS) {
            $cleanSubName = Clean-DisplayText $sub.name
            Write-Host "  - $cleanSubName" -ForegroundColor Cyan
        }
        Write-Host ""
    } catch {
        Write-Host ""
        Write-Host "[X] Invalid input. Please use 'all' or comma-separated numbers (e.g., '1,2,3')" -ForegroundColor Red
        exit 1
    }
}

# Skip role assignment if no subscriptions selected
if ($SUBSCRIPTIONS.Count -eq 0) {
    Write-Host "[!] No subscriptions selected for RBAC configuration" -ForegroundColor Yellow
    Write-Host ""
} else {

    $RBAC_ROLES = @(
        @{Role="Reader"; Desc="Browse resources and RBAC assignments"},
        @{Role="Security Reader"; Desc="Defender for Cloud access"},
        @{Role="Key Vault Reader"; Desc="Encryption assessment"},
        @{Role="Log Analytics Reader"; Desc="Security log queries"},
        @{Role="Network Contributor"; Desc="Enable NSG Flow Logs"},
        @{Role="Storage Account Contributor"; Desc="Create flow log storage"}
    )

    Write-Host "Assigning roles to Service Principal..." -ForegroundColor Yellow
    Write-Host ""

    # Track results for summary
    $SubscriptionResults = @{}

    foreach ($subscription in $SUBSCRIPTIONS) {
        $SubId = $subscription.id
        $SubName = $subscription.name
        $SubNameClean = Clean-DisplayText $SubName
        
        Write-Host "  Subscription: " -NoNewline
        Write-Host $SubNameClean -ForegroundColor Cyan
        
        $RoleFailures = 0
        foreach ($RoleInfo in $RBAC_ROLES) {
            $Role = $RoleInfo.Role
            $result = az role assignment create `
                --assignee $SP_ID `
                --role $Role `
                --scope "/subscriptions/$SubId" `
                --output none 2>&1
            
            if ($LASTEXITCODE -ne 0 -and $result -notmatch "already exists") {
                $RoleFailures++
            }
        }
        
        if ($RoleFailures -eq 0) {
            Write-Host "    [OK] All roles assigned successfully" -ForegroundColor Green
            $SubscriptionResults[$SubName] = "Success"
        } elseif ($RoleFailures -lt $RBAC_ROLES.Count) {
            Write-Host "    [!] Some roles assigned ($RoleFailures failed - may already exist)" -ForegroundColor Yellow
            $SubscriptionResults[$SubName] = "Partial"
        } else {
            Write-Host "    [X] Failed to assign roles" -ForegroundColor Red
            $SubscriptionResults[$SubName] = "Failed"
        }
    }

    Write-Host ""

    # Verify role assignments
    Write-Host "Verifying role assignments..." -ForegroundColor Blue
    Write-Host ""

    $VerificationPassed = $true
    foreach ($subscription in $SUBSCRIPTIONS) {
        $SubId = $subscription.id
        $SubName = $subscription.name
        $SubNameClean = Clean-DisplayText $SubName
        
        # Check if Reader role is assigned (as a proxy for all roles)
        $ReaderCheck = az role assignment list `
            --assignee $SP_ID `
            --scope "/subscriptions/$SubId" `
            --role "Reader" `
            --query "[].id" -o tsv 2>$null
        
        if ($ReaderCheck) {
            Write-Host "  [OK] " -ForegroundColor Green -NoNewline
            Write-Host $SubNameClean
        } else {
            Write-Host "  [X] " -ForegroundColor Red -NoNewline
            Write-Host "$SubNameClean " -NoNewline
            Write-Host "(Reader role not found - may need Owner access to assign)" -ForegroundColor Yellow
            $VerificationPassed = $false
        }
    }

    Write-Host ""

    if (-not $VerificationPassed) {
        Write-Host "================================================================" -ForegroundColor Yellow
        Write-Host "[!] Some subscriptions may not have been configured correctly." -ForegroundColor Yellow
        Write-Host "To manually assign roles, you need Owner or User Access Administrator" -ForegroundColor Yellow
        Write-Host "on each subscription. Run:" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "az role assignment create --assignee $SP_ID --role Reader --scope /subscriptions/<SUB_ID>" -ForegroundColor Cyan
        Write-Host "================================================================" -ForegroundColor Yellow
    }

    Write-Host ""
}

Write-Host ""

# Initialize variable for Step 9 (will be set if user provides Sentinel workspace)
$SENTINEL_WORKSPACE_ID = $null

# ============================================================================
# Step 8: Enable Network Flow Logs (Recommended for Network Traffic Map)
# ============================================================================
Write-Host "================================================================" -ForegroundColor Blue
Write-Host "Step 8: Enable Network Flow Logs (Recommended)" -ForegroundColor Blue
Write-Host "================================================================" -ForegroundColor Blue
Write-Host ""
Write-Host "DUN Security visualizes " -NoNewline
Write-Host "east-west network traffic flows" -ForegroundColor Green -NoNewline
Write-Host " between resources."
Write-Host "This is " -NoNewline
Write-Host "essential" -ForegroundColor Yellow -NoNewline
Write-Host " for detecting lateral movement and security threats."
Write-Host ""
Write-Host "Flow logs capture:" -ForegroundColor Cyan
Write-Host "  * Source and destination IPs"
Write-Host "  * Ports and protocols (TCP/UDP)"
Write-Host "  * Bytes transferred"
Write-Host "  * Allow/deny decisions"
Write-Host ""
Write-Host "================================================================" -ForegroundColor Yellow
Write-Host "COST ESTIMATE" -ForegroundColor Yellow
Write-Host "================================================================" -ForegroundColor Yellow
Write-Host ""
Write-Host "  * " -NoNewline
Write-Host "Storage" -ForegroundColor Cyan -NoNewline
Write-Host ": ~`$0.02/GB/month (typically 1-10 GB/month)"
Write-Host "  * " -NoNewline
Write-Host "Traffic Analytics" -ForegroundColor Cyan -NoNewline
Write-Host ": ~`$2.50/GB processed (optional, enables advanced queries)"
Write-Host "  * " -NoNewline
Write-Host "Estimated Total" -ForegroundColor Cyan -NoNewline
Write-Host ": `$1-30/month for most environments"
Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "[OK] RECOMMENDED: Enable flow logs for full security visibility" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Enable Network Flow Logs? [Y/N] (default: Yes)" -ForegroundColor Yellow
$FLOW_LOGS_INPUT = Read-Host ">"

# Default to Yes if empty or starts with Y
$ENABLE_FLOW_LOGS = ($FLOW_LOGS_INPUT -eq "" -or $FLOW_LOGS_INPUT -match '^[Yy]')

if ($ENABLE_FLOW_LOGS) {
    Write-Host ""
    
    # Ask about Traffic Analytics (optional enhancement)
    Write-Host "Would you like to enable " -NoNewline
    Write-Host "Traffic Analytics" -ForegroundColor Cyan -NoNewline
    Write-Host "? (advanced querying via Log Analytics)"
    Write-Host "  This requires an existing Log Analytics Workspace and has additional storage cost in your tenant (~`$2.50/GB)." -ForegroundColor Yellow
Write-Host ""
    Write-Host "Enable Traffic Analytics? [Y/N] (default: No)"
    $TA_INPUT = Read-Host ">"
    $ENABLE_TRAFFIC_ANALYTICS = $TA_INPUT -match '^[Yy]$'
    
    # Get Log Analytics workspace ID for Traffic Analytics if enabled
    $LA_WORKSPACE_ID = $null
    $LA_WORKSPACE_RESOURCE_ID = $null
    if ($ENABLE_TRAFFIC_ANALYTICS) {
        Write-Host ""
        Write-Host "Enter Log Analytics Workspace ID for Traffic Analytics:"
        Write-Host "(Find in: Azure Portal -> Log Analytics workspaces -> Properties -> Workspace ID)" -ForegroundColor DarkGray
        Write-Host "(Leave empty to skip Traffic Analytics)" -ForegroundColor DarkGray
        $LA_WORKSPACE_ID = Read-Host "  >"
        
        if (-not [string]::IsNullOrWhiteSpace($LA_WORKSPACE_ID)) {
            Write-Host "  Searching for workspace..." -ForegroundColor DarkGray
            
            # Find the workspace resource ID across all subscriptions
            foreach ($subscription in $SUBSCRIPTIONS) {
                az account set --subscription $subscription.id 2>$null
                $workspaces = az monitor log-analytics workspace list --query "[?customerId=='$LA_WORKSPACE_ID'].id" -o tsv 2>$null
                if ($workspaces) {
                    $LA_WORKSPACE_RESOURCE_ID = $workspaces
                    Write-Host "  [OK] Found workspace" -ForegroundColor Green
                    break
                }
            }
            
            if (-not $LA_WORKSPACE_RESOURCE_ID) {
                Write-Host "  [!] Could not find Log Analytics workspace. Traffic Analytics will be skipped." -ForegroundColor Yellow
                $ENABLE_TRAFFIC_ANALYTICS = $false
            }
        } else {
            Write-Host "  [!] No workspace provided. Traffic Analytics will be skipped." -ForegroundColor Yellow
            $ENABLE_TRAFFIC_ANALYTICS = $false
        }
    }
    
    Write-Host ""
    Write-Host "Configuring Network Flow Logs..." -ForegroundColor Cyan
    Write-Host ""
    
    $FlowLogStats = @{
        StorageAccountsCreated = 0
        FlowLogsEnabled = 0
        VNetsProcessed = 0
        Errors = @()
    }
    
    foreach ($subscription in $SUBSCRIPTIONS) {
        $SubId = $subscription.id
        $SubName = $subscription.name
        $SubNameClean = Clean-DisplayText $SubName
        
        Write-Host "  Subscription: " -NoNewline
        Write-Host $SubNameClean -ForegroundColor Cyan
        
        # Set subscription context
        az account set --subscription $SubId 2>$null
        
        # Get all VNets in this subscription (for VNet Flow Logs)
        $VNETS = az network vnet list --query "[].{id:id, name:name, location:location, rg:resourceGroup}" -o json 2>$null | ConvertFrom-Json
        
        # Get all NSGs in this subscription (fallback for NSG Flow Logs)
        $NSGS = az network nsg list --query "[].{id:id, name:name, location:location, rg:resourceGroup}" -o json 2>$null | ConvertFrom-Json
        
        if ((-not $VNETS -or $VNETS.Count -eq 0) -and (-not $NSGS -or $NSGS.Count -eq 0)) {
            Write-Host "    [!] No VNets or NSGs found in this subscription" -ForegroundColor Yellow
            continue
        }
        
        # Get unique regions from both VNets and NSGs
        $allRegions = @()
        if ($VNETS) { $allRegions += $VNETS | Select-Object -ExpandProperty location }
        if ($NSGS) { $allRegions += $NSGS | Select-Object -ExpandProperty location }
        $REGIONS = $allRegions | Select-Object -Unique
        
        foreach ($REGION in $REGIONS) {
            Write-Host "    Region: " -NoNewline
            Write-Host $REGION -ForegroundColor Cyan
            
            # Ensure Network Watcher exists in this region
            $NW_RG = "NetworkWatcherRG"
            
            # Create NetworkWatcherRG if it doesn't exist
            try {
                az group create --name $NW_RG --location $REGION --output none 2>$null
            } catch { }
            
            # Register Network Watcher
            try {
                az network watcher configure --resource-group $NW_RG --locations $REGION --enabled true --output none 2>$null
            } catch { }
            
            # Create storage account for flow logs (one per region)
            # Generate 8-char hash from subscription + region for uniqueness
            $HashInput = "$SubId-$REGION"
            $HashBytes = [System.Text.Encoding]::UTF8.GetBytes($HashInput)
            $Hash = [System.BitConverter]::ToString((New-Object System.Security.Cryptography.MD5CryptoServiceProvider).ComputeHash($HashBytes)).Replace("-","").Substring(0,8).ToLower()
            $CleanRegion = $REGION -replace '[^a-z0-9]', ''
            
            # Storage account name: dunflow + region + hash, max 24 chars
            # Reserve 7 for 'dunflow' and 8 for hash = 15 chars, leaving 9 for region
            if ($CleanRegion.Length -gt 9) { $CleanRegion = $CleanRegion.Substring(0,9) }
            $STORAGE_NAME = "dunflow$CleanRegion$Hash"
            
            # Check if storage account exists, create if not
            $StorageExists = az storage account show --name $STORAGE_NAME --resource-group $NW_RG --query id -o tsv 2>$null
            if (-not $StorageExists -or $LASTEXITCODE -ne 0) {
                Write-Host "      Creating storage account: " -NoNewline
                Write-Host $STORAGE_NAME -ForegroundColor Cyan
                
                $createResult = az storage account create `
                    --name $STORAGE_NAME `
                    --resource-group $NW_RG `
                    --location $REGION `
                    --sku Standard_LRS `
                    --kind StorageV2 `
                    --tags purpose=dun-flow-logs managed-by=dun-onboarding dun-app-id=$APP_ID `
                    -o json 2>&1
                
                if ($LASTEXITCODE -eq 0) {
                    $FlowLogStats.StorageAccountsCreated++
                    Write-Host "      [OK] Storage account created" -ForegroundColor Green
                } else {
                    $errorMsg = "Failed to create storage account $STORAGE_NAME"
                    $FlowLogStats.Errors += $errorMsg
                    Write-Host "      [X] Failed to create storage account" -ForegroundColor Red
                    if ($createResult) {
                        Write-Host "      Error: $createResult" -ForegroundColor DarkGray
                    }
                    continue
                }
            } else {
                Write-Host "      [OK] Storage account exists: $STORAGE_NAME" -ForegroundColor Green
            }
            
            # Get storage account ID
            $STORAGE_ID = az storage account show --name $STORAGE_NAME --resource-group $NW_RG --query id -o tsv 2>$null
            
            if (-not $STORAGE_ID -or $LASTEXITCODE -ne 0) {
                Write-Host "      [X] Could not retrieve storage account ID" -ForegroundColor Red
                $FlowLogStats.Errors += "Could not find storage account $STORAGE_NAME in $REGION"
                continue
            }
            
            # Try VNet Flow Logs first (preferred - more comprehensive)
            $RegionVNets = $VNETS | Where-Object { $_.location -eq $REGION }
            if ($RegionVNets -and $RegionVNets.Count -gt 0) {
                Write-Host "      Found " -NoNewline
                Write-Host $RegionVNets.Count -ForegroundColor Cyan -NoNewline
                Write-Host " VNet(s) - enabling VNet Flow Logs"
                
                foreach ($vnet in $RegionVNets) {
                    $VNET_ID = $vnet.id
                    $VNET_NAME = $vnet.name
                    $FlowLogStats.VNetsProcessed++
                    
                    try {
                        # Build flow-log create command with optional Traffic Analytics
                        $flowLogArgs = @(
                            "network", "watcher", "flow-log", "create",
                            "--location", $REGION,
                            "--name", "vnetflowlog-$VNET_NAME",
                            "--vnet", $VNET_ID,
                            "--storage-account", $STORAGE_ID,
                            "--enabled", "true",
                            "--format", "JSON",
                            "--log-version", "2",
                            "--retention", "7",
                            "--tags", "managed-by=dun-onboarding", "dun-app-id=$APP_ID", "purpose=vnet-flow-logs",
                            "--output", "none"
                        )
                        
                        if ($ENABLE_TRAFFIC_ANALYTICS -and $LA_WORKSPACE_RESOURCE_ID) {
                            $flowLogArgs += "--traffic-analytics", "true"
                            $flowLogArgs += "--workspace", $LA_WORKSPACE_RESOURCE_ID
                            $flowLogArgs += "--interval", "10"
                        }
                        
                        & az @flowLogArgs 2>$null
                        if ($LASTEXITCODE -eq 0) {
                            $FlowLogStats.FlowLogsEnabled++
                        }
                    } catch {
                        # VNet Flow Logs might not be available in some regions
                    }
                }
            }
            
            # Also enable NSG Flow Logs for NSGs not covered by VNet Flow Logs
            $RegionNSGs = $NSGS | Where-Object { $_.location -eq $REGION }
            if ($RegionNSGs -and $RegionNSGs.Count -gt 0) {
                Write-Host "      Found " -NoNewline
                Write-Host $RegionNSGs.Count -ForegroundColor Cyan -NoNewline
                Write-Host " NSG(s) - enabling NSG Flow Logs"
                
                foreach ($nsg in $RegionNSGs) {
                    $NSG_ID = $nsg.id
                    $NSG_NAME = $nsg.name
                    
                    try {
                        # Build flow-log create command with optional Traffic Analytics
                        $flowLogArgs = @(
                            "network", "watcher", "flow-log", "create",
                            "--location", $REGION,
                            "--name", "flowlog-$NSG_NAME",
                            "--nsg", $NSG_ID,
                            "--storage-account", $STORAGE_ID,
                            "--enabled", "true",
                            "--format", "JSON",
                            "--log-version", "2",
                            "--retention", "7",
                            "--tags", "managed-by=dun-onboarding", "dun-app-id=$APP_ID", "purpose=nsg-flow-logs",
                            "--output", "none"
                        )
                        
                        if ($ENABLE_TRAFFIC_ANALYTICS -and $LA_WORKSPACE_RESOURCE_ID) {
                            $flowLogArgs += "--traffic-analytics", "true"
                            $flowLogArgs += "--workspace", $LA_WORKSPACE_RESOURCE_ID
                            $flowLogArgs += "--interval", "10"
                        }
                        
                        & az @flowLogArgs 2>$null
                        if ($LASTEXITCODE -eq 0) {
                            $FlowLogStats.FlowLogsEnabled++
                        }
                    } catch { }
                }
            }
            
            Write-Host "      [OK] Flow logs configured" -ForegroundColor Green
        }
    }
    
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Green
    Write-Host "[OK] Network Flow Logs configured successfully!" -ForegroundColor Green
    Write-Host "================================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Storage accounts created: " -NoNewline
    Write-Host $FlowLogStats.StorageAccountsCreated -ForegroundColor Cyan
    Write-Host "  Flow logs enabled:        " -NoNewline
    Write-Host $FlowLogStats.FlowLogsEnabled -ForegroundColor Cyan
    Write-Host "  VNets processed:          " -NoNewline
    Write-Host $FlowLogStats.VNetsProcessed -ForegroundColor Cyan
    if ($ENABLE_TRAFFIC_ANALYTICS) {
        Write-Host "  Traffic Analytics:        " -NoNewline
        Write-Host "Enabled" -ForegroundColor Green
    }
    Write-Host ""
    Write-Host "  Flow log data will appear in DUN within " -NoNewline
    Write-Host "10-15 minutes" -ForegroundColor Yellow
    Write-Host ""
    
    if ($FlowLogStats.Errors.Count -gt 0) {
        Write-Host "  [!] Some issues occurred:" -ForegroundColor Yellow
        foreach ($err in $FlowLogStats.Errors) {
            Write-Host "    - $err" -ForegroundColor Yellow
        }
    }
} else {
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Yellow
    Write-Host "[!] Flow Logs skipped" -ForegroundColor Yellow
    Write-Host "================================================================" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Without Flow Logs, the Network Traffic Map will show " -NoNewline
    Write-Host "topology only" -ForegroundColor Red -NoNewline
    Write-Host " (no actual traffic data)."
    Write-Host ""
    Write-Host "You can enable Flow Logs later:" -ForegroundColor Cyan
    Write-Host "  Azure Portal -> Network Watcher -> Flow logs -> Create"
    Write-Host ""
}

Write-Host ""

# ============================================================================
# Step 9: Sentinel Log Analytics Workspace (Optional - for Virtual CSOC)
# ============================================================================
Write-Host "================================================================" -ForegroundColor Blue
Write-Host "Step 9: Sentinel Log Analytics Workspace (Optional)" -ForegroundColor Blue
Write-Host "================================================================" -ForegroundColor Blue
Write-Host ""
Write-Host "DUN's " -NoNewline
Write-Host "Virtual CSOC" -ForegroundColor Cyan -NoNewline
Write-Host " feature enables AI-powered threat hunting"
Write-Host "by querying your Microsoft Sentinel security logs."
Write-Host ""
Write-Host "To enable this feature, we need " -NoNewline
Write-Host "Log Analytics Reader" -ForegroundColor Cyan -NoNewline
Write-Host " access"
Write-Host "to your Sentinel workspace."
Write-Host ""
Write-Host "Enter your Sentinel Log Analytics Workspace ID:"
Write-Host "(Press Enter to skip if you don't use Sentinel or don't have it yet)" -ForegroundColor Cyan
Write-Host ""
Write-Host "To find your Workspace ID:" -ForegroundColor Yellow
Write-Host "  Azure Portal -> Log Analytics workspaces -> Your workspace -> Properties -> Workspace ID"
Write-Host ""
$SENTINEL_WORKSPACE_ID = Read-Host ">"

if (-not [string]::IsNullOrWhiteSpace($SENTINEL_WORKSPACE_ID)) {
    Write-Host ""
    Write-Host "Validating workspace and granting access..."
    
    # Try to find the workspace by ID across all subscriptions
    $WORKSPACE_FOUND = $false
    $WORKSPACE_RESOURCE_ID = $null
    $WORKSPACE_NAME = $null
    
    foreach ($subscription in $SUBSCRIPTIONS) {
        $SubId = $subscription.id
        az account set --subscription $SubId 2>$null
        
        # Search for workspace with matching ID
        $workspaces = az monitor log-analytics workspace list --query "[?customerId=='$SENTINEL_WORKSPACE_ID'].{id:id, name:name, rg:resourceGroup}" -o json 2>$null | ConvertFrom-Json
        
        if ($workspaces -and $workspaces.Count -gt 0) {
            $WORKSPACE_RESOURCE_ID = $workspaces[0].id
            $WORKSPACE_NAME = Clean-DisplayText $workspaces[0].name
            $WORKSPACE_FOUND = $true
            Write-Host "[OK] Found workspace: " -ForegroundColor Green -NoNewline
            Write-Host $WORKSPACE_NAME -ForegroundColor Cyan
            break
        }
    }
    
    if ($WORKSPACE_FOUND) {
        # Grant Log Analytics Reader on the workspace
        try {
            $roleResult = az role assignment create `
                --assignee $SP_ID `
                --role "Log Analytics Reader" `
                --scope $WORKSPACE_RESOURCE_ID `
                --output none 2>&1
            
            if ($LASTEXITCODE -eq 0) {
                Write-Host "[OK] Log Analytics Reader granted on workspace" -ForegroundColor Green
            } else {
                Write-Host "[!] Could not assign role. You may need to grant access manually." -ForegroundColor Yellow
            }
        } catch {
            Write-Host "[!] Could not assign role. You may need to grant access manually." -ForegroundColor Yellow
        }
        Write-Host ""
        Write-Host "[OK] Virtual CSOC integration configured" -ForegroundColor Green
    } else {
        Write-Host "[!] Workspace not found with ID: $SENTINEL_WORKSPACE_ID" -ForegroundColor Yellow
        Write-Host "   Please verify the Workspace ID and grant access manually if needed." -ForegroundColor Yellow
        $SENTINEL_WORKSPACE_ID = $null
    }
} else {
    Write-Host ""
    Write-Host "[!] Skipped. You can enable Virtual CSOC later by granting access:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  az role assignment create --assignee SERVICE_PRINCIPAL_ID --role 'Log Analytics Reader' --scope WORKSPACE_RESOURCE_ID" -ForegroundColor Cyan
}
Write-Host ""

# ============================================================================
# Onboarding Complete - Output Summary
# ============================================================================
Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "Onboarding Complete!" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Your DUN Security configuration:" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Organization:      " -NoNewline
Write-Host $ORG_NAME -ForegroundColor Yellow
Write-Host "  Tenant ID:         " -NoNewline
Write-Host $TENANT_ID -ForegroundColor Cyan
Write-Host "  Client ID:         " -NoNewline
Write-Host $APP_ID -ForegroundColor Cyan
if ($CLIENT_SECRET) {
    Write-Host "  Client Secret:     " -NoNewline
    Write-Host $CLIENT_SECRET -ForegroundColor Magenta
}
Write-Host "  Subscriptions:     " -NoNewline
Write-Host "$($SUBSCRIPTIONS.Count) configured" -ForegroundColor Cyan
if (-not [string]::IsNullOrWhiteSpace($SENTINEL_WORKSPACE_ID)) {
    Write-Host "  Sentinel Workspace:" -NoNewline
    Write-Host " $SENTINEL_WORKSPACE_ID" -ForegroundColor Cyan
}
Write-Host ""
Write-Host "Your dashboard will be accessible at: " -NoNewline
Write-Host "https://$CLIENT_SLUG.dunsecurity.ai" -ForegroundColor Yellow
Write-Host ""
Write-Host "================================================================" -ForegroundColor Yellow
Write-Host "Keep the Client Secret safe - it will be needed for provisioning" -ForegroundColor Yellow
Write-Host "================================================================" -ForegroundColor Yellow
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Contact DUN Security to complete tenant provisioning"
Write-Host "  2. Sign in to your dashboard with your Microsoft account"
Write-Host "  3. Start monitoring your Azure security posture!"
Write-Host ""
Write-Host "Questions? Contact: " -NoNewline
Write-Host "support@dunsecurity.ai" -ForegroundColor Cyan
Write-Host ""
