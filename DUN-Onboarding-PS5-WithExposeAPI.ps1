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
        Write-Host "Is this the correct administrator account? (y/n)"
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
$TENANT_NAME_CLEAN = $TENANT_NAME -replace [char]0x2013, '-' -replace [char]0x2014, '-' -replace [char]0x00AD, '-' -replace '[^\x20-\x7E]', '-'

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
        $uri = "https://graph.microsoft.com/v1.0/applications/$APP_OBJECT_ID"

        # Fetch existing scopes so we don't overwrite them
        $existingJson = az rest --method GET --uri "$uri`?`$select=api" 2>&1
        $existing = $null
        if ($LASTEXITCODE -eq 0 -and $existingJson) {
            $existing = $existingJson | ConvertFrom-Json
        }

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
            } | ConvertTo-Json -Depth 20 -Compress

            # Use inline JSON to avoid temp file issues
            $patchResult = az rest --method PATCH --uri $uri --headers "Content-Type=application/json" --body $patchBody 2>&1
            
            if ($LASTEXITCODE -eq 0) {
                Write-Host "  [OK] API scope configured for OBO token exchange (user_impersonation)" -ForegroundColor Green
            } else {
                Write-Host "  [!] Could not configure API scope (may require manual setup)" -ForegroundColor Yellow
            }
        }
    }
    catch {
        Write-Host "  [!] Could not configure API scope (may require manual setup)" -ForegroundColor Yellow
        Write-Host "  Error: $_" -ForegroundColor DarkGray
    }
}

Write-Host ""

# ============================================================================
# Next Steps - Add Additional Logic Here
# ============================================================================
# TODO: Add remaining onboarding steps:
# - Create Service Principal
# - Grant Graph API Permissions
# - Assign Azure RBAC Roles
# - Create Client Secret
# - Output credentials
