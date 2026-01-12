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
# Helper function to return a boolen True/Falue check if the logged in User is Global Admin
function Test-GlobalAdminActive {
  # Global Administrator roleDefinitionId in Microsoft Graph
  $gaRoleDefinitionId = "62e90394-69f5-4237-9190-012177145e10"
  $meId = az ad signed-in-user show --query id -o tsv

  if (-not $meId) {
    Warn "Could not resolve the signed-in user's Entra ID objectId, so Global Administrator status could not be validated."
    return $false
  }

  try {
    # Active role assignments (covers permanent assignment + PIM activation)
    $uri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=principalId eq '$meId' and roleDefinitionId eq '$gaRoleDefinitionId'&`$select=id"
    $json = (Run-Az @("rest","--method","GET","--uri",$uri,"-o","json")).Output
    $resp = if ($json) { $json | ConvertFrom-Json } else { $null }

    $isActive = ($resp -and $resp.value -and $resp.value.Count -gt 0)

    if ($isActive) {
      return $true
    } else {
      return $false
    }
  }
  catch {
    Warn "Could not query Microsoft Graph to validate Global Administrator status."
    Warn "If you use PIM, ensure the role is activated; otherwise you may not have rights to read role assignments."
    return $false
  }
}

# ============================================================================
# Introduction
# ============================================================================

Write-Host ""
Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                                                                ║" -ForegroundColor Cyan
Write-Host "║           🏰 DÚN Security - Azure Onboarding                   ║" -ForegroundColor Cyan
Write-Host "║                                                                ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
Write-Host "Welcome to DÚN Security!" -ForegroundColor Blue
Write-Host ""
Write-Host "This script will configure your Azure tenant to allow DÚN Security"
Write-Host "to perform continuous security monitoring and compliance tracking."
Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Yellow
Write-Host "What will this script do?" -ForegroundColor Blue
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Yellow
Write-Host ""
Write-Host "1. " -NoNewline; Write-Host "Create an App Registration" -ForegroundColor Green -NoNewline; Write-Host " in your Azure AD"
Write-Host "   └─ This is the identity DÚN will use for authentication"
Write-Host ""
Write-Host "2. " -NoNewline; Write-Host "Create a Service Principal" -ForegroundColor Green
Write-Host "   └─ The service account that performs security scans"
Write-Host ""
Write-Host "3. " -NoNewline; Write-Host "Grant Microsoft Graph API Permissions" -ForegroundColor Green
Write-Host ""
Write-Host "   " -ForegroundColor DarkGray -NoNewline; Write-Host "Read-Only (for security scanning):" -ForegroundColor Yellow
Write-Host "   " -NoNewline; Write-Host "Directory.Read.All" -ForegroundColor Cyan -NoNewline; Write-Host "                   - Read apps and service principals"
Write-Host "   " -NoNewline; Write-Host "Application.Read.All" -ForegroundColor Cyan -NoNewline; Write-Host "                 - Audit app registrations"
Write-Host "   " -NoNewline; Write-Host "RoleManagement.Read.All" -ForegroundColor Cyan -NoNewline; Write-Host "              - Detect privileged access"
Write-Host "   " -NoNewline; Write-Host "User.Read.All" -ForegroundColor Cyan -NoNewline; Write-Host "                        - Build identity graph"
Write-Host "   " -NoNewline; Write-Host "Policy.Read.All" -ForegroundColor Cyan -NoNewline; Write-Host "                      - Audit Conditional Access policies"
Write-Host "   " -NoNewline; Write-Host "AuditLog.Read.All" -ForegroundColor Cyan -NoNewline; Write-Host "                    - Analyze sign-in activity & policy changes"
Write-Host "   " -NoNewline; Write-Host "Reports.Read.All" -ForegroundColor Cyan -NoNewline; Write-Host "                     - Check MFA coverage"
Write-Host "   " -NoNewline; Write-Host "UserAuthenticationMethod.Read.All" -ForegroundColor Cyan -NoNewline; Write-Host "    - Read MFA methods per user"
Write-Host "   " -NoNewline; Write-Host "IdentityRiskyUser.Read.All" -ForegroundColor Cyan -NoNewline; Write-Host "           - Detect risky users (requires P2)"
Write-Host ""
Write-Host "4. " -NoNewline; Write-Host "Assign Azure RBAC Roles" -ForegroundColor Green -NoNewline; Write-Host " (subscription-level, READ-ONLY)"
Write-Host "   " -NoNewline; Write-Host "Reader" -ForegroundColor Cyan -NoNewline; Write-Host "                  - Browse resources, read RBAC"
Write-Host "   " -NoNewline; Write-Host "Security Reader" -ForegroundColor Cyan -NoNewline; Write-Host "         - Access Defender for Cloud"
Write-Host "   " -NoNewline; Write-Host "Key Vault Reader" -ForegroundColor Cyan -NoNewline; Write-Host "        - Assess encryption posture"
Write-Host "   " -NoNewline; Write-Host "Log Analytics Reader" -ForegroundColor Cyan -NoNewline; Write-Host "    - Query security logs"
Write-Host "   " -NoNewline; Write-Host "Network Contributor" -ForegroundColor Cyan -NoNewline; Write-Host "     - Enable NSG Flow Logs (setup only)"
Write-Host "   " -NoNewline; Write-Host "Storage Contributor" -ForegroundColor Cyan -NoNewline; Write-Host "     - Create flow log storage (setup only)"
Write-Host ""
Write-Host "5. " -NoNewline; Write-Host "Create Client Secret" -ForegroundColor Green -NoNewline; Write-Host " for tenant authentication"
Write-Host "   └─ Used for SSO and API access to your DÚN tenant"
Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Yellow
Write-Host ""
Write-Host "🔐 Security Model" -ForegroundColor Green
Write-Host ""
Write-Host "The service principal has " -NoNewline; Write-Host "READ-ONLY" -ForegroundColor Green -NoNewline; Write-Host " access."
Write-Host "DÚN Security " -NoNewline; Write-Host "cannot" -ForegroundColor Red -NoNewline; Write-Host " modify, delete, or create any resources in your tenant."
Write-Host ""
Write-Host "All permissions are read-only:" -ForegroundColor Yellow
Write-Host "   • Graph API: Read users, groups, apps, policies, and audit logs"
Write-Host "   • Azure RBAC: Read resources, security findings, and configurations"
Write-Host "   • No write permissions are requested"
Write-Host ""
Write-Host "Press Enter to continue, or Ctrl+C to cancel..." -ForegroundColor Yellow
$null = Read-Host
Write-Host ""

# ============================================================================
# Step 1: Check Prerequisites
# ============================================================================
Write-Host "══════════════════════════════════════════════════════════════════" -ForegroundColor Blue
Write-Host "Step 1: Prerequisites Check" -ForegroundColor Blue
Write-Host "══════════════════════════════════════════════════════════════════" -ForegroundColor Blue
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
    Write-Host "✓ Running in Azure Cloud Shell (Azure CLI available)" -ForegroundColor Green
    Write-Host "✓ Cloud Shell sessions are unable to fetch the token required to grant the Graph API Permissions required for the completion of this script." -ForegroundColor Green
    Write-Host "It will be necessary to re-authenticate with the --use-device-code switch, please follow the instructions below to proceed" -ForegroundColor Yellow
    Write-Host ""
    az login --use-device-code --only-show-errors | Out-Null
    Write-Host "✓ Validate if GA Role is Active" -ForegroundColor Green
    $IsGlobalAdminActive = Test-GlobalAdminActive

    if ($IsGlobalAdminActive) {
        Write-Host "✓ GA Role is Active" -ForegroundColor Green
    } else {
        Write-Host "✗ GA Role has not been activated for this account" -ForegroundColor Red
        Write-Host ""
        exit 1
    }

} else {
    if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
        Write-Host "✗ Azure CLI is not installed" -ForegroundColor Red
        Write-Host ""
        Write-Host "Please install Azure CLI first:"
        Write-Host "  Download: https://aka.ms/installazurecliwindows"
        Write-Host "  Or run:   winget install -e --id Microsoft.AzureCLI"
        Write-Host ""
        exit 1
    }

    Write-Host "✓ Running in Local Powershell Context" -ForegroundColor Green
    Write-Host "✓ Azure CLI is installed" -ForegroundColor Green
}

# ============================================================================
# Step 2: Prompt for Organization Name
# ============================================================================
Write-Host "══════════════════════════════════════════════════════════════════" -ForegroundColor Blue
Write-Host "Step 2: Organization Information" -ForegroundColor Blue
Write-Host "══════════════════════════════════════════════════════════════════" -ForegroundColor Blue
Write-Host ""
Write-Host "Please enter your organization name (e.g., " -NoNewline
Write-Host "Acme Corp" -ForegroundColor Cyan -NoNewline
Write-Host ", " -NoNewline
Write-Host "Contoso" -ForegroundColor Cyan -NoNewline
Write-Host "):"

$ORG_NAME = Read-Host ">"

if ([string]::IsNullOrWhiteSpace($ORG_NAME)) {
    Write-Host "✗ Organization name cannot be empty" -ForegroundColor Red
    exit 1
}

$APP_DISPLAY_NAME = "DÚN Security - $ORG_NAME"

# Derive URL-safe slug
$CLIENT_SLUG = $ORG_NAME.ToLower() -replace '[^a-z0-9-]', '-' -replace '-+', '-'
$CLIENT_SLUG = $CLIENT_SLUG.Trim('-')

Write-Host ""
Write-Host "✓ Organization: $ORG_NAME" -ForegroundColor Green
Write-Host "✓ App Name: $APP_DISPLAY_NAME" -ForegroundColor Green
Write-Host "✓ When the onboarding process is complete your dashboard will be accessible at: " -ForegroundColor Green -NoNewline
Write-Host "https://$CLIENT_SLUG.dunsecurity.ai" -ForegroundColor Yellow -NoNewline
Write-Host "" -ForegroundColor Green
Write-Host ""
Write-Host "If you’re happy with the details above, press Enter to continue (or press Ctrl+C to cancel)..." -ForegroundColor Yellow
$null = Read-Host
Write-Host ""

# ============================================================================
# Step 3: Azure Authentication
# ============================================================================
Write-Host "══════════════════════════════════════════════════════════════════" -ForegroundColor Blue
Write-Host "Step 3: Azure Authentication" -ForegroundColor Blue
Write-Host "══════════════════════════════════════════════════════════════════" -ForegroundColor Blue
Write-Host ""
Write-Host "⚠️  Note: You will need Global Administrator or Privileged Role Administrator access" -ForegroundColor Yellow
Write-Host ""
Write-Host "Checking Azure login status..."

if (-not $IsCloudShell) {

    try {
        $account = az account show --query "{id:id, tenantId:tenantId, name:tenantDisplayName, user:user.name}" -o json | ConvertFrom-Json
        Write-Host ""
        Write-Host "✓ Signed in as: $($account.user)" -ForegroundColor Green
        Write-Host ""
        Write-Host "Is this the correct administrator account? (y/n)"
        $confirm = Read-Host ">"

        if ($confirm -notmatch '^[Yy]$') {
            Write-Host ""
            Write-Host "Please sign in with the correct account:" -ForegroundColor Yellow
            az login | Out-Null
            $account = az account show --query "{id:id, tenantId:tenantId, name:tenantDisplayName, user:user.name}" -o json | ConvertFrom-Json
        }
    } catch {
        Write-Host ""
        Write-Host "Please sign in with your administrator account:" -ForegroundColor Yellow
        Write-Host ""
        az login | Out-Null
        $account = az account show --query "{id:id, tenantId:tenantId, name:tenantDisplayName, user:user.name}" -o json | ConvertFrom-Json
    }

    Write-Host "✓ Validate if GA Role is Active" -ForegroundColor Green
    $IsGlobalAdminActive = Test-GlobalAdminActive

    if ($IsGlobalAdminActive) {
        Write-Host "✓ GA Role is Active" -ForegroundColor Green
    } else {
        Write-Host "✗ GA Role has not been activated for this account" -ForegroundColor Red
        Write-Host ""
        exit 1
    }

} else {
    Write-Host "✓ Skipping interactive Azure Authentication step (Cloud Shell handled earlier)" -ForegroundColor Green
}

$TENANT_ID = $account.tenantId
#$SUB_ID = $account.id
$TENANT_NAME = $account.name

Write-Host ""
Write-Host "✓ Authenticated successfully" -ForegroundColor Green
Write-Host ""
Write-Host "  Tenant: " -NoNewline; Write-Host $TENANT_NAME -ForegroundColor Cyan
Write-Host "  Tenant ID: " -NoNewline; Write-Host $TENANT_ID -ForegroundColor Cyan
Write-Host ""