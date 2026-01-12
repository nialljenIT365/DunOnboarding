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

} else {
    Write-Host "✓ Skipping interactive Azure Authentication step (Cloud Shell handled earlier)" -ForegroundColor Green
}

$TENANT_ID = $account.tenantId
$SUB_ID = $account.id
$TENANT_NAME = $account.name

Write-Host ""
Write-Host "✓ Authenticated successfully" -ForegroundColor Green
Write-Host ""
Write-Host "  Tenant: " -NoNewline; Write-Host $TENANT_NAME -ForegroundColor Cyan
Write-Host "  Tenant ID: " -NoNewline; Write-Host $TENANT_ID -ForegroundColor Cyan

Write-Host ""
