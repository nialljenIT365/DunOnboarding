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

if ($IsCloudShell -eq "False") {

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