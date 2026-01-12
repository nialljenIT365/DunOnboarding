<#
.SYNOPSIS
  Removes all Microsoft Entra ID/Azure artifacts created for the DUN Security onboarding, including:
  - App registration configuration (identifier URI + exposed API scope)
  - Service principal and associated client secrets
  - Microsoft Graph application permissions and consent artifacts
  - Azure Service Management delegated consent artifacts
  - Subscription-scope Azure RBAC role assignments

.VERSION
    Version: 1.0.2
    Last Updated: 2026-01-12
    Note: Future version to include artefact removal for Network Flow Logs and Sentinel Log Analytics Workspace artefacts
    Note: Bug fix added for more rebust clean up on previously incomplete runs

.DESCRIPTION
  1) Always runs a DRY RUN first and shows what WOULD be removed.
  2) Prompts you to confirm expectation before deleting anything.
  3) If confirmed, removes artifacts in this order:
        - Client secret(s) on the app registration (displayName == "DUN-SSO-Secret")
        - Service principal object (if present)
        - Microsoft Graph application permissions (requested requiredResourceAccess; appRoleAssignments skipped if SP missing/deleted)
        - Azure Service Management delegated consent grant + requested delegated permission (grant delete is idempotent; 404 ignored)
        - Subscription-scope Azure RBAC role assignments (requires principalId; supports SP override)
        - Exposed API configuration (remove oauth2PermissionScopes value == "user_impersonation"; remove identifierUri api://<APP_ID>)
        - App registration object

.NOTES
  - No parameters
  - No intermediate/temp files
  - No exit/termination (Cloud Shell / IDE friendly)
  - If the Service Principal has already been deleted, you can still clean up RBAC / delegated grants by setting $SP_OBJECT_ID_OVERRIDE.
#>

$ErrorActionPreference = "Stop"

# =====================================================================
# SET THIS: App Registration Application (client) ID (appId)
# - Leave blank to auto-discover by displayName prefix
# =====================================================================
# Application (client) ID / App ID (GUID) format: 32 hexadecimal characters (0-9, a-f) split into 5 groups with hyphens: 8-4-4-4-12
# (e.g. xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx where each x is 0-9 or a-f)
$APP_ID = ""

# OPTIONAL: If the Service Principal (Enterprise App) has already been deleted
# but you still need to remove RBAC role assignments / delegated consent grants,
# set the former SP objectId (principalId) here (GUID format: 8-4-4-4-12 hex characters).
$SP_OBJECT_ID_OVERRIDE = ""

# Prefix used to find the App Registration (displayName starts with)
$APP_NAME_PREFIX = "DUN Security -"

function Info { param([string]$m) Write-Host $m -ForegroundColor Cyan }
function Good { param([string]$m) Write-Host $m -ForegroundColor Green }
function Warn { param([string]$m) Write-Host $m -ForegroundColor Yellow }
function Bad  { param([string]$m) Write-Host $m -ForegroundColor Red }

# =====================================================================
# Output formatting defaults (avoid truncated tables / ellipses)
# =====================================================================
$FormatEnumerationLimit = -1
$PSDefaultParameterValues['Format-Table:Wrap'] = $true
$PSDefaultParameterValues['Format-Table:AutoSize'] = $true   # optional

function Run-Az {
  param([Parameter(Mandatory=$true)][string[]]$Args)

  $prevEap = $ErrorActionPreference
  $ErrorActionPreference = "SilentlyContinue"

  # Prevent native stderr -> PowerShell error records (PowerShell 7+)
  $hadNativePref = $false
  $prevNativePref = $null
  try {
    if (Get-Variable -Name PSNativeCommandUseErrorActionPreference -Scope Global -ErrorAction SilentlyContinue) {
      $hadNativePref = $true
      $prevNativePref = $global:PSNativeCommandUseErrorActionPreference
      $global:PSNativeCommandUseErrorActionPreference = $false
    }
  } catch { }

  $out  = & az @Args 2>&1
  $code = $LASTEXITCODE

  if ($hadNativePref) { $global:PSNativeCommandUseErrorActionPreference = $prevNativePref }
  $ErrorActionPreference = $prevEap

  [pscustomobject]@{
    ExitCode = $code
    Output   = ($out | Out-String).Trim()
  }
}

function Get-GraphToken {
  $res = Run-Az @("account","get-access-token","--resource-type","ms-graph","--query","accessToken","-o","tsv")
  $t = if ($res.ExitCode -eq 0) { $res.Output } else { $null }

  if (-not $t) {
    $res2 = Run-Az @("account","get-access-token","--resource","https://graph.microsoft.com/","--query","accessToken","-o","tsv")
    $t = if ($res2.ExitCode -eq 0) { $res2.Output } else { $null }
  }

  if (-not $t) { throw "Failed to acquire Microsoft Graph access token from Azure CLI." }
  $t.Trim()
}

function Invoke-Graph {
  param(
    [Parameter(Mandatory=$true)][ValidateSet("GET","POST","PATCH","DELETE")][string]$Method,
    [Parameter(Mandatory=$true)][string]$Uri,
    [Parameter(Mandatory=$false)][string]$BodyJson
  )

  $token = Get-GraphToken
  $headers = @{
    Authorization = "Bearer $token"
    "Content-Type" = "application/json"
  }

  try {
    if ($PSBoundParameters.ContainsKey("BodyJson")) {
      return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -Body $BodyJson
    } else {
      return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers
    }
  }
  catch {
    $msg = $_.Exception.Message
    if ($_.Exception.Response -and $_.Exception.Response.GetResponseStream) {
      try {
        $sr = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
        $resp = $sr.ReadToEnd()
        if ($resp) { $msg = "$msg`n$resp" }
      } catch { }
    }
    throw $msg
  }
}

# ============================
# MAIN
# ============================
try {
  # =====================================================================
  # Auto-discover APP_ID (appId/clientId) from App Registration displayName prefix
  # =====================================================================
  $appObjectId = $null
  $AppDisplayName = $null

  if ([string]::IsNullOrWhiteSpace($APP_ID)) {
    Info ("APP_ID not set. Searching App Registrations with displayName prefix: '{0}'..." -f $APP_NAME_PREFIX)

    $apps = @()

    # Prefer Graph (efficient / accurate)
    try {
      $filter = [uri]::EscapeDataString("startswith(displayName,'$APP_NAME_PREFIX')")
      $uri = "https://graph.microsoft.com/v1.0/applications?`$select=id,appId,displayName&`$filter=$filter&`$top=50"

      while ($uri) {
        $resp = Invoke-Graph -Method GET -Uri $uri
        if ($resp.value) { $apps += @($resp.value) }
        $uri = $resp.'@odata.nextLink'
      }
    }
    catch {
      Warn "Graph search for applications failed; falling back to Azure CLI listing (may be slower)."

      $appsRes = Run-Az @(
        "ad","app","list","--all",
        "--query","[?starts_with(displayName, '$APP_NAME_PREFIX')].{displayName:displayName,appId:appId,id:id}",
        "-o","json","--only-show-errors"
      )

      if ($appsRes.ExitCode -eq 0 -and $appsRes.Output) {
        $apps = @($appsRes.Output | ConvertFrom-Json)
      } else {
        $apps = @()
      }
    }

    if (-not $apps -or $apps.Count -eq 0) {
      Warn ("No App Registrations found with displayName starting with '{0}'." -f $APP_NAME_PREFIX)
      Warn "Nothing to do."
      return
    }

    if ($apps.Count -eq 1) {
      $APP_ID = $apps[0].appId
      $appObjectId = $apps[0].id
      $AppDisplayName = $apps[0].displayName
      Good ("Auto-selected app: {0} | appId: {1} | objectId: {2}" -f $AppDisplayName, $APP_ID, $appObjectId)
    }
    else {
      Warn ("Found {0} matching App Registrations. Please select one:" -f $apps.Count)

      $choices = for ($i=0; $i -lt $apps.Count; $i++) {
        [pscustomobject]@{
          Choice      = $i + 1
          DisplayName = $apps[$i].displayName
          AppId       = $apps[$i].appId
          ObjectId    = $apps[$i].id
        }
      }

      $choices | Format-Table -AutoSize

      $sel = Read-Host "Enter the Choice number to use, or press Enter to cancel >"
      if ([string]::IsNullOrWhiteSpace($sel)) {
        Warn "Cancelled. No changes were made."
        return
      }
      if ($sel -notmatch '^\d+$' -or [int]$sel -lt 1 -or [int]$sel -gt $choices.Count) {
        Warn "Invalid selection. No changes were made."
        return
      }

      $picked = $choices[[int]$sel - 1]
      $APP_ID = $picked.AppId
      $appObjectId = $picked.ObjectId
      $AppDisplayName = $picked.DisplayName
      Good ("Selected app: {0} | appId: {1} | objectId: {2}" -f $AppDisplayName, $APP_ID, $appObjectId)
    }
  } else {
    Info ("APP_ID provided: {0}" -f $APP_ID)

    # Try to resolve app displayName + objectId (helps later steps)
    try {
      $appLookup = Invoke-Graph -Method GET -Uri ("https://graph.microsoft.com/v1.0/applications?`$select=id,appId,displayName&`$filter=appId eq '{0}'&`$top=1" -f $APP_ID)
      if ($appLookup.value -and $appLookup.value.Count -gt 0) {
        $appObjectId = $appLookup.value[0].id
        $AppDisplayName = $appLookup.value[0].displayName
      }
    } catch { }
  }

  if ([string]::IsNullOrWhiteSpace($APP_ID)) {
    Bad "APP_ID is empty. Set `$APP_ID at the top of the script or use auto-discovery."
    return
  }

  if ([string]::IsNullOrWhiteSpace($AppDisplayName)) {
    $AppDisplayName = "DUN Security app (displayName unavailable)"
  }

  # =====================================================================
  # Resolve Service Principal (optional) - DO NOT return if missing
  # =====================================================================
  Info "Resolving service principal for appId: $APP_ID"

  $spObjectId = $null
  $spName = $null
  $spPresent = $false

  $spRes = Run-Az @(
    "ad","sp","show","--id",$APP_ID,
    "--query","{displayName:displayName,appId:appId,id:id}",
    "-o","json","--only-show-errors"
  )

  if ($spRes.ExitCode -eq 0 -and -not [string]::IsNullOrWhiteSpace($spRes.Output)) {
    $sp = $spRes.Output | ConvertFrom-Json
    $spObjectId = $sp.id
    $spName = $sp.displayName
    $spPresent = $true
    Good ("Target SP: {0} | appId: {1} | objectId: {2}" -f $spName, $sp.appId, $sp.id)
  }
  elseif (-not [string]::IsNullOrWhiteSpace($SP_OBJECT_ID_OVERRIDE)) {
    $spObjectId = $SP_OBJECT_ID_OVERRIDE.Trim()
    $spName = "$AppDisplayName (SP not found; using override principalId)"
    $spPresent = $false
    Warn "Service principal not found for this appId, but SP_OBJECT_ID_OVERRIDE is set."
    Warn "Will attempt RBAC/grant cleanup using principalId: $spObjectId"
  }
  else {
    $spObjectId = $null
    $spName = "$AppDisplayName (service principal not found)"
    $spPresent = $false
    Warn "Service principal not found for this appId."
    Warn "Continuing with APP-ONLY cleanup (app registration / secrets / requiredResourceAccess / exposed API / app deletion)."
    Warn "RBAC + delegated consent grant cleanup will be skipped because principalId is unknown."
  }

  # Resolve Application OBJECT id (needed for secret removal / exposed API checks)
  if (-not $appObjectId) {
    $appIdRes = Run-Az @("ad","app","show","--id",$APP_ID,"--query","id","-o","tsv","--only-show-errors")
    if ($appIdRes.ExitCode -eq 0 -and $appIdRes.Output) { $appObjectId = $appIdRes.Output.Trim() }
  }

  Warn "This script will FIRST carry out a DRY RUN and show you exactly what it intends to delete."
  Warn "Review the DRY RUN output carefully (secrets, service principal, permissions/consent, RBAC assignments, exposed API settings, and the app registration) before proceeding."
  Warn "If you confirm, deletions will be attempted in this order: client secrets -> service principal (if present) -> Graph permissions -> delegated consent/permission -> RBAC role assignments -> exposed API settings -> app registration."
  Info ""

  # =====================================================================
  # Exposed API configuration targets (identifierUri + oauth2PermissionScopes)
  # =====================================================================
  $ExposeApiIdentifierUri = "api://$APP_ID"
  $ExposeApiScopeValue    = "user_impersonation"

  # =====================================================================
  # Client secret(s) to remove (passwordCredentials with displayName == "DUN-SSO-Secret")
  # =====================================================================
  $SecretDisplayName = "DUN-SSO-Secret"

  # =====================================================================
  # Microsoft Graph application permissions to remove (app roles requested/consented)
  # =====================================================================
  $MS_GRAPH_APPID = "00000003-0000-0000-c000-000000000000"

  $GraphRequiredRoleIds = @(
    "7ab1d382-f21e-4acd-a863-ba3e13f7da61" # Directory.Read.All
    "9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30" # Application.Read.All
    "c7fbd983-d9aa-4fa7-84b8-17382c103bc4" # RoleManagement.Read.All
    "df021288-bdef-4463-88db-98f22de89214" # User.Read.All
    "246dd0d5-5bd0-4def-940b-0421030a5b68" # Policy.Read.All
    "b0afded3-3588-46d8-8b3d-9842eff778da" # AuditLog.Read.All
    "230c1aed-a721-4c5d-9cb4-a90514e508ef" # Reports.Read.All
    "38d9df27-64da-44fd-b7c5-a6fbac20248f" # UserAuthenticationMethod.Read.All
  ) | ForEach-Object { $_.ToLower() } | Select-Object -Unique

  $graphSpRes = Run-Az @("ad","sp","show","--id",$MS_GRAPH_APPID,"--query","id","-o","tsv","--only-show-errors")
  if (-not ($graphSpRes.ExitCode -eq 0 -and $graphSpRes.Output)) { throw "Could not resolve Microsoft Graph service principal object id." }
  $graphSpId = $graphSpRes.Output.Trim()

  # =====================================================================
  # Targets - Azure Service Management API delegated scope
  # =====================================================================
  $AZURE_MGMT_APPID = "797f4846-ba00-4fd7-ba43-dac1f8f63013"
  $scopeValue = "user_impersonation"

  $resourceSpRes = Run-Az @("ad","sp","show","--id",$AZURE_MGMT_APPID,"--query","id","-o","tsv","--only-show-errors")
  if (-not ($resourceSpRes.ExitCode -eq 0 -and $resourceSpRes.Output)) { throw "Could not resolve Azure Service Management API service principal ($AZURE_MGMT_APPID)." }
  $resourceSpId = $resourceSpRes.Output.Trim()

  $userImpRes = Run-Az @("ad","sp","show","--id",$AZURE_MGMT_APPID,"--query","oauth2PermissionScopes[?value=='$scopeValue'].id | [0]","-o","tsv","--only-show-errors")
  $userImpersonationId = if ($userImpRes.ExitCode -eq 0) { $userImpRes.Output } else { $null }

  if (-not $userImpersonationId) {
    $userImpRes2 = Run-Az @("ad","sp","show","--id",$AZURE_MGMT_APPID,"--query","oauth2Permissions[?value=='$scopeValue'].id | [0]","-o","tsv","--only-show-errors")
    $userImpersonationId = if ($userImpRes2.ExitCode -eq 0) { $userImpRes2.Output } else { $null }
  }
  if (-not $userImpersonationId) { throw "Could not resolve scope id for '$scopeValue' on Azure Service Management API." }
  $userImpersonationId = $userImpersonationId.Trim()

  # =====================================================================
  # DRY RUN - Discover current App Registration state
  # =====================================================================
  $appFull = $null
  $SecretsToRemove = @()
  $ExposeApiScopesToRemove = @()
  $ExposeApiIdentifierPresent = $false
  $AppPresent = $false

  Info ("DRY RUN: discovering application, exposed API settings, and client secrets for {0}..." -f $AppDisplayName)

  if ($appObjectId) {
    $AppPresent = $true
    $appFull = Invoke-Graph -Method GET -Uri ("https://graph.microsoft.com/v1.0/applications/{0}?`$select=id,appId,displayName,identifierUris,passwordCredentials,api" -f $appObjectId)

    if ($appFull.passwordCredentials) {
      $SecretsToRemove = @($appFull.passwordCredentials | Where-Object { $_.displayName -eq $SecretDisplayName })
    }

    if ($appFull.identifierUris) {
      $ExposeApiIdentifierPresent = @($appFull.identifierUris) -contains $ExposeApiIdentifierUri
    }

    if ($appFull.api -and $appFull.api.oauth2PermissionScopes) {
      $ExposeApiScopesToRemove = @($appFull.api.oauth2PermissionScopes | Where-Object { $_.value -eq $ExposeApiScopeValue })
    }
  } else {
    Warn "Could not resolve application object id. App registration removal and secret removal will be skipped."
  }

  Info ""
  Info "DRY RUN RESULTS (App registration + exposed API):"
  $step4Findings = @(
    [pscustomobject]@{
      Item    = "App registration object"
      Present = $(if ($AppPresent) { "Yes" } else { "No" })
      Details = $(if ($AppPresent) { "Will delete app registration for appId $APP_ID (objectId $appObjectId)" } else { "Not found / could not resolve." })
    }
    [pscustomobject]@{
      Item    = "Expose API identifierUri"
      Present = $(if ($ExposeApiIdentifierPresent) { "Yes" } else { "No" })
      Details = $(if ($AppPresent) {
        if ($ExposeApiIdentifierPresent) { "Found identifierUri '$ExposeApiIdentifierUri' (will remove)." } else { "IdentifierUri '$ExposeApiIdentifierUri' not present." }
      } else { "Skipped (app not resolved)." })
    }
    [pscustomobject]@{
      Item    = "Expose API oauth2PermissionScope(s)"
      Present = $(if ($ExposeApiScopesToRemove.Count -gt 0) { "Yes" } else { "No" })
      Details = $(if ($AppPresent) {
        if ($ExposeApiScopesToRemove.Count -gt 0) { "Found $($ExposeApiScopesToRemove.Count) scope(s) with value '$ExposeApiScopeValue' (details below)." } else { "No scopes found with value '$ExposeApiScopeValue'." }
      } else { "Skipped (app not resolved)." })
    }
  )
  $step4Findings | Format-Table -AutoSize

  if ($ExposeApiScopesToRemove.Count -gt 0) {
    Info ""
    Info ("ALL matching exposed API scopes (value == '{0}'):" -f $ExposeApiScopeValue)
    $ExposeApiScopesToRemove |
      Select-Object id, value, isEnabled, type, adminConsentDisplayName, userConsentDisplayName |
      Format-Table -AutoSize
  }

  Info ""
  Info "DRY RUN RESULTS (identity objects to be removed): service principal + matching client secrets"
  $step5Findings = @(
    [pscustomobject]@{
      Item    = "Service principal object"
      Present = $(if ($spPresent) { "Yes" } else { "No" })
      Details = $(if ($spPresent) { ("Will delete service principal: {0} (objectId {1})" -f $spName, $spObjectId) } else { "Not present / already deleted. (RBAC/grants only possible if override principalId was provided.)" })
    }
    [pscustomobject]@{
      Item    = "Client secret(s) (passwordCredentials)"
      Present = $(if ($SecretsToRemove.Count -gt 0) { "Yes" } else { "No" })
      Details = $(if ($AppPresent) {
        if ($SecretsToRemove.Count -gt 0) { ("Found {0} secret(s) with displayName '{1}' (details below)." -f $SecretsToRemove.Count, $SecretDisplayName) } else { ("No secrets found with displayName '{0}'." -f $SecretDisplayName) }
      } else { "Skipped (app not resolved)." })
    }
  )
  $step5Findings | Format-Table -AutoSize

  if ($SecretsToRemove.Count -gt 0) {
    Info ""
    Info ("ALL matching secrets for '{0}':" -f $SecretDisplayName)
    $SecretsToRemove |
      Select-Object displayName, keyId, startDateTime, endDateTime |
      Sort-Object endDateTime, keyId |
      Format-Table -AutoSize
  }

  # =====================================================================
  # DRY RUN - Graph permission cleanup discovery
  # =====================================================================
  Info ""
  Info ("DRY RUN: discovering Microsoft Graph application permissions and consent artifacts for {0}..." -f $AppDisplayName)

  $requestedGraphIdsOut = $null
  $reqGraphRes = Run-Az @(
    "ad","app","show","--id",$APP_ID,
    "--query","requiredResourceAccess[?resourceAppId=='$MS_GRAPH_APPID'].resourceAccess[?type=='Role'].id",
    "-o","tsv","--only-show-errors"
  )
  if ($reqGraphRes.ExitCode -eq 0) { $requestedGraphIdsOut = $reqGraphRes.Output }

  $requestedGraphIds = @()
  if ($requestedGraphIdsOut) {
    $requestedGraphIds = @(
      $requestedGraphIdsOut -split "`n" | ForEach-Object { $_.Trim().ToLower() } | Where-Object { $_ }
    ) | Select-Object -Unique
  }

  $requestedGraphToRemove = @($requestedGraphIds | Where-Object { $GraphRequiredRoleIds -contains $_ })

  $graphAssignmentsToRemoveCount = 0
  $matchingGraphAssignments = @()

  if ($spPresent -and $spObjectId) {
    try {
      $graphAssignUri = ("https://graph.microsoft.com/v1.0/servicePrincipals/{0}/appRoleAssignments?`$filter=resourceId eq {1}&`$select=id,appRoleId" -f $spObjectId, $graphSpId)
      $graphAssignments = Invoke-Graph -Method GET -Uri $graphAssignUri

      if ($graphAssignments.value) {
        $matchingGraphAssignments = @(
          $graphAssignments.value | Where-Object {
            $rid = ($_.appRoleId.ToString()).ToLower()
            $GraphRequiredRoleIds -contains $rid
          }
        )
      }
      $graphAssignmentsToRemoveCount = $matchingGraphAssignments.Count
    } catch {
      Warn "Could not enumerate Graph appRoleAssignments for DRY RUN (may require additional Graph permissions)."
      $graphAssignmentsToRemoveCount = 0
      $matchingGraphAssignments = @()
    }
  } else {
    Info "Skipping Graph appRoleAssignments discovery (service principal not present)."
    $graphAssignmentsToRemoveCount = 0
    $matchingGraphAssignments = @()
  }

  $step6Findings = @(
    [pscustomobject]@{
      Item    = "Requested Graph app roles (requiredResourceAccess)"
      Present = $(if ($requestedGraphToRemove.Count -gt 0) { "Yes" } else { "No" })
      Details = $(if ($requestedGraphToRemove.Count -gt 0) { "Found $($requestedGraphToRemove.Count) of $($GraphRequiredRoleIds.Count) required role(s) requested." } else { "None of the required roles are requested." })
    }
    [pscustomobject]@{
      Item    = "Admin-consented Graph app roles (appRoleAssignments)"
      Present = $(if ($graphAssignmentsToRemoveCount -gt 0) { "Yes" } else { "No" })
      Details = $(if (-not $spPresent) { "Skipped (service principal not present)." }
                 elseif ($graphAssignmentsToRemoveCount -gt 0) { "Found $graphAssignmentsToRemoveCount matching appRoleAssignment(s) on the client service principal." }
                 else { "No matching appRoleAssignments found (or could not enumerate)." })
    }
  )

  Info ""
  Info "DRY RUN RESULTS (Microsoft Graph permissions + consent artifacts):"
  $step6Findings | Format-Table -AutoSize

  # =====================================================================
  # DRY RUN - Step 6b (Azure Mgmt delegated consent + requested perm)
  # =====================================================================
  Info ""
  Info ("DRY RUN: discovering delegated consent grants and requested delegated permissions for {0}..." -f $AppDisplayName)

  $matchingGrants = @()
  $grantPresent = $false

  if ($spObjectId) {
    try {
      $filter = [uri]::EscapeDataString("clientId eq '$spObjectId' and resourceId eq '$resourceSpId'")
      $grants = Invoke-Graph -Method GET -Uri ("https://graph.microsoft.com/v1.0/oauth2PermissionGrants?`$filter=$filter")

      if ($grants.value) {
        $matchingGrants = @($grants.value | Where-Object {
          $_.consentType -eq "AllPrincipals" -and (" $($_.scope) " -like "* $scopeValue *")
        })
      }

      $grantPresent = ($matchingGrants.Count -gt 0)
    }
    catch {
      Warn "Could not query oauth2PermissionGrants for DRY RUN (may require additional permissions)."
      $matchingGrants = @()
      $grantPresent = $false
    }
  } else {
    Info "Skipping delegated consent grant discovery (principalId unknown)."
  }

  $req6bRes = Run-Az @(
    "ad","app","show","--id",$APP_ID,
    "--query","requiredResourceAccess[?resourceAppId=='$AZURE_MGMT_APPID'].resourceAccess[]",
    "-o","json","--only-show-errors"
  )

  $requestedPresent = $false
  if ($req6bRes.ExitCode -eq 0 -and $req6bRes.Output) {
    $ra6b = @($req6bRes.Output | ConvertFrom-Json)
    $requestedPresent = @($ra6b | Where-Object { $_.type -eq "Scope" -and $_.id -eq $userImpersonationId }).Count -gt 0
  }

  $step6bFindings = @(
    [pscustomobject]@{
      Item    = "Delegated consent grant (AllPrincipals)"
      Present = $(if ($grantPresent) { "Yes" } else { "No" })
      Details = $(if (-not $spObjectId) { "Skipped (principalId unknown)." }
                 elseif ($grantPresent) { "Found $($matchingGrants.Count) grant(s) for '$scopeValue' to Windows Azure Service Management API." }
                 else { "No matching oauth2PermissionGrants found." })
    }
    [pscustomobject]@{
      Item    = "Requested delegated permission (requiredResourceAccess)"
      Present = $(if ($requestedPresent) { "Yes" } else { "No" })
      Details = $(if ($requestedPresent) { "$scopeValue scope requested on Azure Service Management API (requiredResourceAccess)." } else { "Not present in requiredResourceAccess." })
    }
  )

  Info ""
  Info "DRY RUN RESULTS (delegated consent grants + requested delegated permissions):"
  $step6bFindings | Format-Table -AutoSize

  # =====================================================================
  # Discover subscriptions
  # =====================================================================
  Info ""
  Info "Discovering enabled subscriptions..."
  $subsRes = Run-Az @("account","list","--query","[?state=='Enabled'].{id:id,name:name}","-o","json","--only-show-errors")

  $SUBSCRIPTIONS = @()
  if ($subsRes.ExitCode -eq 0 -and $subsRes.Output) {
    $SUBSCRIPTIONS = @($subsRes.Output | ConvertFrom-Json)
  }

  if (-not $SUBSCRIPTIONS -or $SUBSCRIPTIONS.Count -eq 0) {
    Warn "No enabled subscriptions found. RBAC removal will be skipped."
    $SUBSCRIPTIONS = @()
  } else {
    Info ("Found {0} enabled subscription(s):" -f $SUBSCRIPTIONS.Count)
    foreach ($s in $SUBSCRIPTIONS) { Info (" - {0} ({1})" -f $s.name, $s.id) }
  }

  # =====================================================================
  # DRY RUN - Azure RBAC discovery (subscription-scope role assignments)
  # =====================================================================
  $RBAC_ROLES = @(
    "Reader",
    "Security Reader",
    "Key Vault Reader",
    "Log Analytics Reader",
    "Network Contributor",
    "Storage Account Contributor"
  )

  $dryRunFindings = New-Object System.Collections.Generic.List[psobject]
  $rbacTotal = 0

  Info ""
  if (-not $spObjectId) {
    Info "DRY RUN: skipping RBAC scan (principalId unknown)."
  } elseif (-not $SUBSCRIPTIONS -or $SUBSCRIPTIONS.Count -eq 0) {
    Info "DRY RUN: skipping RBAC scan (no enabled subscriptions)."
  } else {
    Info ("DRY RUN: scanning Azure subscriptions for RBAC role assignments linked to principalId {0}..." -f $spObjectId)

    foreach ($sub in $SUBSCRIPTIONS) {
      $subId = $sub.id
      $subName = $sub.name
      $scope = "/subscriptions/$subId"

      [void](Run-Az @("account","set","--subscription",$subId,"--only-show-errors"))

      foreach ($role in $RBAC_ROLES) {
        $q = "[?principalId=='$spObjectId' && roleDefinitionName=='$role'].id"
        $idsOut = (Run-Az @("role","assignment","list","--scope",$scope,"--query",$q,"-o","tsv","--only-show-errors")).Output
        $ids = @($idsOut -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })

        $dryRunFindings.Add([pscustomobject]@{
          Subscription     = $subName
          SubscriptionId   = $subId
          Role             = $role
          AssignmentsFound = $ids.Count
          Scope            = $scope
        }) | Out-Null
      }
    }

    Info ""
    Info "DRY RUN RESULTS (RBAC role assignments by subscription and role):"
    $dryRunFindings | Sort-Object Subscription, Role | Format-Table -AutoSize

    if ($dryRunFindings.Count -gt 0) {
      $rbacTotal = ($dryRunFindings | Measure-Object -Property AssignmentsFound -Sum).Sum
    }
  }

  # =====================================================================
  # SUMMARY
  # =====================================================================
  $step4AppTotal          = $(if ($AppPresent) { 1 } else { 0 })
  $step4bIdUriTotal       = $(if ($ExposeApiIdentifierPresent) { 1 } else { 0 })
  $step4bScopeTotal       = $ExposeApiScopesToRemove.Count

  $step5SecretTotal       = $SecretsToRemove.Count
  $step5SpTotal           = $(if ($spPresent) { 1 } else { 0 })

  $step6RequestedTotal    = $requestedGraphToRemove.Count
  $step6ConsentTotal      = $graphAssignmentsToRemoveCount

  $step6bGrantTotal       = $matchingGrants.Count
  $step6bReqTotal         = $(if ($requestedPresent) { 1 } else { 0 })

  Info ""
  Warn ("SUMMARY (items queued for removal):")
  Warn ("  App registration cleanup            : app={0}, identifierUris={1}, exposedScopes={2}" -f $step4AppTotal, $step4bIdUriTotal, $step4bScopeTotal)
  Warn ("  Service principal + client secrets  : servicePrincipal={0}, secrets={1}" -f $step5SpTotal, $step5SecretTotal)
  Warn ("  Microsoft Graph application roles   : requested={0}, consentedAssignments={1}" -f $step6RequestedTotal, $step6ConsentTotal)
  Warn ("  Delegated consent + delegated perms : grants={0}, requested={1}" -f $step6bGrantTotal, $step6bReqTotal)
  Warn ("  Azure RBAC role assignments         : {0}" -f $rbacTotal)

  $grandTotal =
    $step4AppTotal + $step4bIdUriTotal + $step4bScopeTotal +
    $step5SpTotal + $step5SecretTotal +
    $step6RequestedTotal + $step6ConsentTotal +
    $step6bGrantTotal + $step6bReqTotal +
    $rbacTotal

  if ($grandTotal -eq 0) {
    Good "Nothing to remove. No changes will be made."
    return
  }

  Info ""
  Warn "PLEASE REVIEW THE OUTPUT ABOVE BEFORE CONTINUING:"
  Warn "The DRY RUN output above is the exact set of items this script will attempt to DELETE/REMOVE."
  Warn "If anything looks unexpected (wrong app/SP, extra secrets, unexpected roles/assignments), CANCEL now and investigate."
  Info ""
  Info "To proceed, type REMOVE (ALL CAPITALS) to proceed or press Enter to cancel (no changes will be made)."
  $confirm = Read-Host "Confirmation >"

  if ($confirm -ne "REMOVE") {
    Warn "Cancelled. No changes were made."
    return
  }

  # =====================================================================
  # EXECUTE - Remove matching client secrets from the App Registration
  # =====================================================================
  Info ""
  Warn "Proceeding with client secret removal (revoking credentials) first..."

  if (-not $appObjectId) {
    Warn "Skipping secret removal (application object id could not be resolved)."
  }
  elseif ($SecretsToRemove.Count -gt 0) {
    $removedSecrets = 0
    $failedSecrets  = 0

    foreach ($s in $SecretsToRemove) {
      $kid = $s.keyId.ToString()
      try {
        $body = (@{ keyId = $kid } | ConvertTo-Json -Compress)
        Invoke-Graph -Method POST -Uri ("https://graph.microsoft.com/v1.0/applications/{0}/removePassword" -f $appObjectId) -BodyJson $body | Out-Null
        $removedSecrets++
        Good ("Removed secret '{0}' (keyId {1})" -f $SecretDisplayName, $kid)
      }
      catch {
        $failedSecrets++
        Warn ("Failed to remove secret '{0}' (keyId {1})" -f $SecretDisplayName, $kid)
        Warn $_
      }
    }

    if ($removedSecrets -gt 0 -and $failedSecrets -eq 0) {
      Good ("Removed {0} secret(s) successfully." -f $removedSecrets)
    } elseif ($removedSecrets -gt 0 -and $failedSecrets -gt 0) {
      Warn ("Partially removed secrets (removed {0}, failed {1})." -f $removedSecrets, $failedSecrets)
    } else {
      Warn "No secrets were removed (permissions may be insufficient)."
    }
  } else {
    Info ("No secrets found with displayName '{0}' to remove." -f $SecretDisplayName)
  }

  # =====================================================================
  # EXECUTE - Delete the service principal (if present)
  # =====================================================================
  Info ""
  Warn "Proceeding with service principal deletion (removing the Enterprise Application) ..."

  $spDeleted = $false
  if (-not $spPresent -or -not $spObjectId -or ($spName -match "SP not found")) {
    $spDeleted = $true
    Info "Skipping service principal deletion (service principal not present in tenant)."
  } else {
    $delSp = Run-Az @("ad","sp","delete","--id",$spObjectId,"--only-show-errors")
    if ($delSp.ExitCode -eq 0) {
      $spDeleted = $true
      Good ("Deleted service principal: {0} (objectId {1})" -f $spName, $spObjectId)
    } else {
      Warn "Could not delete service principal (you may lack permission). Continuing with remaining removals."
      if ($delSp.Output) { Warn $delSp.Output }
    }
  }

  # =====================================================================
  # EXECUTE - Remove Microsoft Graph application permissions configured on the app/SP
  # =====================================================================
  Info ""
  Warn "Proceeding with Microsoft Graph permission cleanup (consented assignments + requested roles)..."

  if (-not $spDeleted -and $matchingGraphAssignments.Count -gt 0) {
    Info "Removing Graph appRoleAssignments (admin consent artifacts) for the specified role set..."
    $deleted = 0
    $failed  = 0

    foreach ($a in $matchingGraphAssignments) {
      try {
        Invoke-Graph -Method DELETE -Uri ("https://graph.microsoft.com/v1.0/servicePrincipals/{0}/appRoleAssignments/{1}" -f $spObjectId, $a.id) | Out-Null
        $deleted++
      }
      catch {
        $failed++
        Warn ("Failed to delete Graph appRoleAssignment id: {0}" -f $a.id)
        Warn $_
      }
    }

    if ($deleted -gt 0 -and $failed -eq 0) {
      Good ("Removed {0} Graph appRoleAssignment(s)." -f $deleted)
    } elseif ($deleted -gt 0 -and $failed -gt 0) {
      Warn ("Partially removed Graph appRoleAssignments (removed {0}, failed {1})." -f $deleted, $failed)
    } else {
      Warn "No Graph appRoleAssignments were removed (permissions may be insufficient)."
    }
  }
  elseif ($spDeleted) {
    Info "Skipped explicit Graph appRoleAssignment deletion because the service principal is missing/deleted."
  }
  else {
    Info "No matching Graph appRoleAssignments to remove."
  }

  if ($requestedGraphToRemove.Count -gt 0) {
    Info "Removing requested Graph application permissions from requiredResourceAccess..."
    foreach ($rid in $requestedGraphToRemove) {
      $del = Run-Az @("ad","app","permission","delete","--id",$APP_ID,"--api",$MS_GRAPH_APPID,"--api-permissions",$rid,"--only-show-errors")
      if ($del.ExitCode -eq 0) {
        Good ("Removed requested Graph role id: {0}" -f $rid)
      } else {
        Warn ("Could not remove requested Graph role id: {0} (may already be absent or require manual removal)" -f $rid)
        if ($del.Output) { Warn $del.Output }
      }
    }
    Good "Graph requiredResourceAccess cleanup attempted."
  } else {
    Info "No requested Graph application permissions to remove."
  }

  # =====================================================================
  # EXECUTE - Remove Azure Service Management delegated consent + requested scope
  # (Grant delete is idempotent; 404 ignored)
  # =====================================================================
  Info ""
  Warn "Proceeding with Azure Service Management delegated access cleanup (consent grants + requested scope)..."

  if ($grantPresent -and $matchingGrants.Count -gt 0) {
    Info ("Removing delegated consent grant(s) (AllPrincipals) for '{0}'..." -f $scopeValue)

    $removed = 0
    $skipped = 0
    $failed  = 0

    foreach ($g in $matchingGrants) {
      try {
        Invoke-Graph -Method DELETE -Uri ("https://graph.microsoft.com/v1.0/oauth2PermissionGrants/{0}" -f $g.id) | Out-Null
        $removed++
      }
      catch {
        $m = $_.Exception.Message
        if ($m -match "\(404\)" -or $m -match "Request_ResourceNotFound") {
          $skipped++
          Info ("Grant already removed (404): {0}" -f $g.id)
        } else {
          $failed++
          Warn ("Failed to delete grant id: {0}" -f $g.id)
          Warn $m
        }
      }
    }

    if ($failed -eq 0) {
      Good ("Delegated consent grants removed: {0} (already gone: {1})" -f $removed, $skipped)
    } else {
      Warn ("Delegated consent grants removed: {0}, already gone: {1}, failed: {2}" -f $removed, $skipped, $failed)
    }
  } else {
    Info "No delegated consent grants to remove (or could not enumerate)."
  }

  if ($requestedPresent) {
    Info "Removing requested delegated permission from requiredResourceAccess..."
    $del6b = Run-Az @("ad","app","permission","delete","--id",$APP_ID,"--api",$AZURE_MGMT_APPID,"--api-permissions",$userImpersonationId,"--only-show-errors")
    if ($del6b.ExitCode -eq 0) {
      Good "Removed requested delegated permission (requiredResourceAccess updated)."
    } else {
      Warn "Could not remove requested delegated permission via az (may require manual removal)."
      if ($del6b.Output) { Warn $del6b.Output }
    }
  } else {
    Info "No requested delegated permission to remove."
  }

  # =====================================================================
  # EXECUTE - Remove Azure RBAC role assignments at subscription scope
  # =====================================================================
  Info ""
  Warn "Proceeding with Azure RBAC role assignment cleanup across enabled subscriptions..."

  if (-not $spObjectId) {
    Warn "Skipping RBAC removal (principalId is unknown). If the SP was already deleted, set `$SP_OBJECT_ID_OVERRIDE and re-run."
  }
  elseif ($rbacTotal -eq 0) {
    Good "No RBAC assignments found to remove. Skipping RBAC removal."
  }
  else {
    $removalSummary = New-Object System.Collections.Generic.List[psobject]

    foreach ($sub in $SUBSCRIPTIONS) {
      $subId = $sub.id
      $subName = $sub.name
      $scope = "/subscriptions/$subId"

      Info ""
      Info ("Processing subscription: {0} ({1})" -f $subName, $subId)
      [void](Run-Az @("account","set","--subscription",$subId,"--only-show-errors"))

      foreach ($role in $RBAC_ROLES) {
        $q = "[?principalId=='$spObjectId' && roleDefinitionName=='$role'].id"
        $idsOut = (Run-Az @("role","assignment","list","--scope",$scope,"--query",$q,"-o","tsv","--only-show-errors")).Output
        $ids = @($idsOut -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })

        if ($ids.Count -eq 0) {
          Info ("  No assignment found for role: {0}" -f $role)
          $removalSummary.Add([pscustomobject]@{ Subscription=$subName; Role=$role; Removed=0; Status="None" }) | Out-Null
          continue
        }

        $removed = 0
        $failed = 0

        foreach ($id in $ids) {
          $delR = Run-Az @("role","assignment","delete","--ids",$id,"--only-show-errors")
          if ($delR.ExitCode -eq 0) {
            $removed++
          } else {
            $failed++
            Warn ("  Failed to delete assignment id: {0}" -f $id)
            if ($delR.Output) { Warn $delR.Output }
          }
        }

        if ($removed -gt 0 -and $failed -eq 0) {
          Good ("  Removed {0} assignment(s) for role: {1}" -f $removed, $role)
          $removalSummary.Add([pscustomobject]@{ Subscription=$subName; Role=$role; Removed=$removed; Status="Removed" }) | Out-Null
        }
        elseif ($removed -gt 0 -and $failed -gt 0) {
          Warn ("  Partially removed {0} assignment(s) for role: {1} (failed: {2})" -f $removed, $role, $failed)
          $removalSummary.Add([pscustomobject]@{ Subscription=$subName; Role=$role; Removed=$removed; Status="Partial" }) | Out-Null
        }
        else {
          Warn ("  No assignments removed for role: {0} (you may lack permission)" -f $role)
          $removalSummary.Add([pscustomobject]@{ Subscription=$subName; Role=$role; Removed=0; Status="Failed" }) | Out-Null
        }
      }
    }

    Info ""
    Info "RBAC REMOVAL SUMMARY:"
    $removalSummary | Sort-Object Subscription, Role | Format-Table -AutoSize
  }

  # =====================================================================
  # EXECUTE - Remove "Expose an API" configuration on the App Registration
  # FIX: disable scope(s) first, then remove
  # =====================================================================
  Info ""
  Warn "Proceeding with app 'Expose an API' cleanup (scopes + identifier URI)..."

  if (-not $appObjectId) {
    Warn "Skipping 'Expose an API' cleanup (application object id could not be resolved)."
  } else {
    try {
      $appNow = Invoke-Graph -Method GET -Uri ("https://graph.microsoft.com/v1.0/applications/{0}?`$select=identifierUris,api" -f $appObjectId)

      # ---- Scopes ----
      $existingScopes = @()
      if ($appNow.api -and $appNow.api.oauth2PermissionScopes) { $existingScopes = @($appNow.api.oauth2PermissionScopes) }

      $targetScopes = @($existingScopes | Where-Object { $_.value -eq $ExposeApiScopeValue })
      if ($targetScopes.Count -gt 0) {

        # 1) Disable any enabled target scope(s)
        $needsDisable = @($targetScopes | Where-Object { $_.isEnabled -eq $true })
        if ($needsDisable.Count -gt 0) {

          $disabledScopes = foreach ($s in $existingScopes) {
            $isTarget = ($s.value -eq $ExposeApiScopeValue)
            [pscustomobject]@{
              id                     = $s.id
              value                  = $s.value
              type                   = $s.type
              isEnabled              = $(if ($isTarget) { $false } else { [bool]$s.isEnabled })
              adminConsentDisplayName= $s.adminConsentDisplayName
              adminConsentDescription= $s.adminConsentDescription
              userConsentDisplayName = $s.userConsentDisplayName
              userConsentDescription = $s.userConsentDescription
            }
          }

          $disableBody = @{ api = @{ oauth2PermissionScopes = $disabledScopes } } | ConvertTo-Json -Depth 50 -Compress
          Invoke-Graph -Method PATCH -Uri ("https://graph.microsoft.com/v1.0/applications/{0}" -f $appObjectId) -BodyJson $disableBody | Out-Null
          Good ("Disabled {0} exposed API scope(s) with value '{1}'." -f $needsDisable.Count, $ExposeApiScopeValue)

          # Re-read after disabling (avoids eventual consistency weirdness)
          $appNow = Invoke-Graph -Method GET -Uri ("https://graph.microsoft.com/v1.0/applications/{0}?`$select=api" -f $appObjectId)
          $existingScopes = @()
          if ($appNow.api -and $appNow.api.oauth2PermissionScopes) { $existingScopes = @($appNow.api.oauth2PermissionScopes) }
        }

        # 2) Remove target scope(s)
        $remainingScopes = @($existingScopes | Where-Object { $_.value -ne $ExposeApiScopeValue })

        $removeBody = @{ api = @{ oauth2PermissionScopes = $remainingScopes } } | ConvertTo-Json -Depth 50 -Compress
        Invoke-Graph -Method PATCH -Uri ("https://graph.microsoft.com/v1.0/applications/{0}" -f $appObjectId) -BodyJson $removeBody | Out-Null
        Good ("Removed exposed API scope(s) with value '{0}'." -f $ExposeApiScopeValue)

      } else {
        Info ("No exposed API scopes found with value '{0}'." -f $ExposeApiScopeValue)
      }

      # ---- Identifier URI ----
      $idUris = @()
      if ($appNow.identifierUris) { $idUris = @($appNow.identifierUris) }

      if ($idUris -contains $ExposeApiIdentifierUri) {
        $newIdUris = @($idUris | Where-Object { $_ -ne $ExposeApiIdentifierUri })
        $patchUris = @{ identifierUris = $newIdUris } | ConvertTo-Json -Compress
        Invoke-Graph -Method PATCH -Uri ("https://graph.microsoft.com/v1.0/applications/{0}" -f $appObjectId) -BodyJson $patchUris | Out-Null
        Good ("Removed identifierUri: {0}" -f $ExposeApiIdentifierUri)
      } else {
        Info ("No identifierUri '{0}' found to remove." -f $ExposeApiIdentifierUri)
      }
    }
    catch {
      Warn "Failed to remove 'Expose an API' settings. You may need to remove these manually in Entra ID."
      Warn $_
    }
  }

  # =====================================================================
  # EXECUTE - Delete the App Registration object (Entra ID application)
  # =====================================================================
  Info ""
  Warn "Proceeding to delete the app registration (this permanently removes the Entra ID application)..."

  $delApp = Run-Az @("ad","app","delete","--id",$APP_ID,"--only-show-errors")
  if ($delApp.ExitCode -eq 0) {
    Good ("Deleted app registration (appId {0})." -f $APP_ID)
  } else {
    Warn "Could not delete app registration (you may lack permission)."
    if ($delApp.Output) { Warn $delApp.Output }
  }

  Info ""
  Good "Removal complete."
}
catch {
  $msg = $_.Exception.Message

  if ($msg -match "Invalid JSON primitive" -or $msg -match "az\.cmd") {
    Good "No removable artifacts were found for the supplied App ID ($APP_ID)."
    Info "This commonly occurs when the onboarding has already been cleaned up."
    Info "If you expected artifacts to exist, verify the App ID or leave `$APP_ID blank to auto-discover by the displayName prefix."
    return
  }

  Bad "Removal failed."
  Warn $msg
}