# ============================================================================
# Mock DUN Onboarding Script - For Testing Secret Upload Integration
# ============================================================================
# This script simulates the onboarding process without creating actual Azure resources.
# It generates mock credentials and uploads the client secret to the Secure Secret API.
# ============================================================================

param(
    [string]$BaseUrl = "https://secsecret-poc-func.azurewebsites.net",
    [string]$OrganizationName = "Acme Corp",
    [string]$TenantId,
    [switch]$SkipPrompts
)

$ErrorActionPreference = "Stop"

# ============================================================================
# Introduction
# ============================================================================
Write-Host ""
Write-Host "+================================================================+" -ForegroundColor Cyan
Write-Host "|                                                                |" -ForegroundColor Cyan
Write-Host "|          DUN Security - Mock Onboarding (TEST ONLY)           |" -ForegroundColor Cyan
Write-Host "|                                                                |" -ForegroundColor Cyan
Write-Host "+================================================================+" -ForegroundColor Cyan
Write-Host ""
Write-Host "[TEST MODE] This script simulates onboarding without creating real resources" -ForegroundColor Yellow
Write-Host ""

# ============================================================================
# Get Organization Name
# ============================================================================
if ([string]::IsNullOrWhiteSpace($OrganizationName) -and -not $SkipPrompts) {
    Write-Host "Enter organization name (default: Acme Corp):" -ForegroundColor Yellow
    $input = Read-Host ">"
    if (-not [string]::IsNullOrWhiteSpace($input)) {
        $OrganizationName = $input
    }
}

Write-Host ""
Write-Host "[OK] Organization: $OrganizationName" -ForegroundColor Green
Write-Host ""

# ============================================================================
# Get Azure Context
# ============================================================================
Write-Host "Getting Azure context..." -ForegroundColor Blue

try {
    $context = Get-AzContext -ErrorAction Stop
    
    if (-not $context) {
        Write-Host "[X] Not logged into Azure" -ForegroundColor Red
        Write-Host ""
        Write-Host "Please run: Connect-AzAccount" -ForegroundColor Yellow
        exit 1
    }
    
    $ActualTenantId = $context.Tenant.Id
    
    # Use provided TenantId if specified, otherwise use actual
    if ([string]::IsNullOrWhiteSpace($TenantId)) {
        $TenantId = $ActualTenantId
    }
    
    Write-Host "[OK] Logged in as: $($context.Account.Id)" -ForegroundColor Green
    Write-Host "    Tenant: $TenantId" -ForegroundColor Gray
    Write-Host ""
} catch {
    Write-Host "[X] Failed to get Azure context" -ForegroundColor Red
    Write-Host ""
    Write-Host "Please install Az PowerShell module and run: Connect-AzAccount" -ForegroundColor Yellow
    exit 1
}

# Get tenant name
try {
    $tenantInfo = az rest --method GET --url "https://graph.microsoft.com/v1.0/organization" --query "value[0].displayName" -o tsv 2>$null
    if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($tenantInfo)) {
        $TenantName = $tenantInfo
    } else {
        $TenantName = $TenantId
    }
} catch {
    $TenantName = $TenantId
}

# ============================================================================
# Mock: Generate "Onboarding" Data
# ============================================================================
Write-Host "================================================================" -ForegroundColor Blue
Write-Host "Simulating Onboarding Process" -ForegroundColor Blue
Write-Host "================================================================" -ForegroundColor Blue
Write-Host ""

Write-Host "[MOCK] Creating App Registration..." -ForegroundColor DarkGray
Start-Sleep -Milliseconds 500
$MockAppId = [Guid]::NewGuid().ToString()
Write-Host "[OK] App ID: $MockAppId" -ForegroundColor Green
Write-Host ""

Write-Host "[MOCK] Creating Service Principal..." -ForegroundColor DarkGray
Start-Sleep -Milliseconds 500
$MockSpId = [Guid]::NewGuid().ToString()
Write-Host "[OK] SP Object ID: $MockSpId" -ForegroundColor Green
Write-Host ""

Write-Host "[MOCK] Generating Client Secret..." -ForegroundColor DarkGray
Start-Sleep -Milliseconds 500

# Generate a realistic-looking client secret (base64-encoded random bytes)
$randomBytes = New-Object byte[] 32
(New-Object System.Security.Cryptography.RNGCryptoServiceProvider).GetBytes($randomBytes)
$MockClientSecret = [Convert]::ToBase64String($randomBytes) + "~"

Write-Host "[OK] Client Secret generated (40 chars)" -ForegroundColor Green
Write-Host ""

Write-Host "[MOCK] Assigning Graph API permissions..." -ForegroundColor DarkGray
Start-Sleep -Milliseconds 500
Write-Host "[OK] 9 permissions granted" -ForegroundColor Green
Write-Host ""

# Get subscriptions
$subscriptions = az account list --query "[?state=='Enabled'].{id:id, name:name}" -o json | ConvertFrom-Json
$subscriptionIds = @()
$subscriptionNames = @()

if ($subscriptions -and $subscriptions.Count -gt 0) {
    Write-Host "[MOCK] Assigning RBAC roles to $($subscriptions.Count) subscription(s)..." -ForegroundColor DarkGray
    Start-Sleep -Milliseconds 500
    
    foreach ($sub in $subscriptions) {
        $subscriptionIds += $sub.id
        $subscriptionNames += $sub.name
    }
    
    Write-Host "[OK] RBAC configured on $($subscriptions.Count) subscription(s)" -ForegroundColor Green
} else {
    Write-Host "[!] No subscriptions found" -ForegroundColor Yellow
}

Write-Host ""

# ============================================================================
# Secure Secret Upload: Get Token
# ============================================================================
Write-Host "================================================================" -ForegroundColor Blue
Write-Host "Uploading Client Secret Securely" -ForegroundColor Blue
Write-Host "================================================================" -ForegroundColor Blue
Write-Host ""
Write-Host "[1/4] Acquiring Azure AD access token..." -ForegroundColor Blue

try {
    $tokenInfo = Get-AzAccessToken -ResourceUrl "https://management.azure.com"
    
    if (-not $tokenInfo) {
        throw "Failed to acquire token"
    }
    
    # Handle different token formats (SecureString vs String)
    $token = $null
    if ($tokenInfo.Token -is [System.Security.SecureString]) {
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($tokenInfo.Token)
        $token = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($BSTR)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
    } elseif ($tokenInfo.Token -is [string]) {
        $token = $tokenInfo.Token
    } elseif ($tokenInfo -is [string]) {
        $token = $tokenInfo
    } elseif ($null -ne $tokenInfo.Token) {
        $token = $tokenInfo.Token.ToString()
    }
    
    if ([string]::IsNullOrWhiteSpace($token) -or $token.Length -lt 50) {
        throw "Token is empty or invalid"
    }
    
    Write-Host "  [OK] Token acquired successfully" -ForegroundColor Green
    Write-Host ""
} catch {
    Write-Host "  [X] Failed to acquire token" -ForegroundColor Red
    Write-Host "  Error: $_" -ForegroundColor Red
    Write-Host ""
    exit 1
}

# ============================================================================
# Secure Secret Upload: Create Session
# ============================================================================
Write-Host "[2/4] Creating upload session (generating RSA-4096 keypair)..." -ForegroundColor Blue

$SubmissionId = [Guid]::NewGuid().ToString()
$createBody = @{
    submissionId = $SubmissionId
    clientTenantId = $TenantId
} | ConvertTo-Json

try {
    $session = Invoke-RestMethod -Method Post `
        -Uri "$BaseUrl/v1/upload-sessions" `
        -Headers @{
            "Authorization" = "Bearer $token"
            "Content-Type" = "application/json"
        } `
        -Body $createBody
    
    $PublicKeyB64 = $session.publicKeySpkiB64
    $ApiAppId = "a023625b-aa0e-4a24-a6e6-7c5b4e8d7663"
    $ActualSessionId = $session.submissionId
    
    Write-Host "  [OK] Session created successfully" -ForegroundColor Green
    Write-Host "    Session ID: $ActualSessionId" -ForegroundColor Gray
    Write-Host "    Expires: $($session.expiresUtc)" -ForegroundColor Gray
    Write-Host ""
} catch {
    Write-Host "  [X] Failed to create session" -ForegroundColor Red
    Write-Host "  Error: $_" -ForegroundColor Red
    if ($_.ErrorDetails.Message) {
        Write-Host "  Response: $($_.ErrorDetails.Message)" -ForegroundColor Red
    }
    Write-Host ""
    exit 1
}

# ============================================================================
# Helper Functions for RSA Encryption (PowerShell 5.1 compatible)
# ============================================================================
function Parse-SubjectPublicKeyInfo {
    param([byte[]]$keyBytes)
    
    $offset = 0
    
    if ($keyBytes[$offset] -ne 0x30) { throw "Invalid key format: expected SEQUENCE" }
    $offset++
    $outerLength = Read-ASN1Length $keyBytes ([ref]$offset)
    
    if ($keyBytes[$offset] -ne 0x30) { throw "Invalid key format: expected algorithm SEQUENCE" }
    $offset++
    $algLength = Read-ASN1Length $keyBytes ([ref]$offset)
    $offset += $algLength
    
    if ($keyBytes[$offset] -ne 0x03) { throw "Invalid key format: expected BIT STRING" }
    $offset++
    $bitStringLength = Read-ASN1Length $keyBytes ([ref]$offset)
    $offset++
    
    if ($keyBytes[$offset] -ne 0x30) { throw "Invalid key format: expected RSA SEQUENCE" }
    $offset++
    $rsaSeqLength = Read-ASN1Length $keyBytes ([ref]$offset)
    
    if ($keyBytes[$offset] -ne 0x02) { throw "Invalid key format: expected modulus INTEGER" }
    $offset++
    $modulusLength = Read-ASN1Length $keyBytes ([ref]$offset)
    
    if ($keyBytes[$offset] -eq 0x00) {
        $offset++
        $modulusLength--
    }
    
    $modulus = New-Object byte[] $modulusLength
    [Array]::Copy($keyBytes, $offset, $modulus, 0, $modulusLength)
    $offset += $modulusLength
    
    if ($keyBytes[$offset] -ne 0x02) { throw "Invalid key format: expected exponent INTEGER" }
    $offset++
    $exponentLength = Read-ASN1Length $keyBytes ([ref]$offset)
    
    $exponent = New-Object byte[] $exponentLength
    [Array]::Copy($keyBytes, $offset, $exponent, 0, $exponentLength)
    
    return @{
        Modulus = $modulus
        Exponent = $exponent
    }
}

function Read-ASN1Length {
    param([byte[]]$bytes, [ref]$offset)
    
    $lengthByte = $bytes[$offset.Value]
    $offset.Value++
    
    if ($lengthByte -lt 0x80) {
        return $lengthByte
    } else {
        $numLengthBytes = $lengthByte -band 0x7F
        $length = 0
        for ($i = 0; $i -lt $numLengthBytes; $i++) {
            $length = ($length -shl 8) -bor $bytes[$offset.Value]
            $offset.Value++
        }
        return $length
    }
}

# ============================================================================
# Secure Secret Upload: Encrypt Secret
# ============================================================================
Write-Host "[3/4] Encrypting client secret with RSA-OAEP-SHA256..." -ForegroundColor Blue

try {
    $publicKeyBytes = [Convert]::FromBase64String($PublicKeyB64)
    
    # Detect PowerShell version and use appropriate RSA encryption
    $psVersion = $PSVersionTable.PSVersion.Major
    
    if ($psVersion -ge 7) {
        # PowerShell 7+ - Use modern RSA API
        $rsa = [System.Security.Cryptography.RSA]::Create()
        $bytesRead = 0
        $rsa.ImportSubjectPublicKeyInfo($publicKeyBytes, [ref]$bytesRead)
        
        $secretBytes = [System.Text.Encoding]::UTF8.GetBytes($MockClientSecret)
        $encryptedBytes = $rsa.Encrypt($secretBytes, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256)
        $encryptedB64 = [Convert]::ToBase64String($encryptedBytes)
        $rsa.Dispose()
    } else {
        # PowerShell 5.1 - Parse key manually and use RSACng
        $rsaParams = Parse-SubjectPublicKeyInfo $publicKeyBytes
        
        $rsa = New-Object System.Security.Cryptography.RSACng
        $rsaParameters = New-Object System.Security.Cryptography.RSAParameters
        $rsaParameters.Modulus = $rsaParams.Modulus
        $rsaParameters.Exponent = $rsaParams.Exponent
        $rsa.ImportParameters($rsaParameters)
        
        $secretBytes = [System.Text.Encoding]::UTF8.GetBytes($MockClientSecret)
        $padding = [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256
        $encryptedBytes = $rsa.Encrypt($secretBytes, $padding)
        $encryptedB64 = [Convert]::ToBase64String($encryptedBytes)
        $rsa.Dispose()
    }
    
    Write-Host "  [OK] Client secret encrypted successfully (PS $psVersion)" -ForegroundColor Green
    Write-Host "    Plaintext:  $($MockClientSecret.Length) bytes" -ForegroundColor Gray
    Write-Host "    Ciphertext: $($encryptedB64.Length) bytes (base64)" -ForegroundColor Gray
    Write-Host ""
} catch {
    Write-Host "  [X] Failed to encrypt secret" -ForegroundColor Red
    Write-Host "  Error: $_" -ForegroundColor Red
    Write-Host ""
    exit 1
}

# ============================================================================
# Secure Secret Upload: Submit Encrypted Secret
# ============================================================================
Write-Host "[4/4] Submitting encrypted secret to API..." -ForegroundColor Blue

$submitBody = @{
    tenantId = $TenantId
    appId = $ApiAppId
    displayName = "DUN Security - $OrganizationName - Client Secret"
    secret = @{
        cipherTextB64 = $encryptedB64
        alg = "RSA-OAEP-256"
        expiresUtc = (Get-Date).AddYears(2).ToUniversalTime().ToString("o")
    }
    sentUtc = (Get-Date).ToUniversalTime().ToString("o")
    organizationName = $OrganizationName
    tenantName = $TenantName
    clientAppId = $MockAppId
    subscriptionIds = ($subscriptionIds -join ",")
} | ConvertTo-Json -Depth 10

try {
    $receipt = Invoke-RestMethod -Method Post `
        -Uri "$BaseUrl/v1/upload-sessions/$ActualSessionId/submit" `
        -Headers @{
            "Authorization" = "Bearer $token"
            "Content-Type" = "application/json"
        } `
        -Body $submitBody
    
    $ReceiptId = $receipt.receiptId
    
    Write-Host "  [OK] Client secret uploaded and stored in Key Vault!" -ForegroundColor Green
    Write-Host "    Receipt ID:   $ReceiptId" -ForegroundColor Gray
    Write-Host "    Correlation:  $($receipt.correlationId)" -ForegroundColor Gray
    Write-Host ""
} catch {
    Write-Host "  [X] Failed to submit secret" -ForegroundColor Red
    Write-Host "  Error: $_" -ForegroundColor Red
    
    if ($_.Exception.Response) {
        $responseStream = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($responseStream)
        $responseBody = $reader.ReadToEnd()
        $reader.Close()
        $responseStream.Close()
        
        Write-Host "  API Response: $responseBody" -ForegroundColor Red
    } elseif ($_.ErrorDetails.Message) {
        Write-Host "  Response: $($_.ErrorDetails.Message)" -ForegroundColor Red
    }
    Write-Host ""
    exit 1
}

# ============================================================================
# Onboarding Complete - Output Configuration Summary
# ============================================================================
Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "Mock Onboarding Complete!" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Configuration Summary (send to DUN Security):" -ForegroundColor Cyan
Write-Host ""
Write-Host "Organization Name:      " -NoNewline
Write-Host $OrganizationName -ForegroundColor Yellow
Write-Host "Tenant Name:            " -NoNewline
Write-Host $TenantName -ForegroundColor Cyan
Write-Host "Tenant ID:              " -NoNewline
Write-Host $TenantId -ForegroundColor Cyan
Write-Host "Client ID (appId):      " -NoNewline
Write-Host $MockAppId -ForegroundColor Cyan
Write-Host "Receipt ID:             " -NoNewline
Write-Host $ReceiptId -ForegroundColor Magenta
Write-Host "No. of Subscriptions:   " -NoNewline
Write-Host $subscriptionIds.Count -ForegroundColor Cyan

if ($subscriptionIds.Count -gt 0) {
    if ($subscriptionIds.Count -le 5) {
        Write-Host "Subscription IDs:       " -NoNewline
        Write-Host ($subscriptionIds -join ", ") -ForegroundColor Cyan
    } else {
        Write-Host "Subscription IDs:       " -NoNewline
        Write-Host "$($subscriptionIds.Count)" -ForegroundColor Cyan -NoNewline
        Write-Host " (list below)"
        Write-Host "Subscriptions:"
        for ($i = 0; $i -lt $subscriptionIds.Count; $i++) {
            Write-Host "  - $($subscriptionIds[$i]) ($($subscriptionNames[$i]))" -ForegroundColor Cyan
        }
    }
}

Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "Share these configuration details with Chat Bot at:" -ForegroundColor Yellow
Write-Host "https://dunsecurity.ai/get-started" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "The client secret is now securely stored in Azure Key Vault." -ForegroundColor Green
Write-Host "DUN will retrieve it using the Receipt ID provided above." -ForegroundColor Green
Write-Host ""
