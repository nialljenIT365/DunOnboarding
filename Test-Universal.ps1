# ============================================================================
# Secure Secret Upload POC - End-to-End Test (Universal)
# ============================================================================
# This script works in both Windows PowerShell ISE and Azure Cloud Shell
# using RSACng/RSA for RSA-OAEP-SHA256 encryption.
# ============================================================================

param(
    [string]$BaseUrl = "https://secsecret-poc-func.azurewebsites.net",
    [string]$TenantId = "ac99b1d0-972a-4a3a-bedf-6728544da6d0",
    [string]$TestSecret = "MyTestSecret-$((Get-Random -Maximum 9999).ToString().PadLeft(4,'0'))"
)

Write-Host ""
Write-Host "============================================================================" -ForegroundColor Cyan
Write-Host "Secure Secret Upload POC - End-to-End Test (PowerShell 5.1)" -ForegroundColor Cyan
Write-Host "============================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Configuration:" -ForegroundColor Yellow
Write-Host "  API Base URL: $BaseUrl"
Write-Host "  Tenant ID:    $TenantId"
Write-Host "  Test Secret:  $TestSecret"
Write-Host ""

# ============================================================================
# Helper Function: Parse SubjectPublicKeyInfo to extract RSA parameters
# ============================================================================
function Parse-SubjectPublicKeyInfo {
    param([byte[]]$keyBytes)
    
    # This is a simplified ASN.1 parser for RSA public keys in SubjectPublicKeyInfo format
    # Format: SEQUENCE { algorithm, BIT STRING { SEQUENCE { modulus, exponent } } }
    
    $offset = 0
    
    # Read SEQUENCE tag and length (outer)
    if ($keyBytes[$offset] -ne 0x30) { throw "Invalid key format: expected SEQUENCE" }
    $offset++
    $outerLength = Read-ASN1Length $keyBytes ([ref]$offset)
    
    # Skip algorithm identifier SEQUENCE
    if ($keyBytes[$offset] -ne 0x30) { throw "Invalid key format: expected algorithm SEQUENCE" }
    $offset++
    $algLength = Read-ASN1Length $keyBytes ([ref]$offset)
    $offset += $algLength
    
    # Read BIT STRING
    if ($keyBytes[$offset] -ne 0x03) { throw "Invalid key format: expected BIT STRING" }
    $offset++
    $bitStringLength = Read-ASN1Length $keyBytes ([ref]$offset)
    $offset++ # Skip unused bits byte
    
    # Now we're in the actual RSA key SEQUENCE
    if ($keyBytes[$offset] -ne 0x30) { throw "Invalid key format: expected RSA SEQUENCE" }
    $offset++
    $rsaSeqLength = Read-ASN1Length $keyBytes ([ref]$offset)
    
    # Read modulus (INTEGER)
    if ($keyBytes[$offset] -ne 0x02) { throw "Invalid key format: expected modulus INTEGER" }
    $offset++
    $modulusLength = Read-ASN1Length $keyBytes ([ref]$offset)
    
    # Skip leading zero byte if present (ASN.1 adds this for positive integers with high bit set)
    if ($keyBytes[$offset] -eq 0x00) {
        $offset++
        $modulusLength--
    }
    
    $modulus = New-Object byte[] $modulusLength
    [Array]::Copy($keyBytes, $offset, $modulus, 0, $modulusLength)
    $offset += $modulusLength
    
    # Read exponent (INTEGER)
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
        # Short form
        return $lengthByte
    } else {
        # Long form
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
# STEP 0: Verify tenant context
# ============================================================================
Write-Host "[0/4] Verifying Azure context..." -ForegroundColor Blue

try {
    $context = Get-AzContext -ErrorAction Stop
    
    if (-not $context) {
        Write-Host "  [X] Not logged into Azure" -ForegroundColor Red
        Write-Host ""
        Write-Host "Please run: Connect-AzAccount -TenantId $TenantId" -ForegroundColor Yellow
        Write-Host ""
        return
    }
    
    if ($context.Tenant.Id -ne $TenantId) {
        Write-Host "  [X] Wrong tenant context" -ForegroundColor Red
        Write-Host "    Current:  $($context.Tenant.Id)" -ForegroundColor Gray
        Write-Host "    Required: $TenantId" -ForegroundColor Gray
        Write-Host ""
        Write-Host "Please run: Connect-AzAccount -TenantId $TenantId" -ForegroundColor Yellow
        Write-Host ""
        return
    }
    
    Write-Host "  [OK] Logged in as: $($context.Account.Id)" -ForegroundColor Green
    Write-Host "    Tenant: $($context.Tenant.Id)" -ForegroundColor Gray
    Write-Host ""
} catch {
    Write-Host "  [X] Failed to get Azure context" -ForegroundColor Red
    Write-Host "  Error: $_" -ForegroundColor Red
    Write-Host ""
    Write-Host "Please install Az PowerShell module and run: Connect-AzAccount -TenantId $TenantId" -ForegroundColor Yellow
    Write-Host ""
    return
}

# ============================================================================
# STEP 1: Get Access Token
# ============================================================================
Write-Host "[1/4] Acquiring Azure AD access token..." -ForegroundColor Blue

try {
    $tokenInfo = Get-AzAccessToken -ResourceUrl "https://management.azure.com"
    
    if (-not $tokenInfo) {
        Write-Host "  [X] Failed to acquire token - no token info returned" -ForegroundColor Red
        Write-Host ""
        return
    }
    
    # Handle different token formats across PowerShell versions
    $token = $null
    
    # Try each method in order of likelihood
    if ($tokenInfo.Token -is [System.Security.SecureString]) {
        # Windows PowerShell 5.1 ISE with SecureString or Cloud Shell on Linux
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($tokenInfo.Token)
        # Use PtrToStringUni (works on both Windows and Linux)
        $token = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($BSTR)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
    } elseif ($tokenInfo.Token -is [string]) {
        # Cloud Shell / PowerShell 7+ with plain string
        $token = $tokenInfo.Token
    } elseif ($tokenInfo -is [string]) {
        # Direct string return
        $token = $tokenInfo
    } elseif ($null -ne $tokenInfo.Token) {
        # Fallback: try ToString()
        $token = $tokenInfo.Token.ToString()
    }
    
    # Validate token
    if ([string]::IsNullOrWhiteSpace($token)) {
        Write-Host "  [X] Token is empty or invalid" -ForegroundColor Red
        Write-Host "  Debug: TokenInfo type was $($tokenInfo.GetType().FullName)" -ForegroundColor Gray
        if ($null -ne $tokenInfo.Token) {
            Write-Host "  Debug: Token property type was $($tokenInfo.Token.GetType().FullName)" -ForegroundColor Gray
        }
        Write-Host ""
        return
    }
    
    if ($token.Length -lt 50) {
        Write-Host "  [X] Token is too short ($($token.Length) chars)" -ForegroundColor Red
        Write-Host ""
        return
    }
    
    # Decode JWT to check audience (handle errors gracefully)
    try {
        $tokenParts = $token.Split('.')
        if ($tokenParts.Length -ge 2) {
            $payloadBytes = [Convert]::FromBase64String($tokenParts[1].PadRight(($tokenParts[1].Length + 3) -band -4, '='))
            $payloadJson = [System.Text.Encoding]::UTF8.GetString($payloadBytes)
            $payload = $payloadJson | ConvertFrom-Json
            
            Write-Host "  [OK] Token acquired successfully" -ForegroundColor Green
            Write-Host "    Token Audience: $($payload.aud)" -ForegroundColor Gray
        } else {
            Write-Host "  [OK] Token acquired successfully" -ForegroundColor Green
        }
    } catch {
        Write-Host "  [OK] Token acquired successfully" -ForegroundColor Green
        Write-Host "    (Unable to decode token audience)" -ForegroundColor Gray
    }
    Write-Host ""
} catch {
    Write-Host "  [X] Failed to acquire token" -ForegroundColor Red
    Write-Host "  Error: $_" -ForegroundColor Red
    Write-Host "  Error Type: $($_.Exception.GetType().FullName)" -ForegroundColor Red
    Write-Host ""
    return
}

# ============================================================================
# STEP 2: Create Upload Session
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
    # AppId is the API's app registration ID (hardcoded)
    $AppId = "a023625b-aa0e-4a24-a6e6-7c5b4e8d7663"
    
    # Use the session ID returned by the API, not the one we sent
    $ActualSessionId = $session.submissionId
    
    Write-Host "  [OK] Session created successfully" -ForegroundColor Green
    Write-Host "    Session ID: $ActualSessionId" -ForegroundColor Gray
    Write-Host "    Expires: $($session.expiresUtc)" -ForegroundColor Gray
    Write-Host "    Public Key: $($PublicKeyB64.Length) chars" -ForegroundColor Gray
    Write-Host ""
} catch {
    Write-Host "  [X] Failed to create session" -ForegroundColor Red
    Write-Host "  Error: $_" -ForegroundColor Red
    
    if ($_.ErrorDetails.Message) {
        Write-Host "  Response: $($_.ErrorDetails.Message)" -ForegroundColor Red
    }
    Write-Host ""
    return
}

# ============================================================================
# STEP 3: Encrypt Secret with RSA-OAEP-SHA256 (PowerShell 5.1 compatible)
# ============================================================================
Write-Host "[3/4] Encrypting secret with RSA-OAEP-SHA256..." -ForegroundColor Blue

try {
    # Decode the public key
    $publicKeyBytes = [Convert]::FromBase64String($PublicKeyB64)
    
    # Detect PowerShell version and use appropriate RSA encryption
    $psVersion = $PSVersionTable.PSVersion.Major
    
    if ($psVersion -ge 7) {
        # PowerShell 7+ - Use modern RSA API
        $rsa = [System.Security.Cryptography.RSA]::Create()
        $bytesRead = 0
        $rsa.ImportSubjectPublicKeyInfo($publicKeyBytes, [ref]$bytesRead)
        
        $secretBytes = [System.Text.Encoding]::UTF8.GetBytes($TestSecret)
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
        
        $secretBytes = [System.Text.Encoding]::UTF8.GetBytes($TestSecret)
        $padding = [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA256
        $encryptedBytes = $rsa.Encrypt($secretBytes, $padding)
        $encryptedB64 = [Convert]::ToBase64String($encryptedBytes)
        $rsa.Dispose()
    }
    
    Write-Host "  [OK] Secret encrypted successfully (PS $psVersion)" -ForegroundColor Green
    Write-Host "    Plaintext:  $($TestSecret.Length) bytes" -ForegroundColor Gray
    Write-Host "    Ciphertext: $($encryptedB64.Length) bytes (base64)" -ForegroundColor Gray
    Write-Host ""
} catch {
    Write-Host "  [X] Failed to encrypt secret" -ForegroundColor Red
    Write-Host "  Error: $_" -ForegroundColor Red
    Write-Host ""
    return
}

# ============================================================================
# STEP 4: Submit Encrypted Secret
# ============================================================================
Write-Host "[4/4] Submitting encrypted secret to API..." -ForegroundColor Blue
Write-Host "    URL: $BaseUrl/v1/upload-sessions/$ActualSessionId/submit" -ForegroundColor Gray

$submitBody = @{
    tenantId = $TenantId
    appId = $AppId
    displayName = "PowerShell 5.1 E2E Test Secret"
    secret = @{
        cipherTextB64 = $encryptedB64
        alg = "RSA-OAEP-256"
        expiresUtc = (Get-Date).AddDays(1).ToUniversalTime().ToString("o")
    }
    sentUtc = (Get-Date).ToUniversalTime().ToString("o")
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
    
    Write-Host "  [OK] Secret submitted and stored in Key Vault!" -ForegroundColor Green
    Write-Host "    Receipt ID:   $ReceiptId" -ForegroundColor Gray
    Write-Host "    Correlation:  $($receipt.correlationId)" -ForegroundColor Gray
    Write-Host ""
} catch {
    Write-Host "  [X] Failed to submit secret" -ForegroundColor Red
    Write-Host "  Error: $_" -ForegroundColor Red
    
    # Try to get response body
    if ($_.Exception.Response) {
        $responseStream = $_.Exception.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($responseStream)
        $responseBody = $reader.ReadToEnd()
        $reader.Close()
        $responseStream.Close()
        
        Write-Host "  API Response: $responseBody" -ForegroundColor Red
        
        try {
            $errorJson = $responseBody | ConvertFrom-Json
            if ($errorJson.error) {
                Write-Host "  Error Type: $($errorJson.error)" -ForegroundColor Red
            }
            if ($errorJson.message) {
                Write-Host "  Message: $($errorJson.message)" -ForegroundColor Red
            }
        } catch {
            # Response wasn't JSON
        }
    } elseif ($_.ErrorDetails.Message) {
        Write-Host "  Response: $($_.ErrorDetails.Message)" -ForegroundColor Red
    }
    Write-Host ""
    return
}

# ============================================================================
# Test Complete - Success!
# ============================================================================
Write-Host ""
Write-Host "============================================================================" -ForegroundColor Green
Write-Host "[SUCCESS] END-TO-END TEST PASSED!" -ForegroundColor Green
Write-Host "============================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
Write-Host "  [OK] Authenticated with Azure AD token" -ForegroundColor White
Write-Host "  [OK] Created upload session with ephemeral RSA-4096 keypair" -ForegroundColor White
Write-Host "  [OK] Encrypted secret locally using session public key (PS 5.1 + RSACng)" -ForegroundColor White
Write-Host "  [OK] Submitted encrypted secret via HTTPS" -ForegroundColor White
Write-Host "  [OK] Secret decrypted server-side and stored in Key Vault" -ForegroundColor White
Write-Host ""
Write-Host "Key Vault Details:" -ForegroundColor Yellow
Write-Host "  Vault:  https://secsecret-poc-kv-f6be.vault.azure.net/"
Write-Host "  Secret: $ReceiptId"
Write-Host ""
Write-Host "============================================================================" -ForegroundColor Cyan
Write-Host "The POC is fully functional with PowerShell 5.1!" -ForegroundColor Cyan
Write-Host "============================================================================" -ForegroundColor Cyan
Write-Host ""
