<#
    Claude Code - Corporate / Campus TLS Interception Fix (Windows)

    Problem:
        "API Error: Unable to connect to API: Self-signed certificate detected.
         Check your proxy or corporate SSL certificates"

        A firewall / VPN / antivirus is replacing the TLS certificate of
        api.anthropic.com. Windows (and your browser) trusts the replacement CA,
        but Node.js ships its own CA bundle and does not.

    What this script does:
        1. TLS handshake with api.anthropic.com:443 and prints the certificate ISSUER
        2. Saves the full certificate chain as PEM to %USERPROFILE%\proxy-ca.pem
        3. Sets NODE_EXTRA_CA_CERTS permanently (setx) and for the current session
        4. Verifies the variable and confirms the cert error is gone
        5. Prints HTTP_PROXY / HTTPS_PROXY / NO_PROXY

    What this script does NOT do:
        Nothing is deleted or modified. It only creates one .pem file and sets
        one user environment variable.

    Usage:
        Run in a normal (non-admin) PowerShell window.
        If script execution is blocked:
            powershell -ExecutionPolicy Bypass -File .\fix-claude-code-cert-windows.ps1
#>

$ErrorActionPreference = 'Continue'
$targetHost = 'api.anthropic.com'
$targetPort = 443
$pemPath    = Join-Path $env:USERPROFILE 'proxy-ca.pem'

# Windows stores that can hold the intercepting CA. Root/AuthRoot hold self-signed
# roots, CA holds intermediates. Both machine-wide and per-user are checked.
$certStores = @(
    'Cert:\LocalMachine\Root'
    'Cert:\LocalMachine\CA'
    'Cert:\LocalMachine\AuthRoot'
    'Cert:\CurrentUser\Root'
    'Cert:\CurrentUser\CA'
)

function Write-Step {
    param([int]$Number, [string]$Title)
    Write-Host ""
    Write-Host ('=' * 64) -ForegroundColor DarkCyan
    Write-Host " STEP $Number : $Title" -ForegroundColor Cyan
    Write-Host ('=' * 64) -ForegroundColor DarkCyan
}

# A chain element can carry a null or empty certificate; exporting one throws.
function Test-UsableCert {
    param($Cert)
    return ($null -ne $Cert -and $null -ne $Cert.RawData -and $Cert.RawData.Length -gt 0)
}

function Find-CertBySubject {
    param([string]$Subject)
    foreach ($store in $certStores) {
        $hit = Get-ChildItem $store -ErrorAction SilentlyContinue |
                   Where-Object { $_.Subject -eq $Subject -and (Test-UsableCert $_) } |
                   Select-Object -First 1
        if ($hit) { return $hit }
    }
    return $null
}

# ---------------------------------------------------------------------------
Write-Step 1 'TLS handshake -> who is issuing the certificate?'
# ---------------------------------------------------------------------------
$chainCerts = @()
$leaf       = $null
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $tcp = New-Object System.Net.Sockets.TcpClient
    $tcp.Connect($targetHost, $targetPort)
    Write-Host "TCP connect OK -> ${targetHost}:${targetPort}" -ForegroundColor Green

    # Accept any certificate on purpose: we want to INSPECT it, not trust it.
    # The callback also hands us the chain .NET assembled from what the server
    # actually sent on the wire - that is where the intermediates come from.
    $script:wireChain = @()
    $acceptAll = [System.Net.Security.RemoteCertificateValidationCallback] {
        param($senderObj, $certificate, $chain, $sslErrors)
        if ($chain -and $chain.ChainElements) {
            $script:wireChain = @($chain.ChainElements | ForEach-Object { $_.Certificate })
        }
        return $true
    }
    $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, $acceptAll)
    $ssl.AuthenticateAsClient($targetHost)

    $leaf = [System.Security.Cryptography.X509Certificates.X509Certificate2]$ssl.RemoteCertificate

    Write-Host ""
    Write-Host "  SUBJECT    : $($leaf.Subject)"
    Write-Host "  ISSUER     : $($leaf.Issuer)" -ForegroundColor Yellow
    Write-Host "  VALID FROM : $($leaf.NotBefore)"
    Write-Host "  VALID TO   : $($leaf.NotAfter)"
    Write-Host "  THUMBPRINT : $($leaf.Thumbprint)"
    Write-Host "  TLS PROTO  : $($ssl.SslProtocol)"
    Write-Host ""

    $publicCaPattern = "DigiCert|Amazon|Let's Encrypt|Google Trust|ISRG|Sectigo|GlobalSign|Baltimore"
    if ($leaf.Issuer -match $publicCaPattern) {
        Write-Host '  >> Issuer looks like a PUBLIC CA - probably no interception.' -ForegroundColor Green
        Write-Host '  >> If the error persists, suspect HTTP(S)_PROXY or antivirus SSL scanning.' -ForegroundColor Green
    } else {
        Write-Host '  >> INTERCEPTION CONFIRMED - this is not a public CA.' -ForegroundColor Red
        Write-Host '  >> The ISSUER name above tells you which firewall / VPN / antivirus is doing it.' -ForegroundColor Red
    }

    $ssl.Dispose()
    $tcp.Close()
}
catch {
    Write-Host "  HANDSHAKE FAILED: $($_.Exception.Message)" -ForegroundColor Red
}

# --- Assemble the chain -----------------------------------------------------
# NODE_EXTRA_CA_CERTS needs the CA certificates, not the leaf. A leaf-only PEM
# looks like it worked but Node still fails with SELF_SIGNED_CERT_IN_CHAIN, so
# every source below is tried and the result is checked before we call it done.
if ($leaf) {
    $chainCerts = @($leaf)

    # Source A: chain .NET built during the handshake (server-supplied intermediates)
    foreach ($cert in $script:wireChain) {
        if (-not (Test-UsableCert $cert)) { continue }
        if (@($chainCerts | ForEach-Object { $_.Thumbprint }) -notcontains $cert.Thumbprint) {
            $chainCerts += $cert
        }
    }

    # Source B: walk up through the Windows trust stores. The intercepting root is
    # installed there (that is why browsers work) but is not sent on the wire.
    $current = $chainCerts[-1]
    for ($hop = 0; $hop -lt 10; $hop++) {
        if ($current.Subject -eq $current.Issuer) { break }   # reached a self-signed root
        $issuer = Find-CertBySubject -Subject $current.Issuer
        if (-not $issuer) { break }
        if (@($chainCerts | ForEach-Object { $_.Thumbprint }) -contains $issuer.Thumbprint) { break }
        $chainCerts += $issuer
        Write-Host "  + Pulled from Windows trust store: $($issuer.Subject)" -ForegroundColor Green
        $current = $issuer
    }

    Write-Host ""
    Write-Host "  Chain assembled - $($chainCerts.Count) certificate(s):"
    for ($i = 0; $i -lt $chainCerts.Count; $i++) {
        Write-Host ("   [{0}] {1}" -f $i, $chainCerts[$i].Subject)
    }

    # Did we actually capture the CA that signed the leaf? Without it the PEM is useless.
    $haveIssuingCa = @($chainCerts | Where-Object { $_.Subject -eq $leaf.Issuer }).Count -gt 0

    if (-not $haveIssuingCa) {
        Write-Host ""
        Write-Host "  !! The issuing CA ($($leaf.Issuer)) was not found on the wire" -ForegroundColor Yellow
        Write-Host '  !! or in the Windows trust stores. Falling back to exporting every' -ForegroundColor Yellow
        Write-Host '  !! root Windows already trusts, so Node trusts what Windows trusts.' -ForegroundColor Yellow

        $allRoots = @(
            Get-ChildItem Cert:\LocalMachine\Root, Cert:\CurrentUser\Root, Cert:\LocalMachine\CA -ErrorAction SilentlyContinue
        )
        $known = @($chainCerts | ForEach-Object { $_.Thumbprint })
        $added = 0
        foreach ($root in $allRoots) {
            if (-not (Test-UsableCert $root)) { continue }
            if ($known -notcontains $root.Thumbprint) {
                $chainCerts += $root
                $known += $root.Thumbprint
                $added++
            }
        }
        Write-Host "  Fallback added $added certificate(s) from the Windows stores." -ForegroundColor Yellow
    }

    # Final guard so the PEM writer never sees an unusable entry.
    $chainCerts = @($chainCerts | Where-Object { Test-UsableCert $_ })
}

# ---------------------------------------------------------------------------
Write-Step 2 "Save the certificate chain as PEM"
# ---------------------------------------------------------------------------
if ($chainCerts.Count -eq 0) {
    Write-Host '  No certificates captured - cannot write the PEM file. Stopping here.' -ForegroundColor Red
} else {
    $pemLines = New-Object System.Collections.Generic.List[string]
    foreach ($cert in $chainCerts) {
        $pemLines.Add("# Subject: $($cert.Subject)")
        $pemLines.Add("# Issuer : $($cert.Issuer)")
        $pemLines.Add('-----BEGIN CERTIFICATE-----')
        $b64 = [Convert]::ToBase64String($cert.RawData)
        for ($pos = 0; $pos -lt $b64.Length; $pos += 64) {
            $pemLines.Add($b64.Substring($pos, [Math]::Min(64, $b64.Length - $pos)))
        }
        $pemLines.Add('-----END CERTIFICATE-----')
        $pemLines.Add('')
    }

    # ASCII, no BOM - OpenSSL/Node reject a BOM at the start of a PEM file.
    [System.IO.File]::WriteAllLines($pemPath, $pemLines, (New-Object System.Text.ASCIIEncoding))

    $certCount = @(Select-String -Path $pemPath -Pattern 'BEGIN CERTIFICATE').Count
    Write-Host "  Saved -> $pemPath" -ForegroundColor Green
    Write-Host "  Size  : $((Get-Item $pemPath).Length) bytes"
    Write-Host "  Certs : $certCount"

    if ($certCount -le 1) {
        Write-Host ""
        Write-Host '  WARNING: only the server certificate was captured - no CA.' -ForegroundColor Red
        Write-Host '  Node needs the CA, so this file alone will NOT fix the error.' -ForegroundColor Red
        Write-Host '  Export the CA by hand instead:' -ForegroundColor Red
        Write-Host '    1. Win+R -> certmgr.msc -> Trusted Root Certification Authorities -> Certificates' -ForegroundColor Red
        Write-Host "    2. Find the CA named in the ISSUER line above: $(if ($leaf) { $leaf.Issuer })" -ForegroundColor Red
        Write-Host '    3. Right-click -> All Tasks -> Export -> Base-64 encoded X.509 (.CER)' -ForegroundColor Red
        Write-Host "    4. Save it over $pemPath and re-run this script" -ForegroundColor Red
    }

    Write-Host ""
    Write-Host '  --- head of file ---' -ForegroundColor DarkGray
    Get-Content $pemPath -TotalCount 6 | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }
}

# ---------------------------------------------------------------------------
Write-Step 3 'Set NODE_EXTRA_CA_CERTS (permanent + current session)'
# ---------------------------------------------------------------------------
if (Test-Path $pemPath) {
    $previous = [Environment]::GetEnvironmentVariable('NODE_EXTRA_CA_CERTS', 'User')
    if ($previous) {
        Write-Host "  Previous value : $previous"
    } else {
        Write-Host '  Previous value : <not set>'
    }

    setx NODE_EXTRA_CA_CERTS "$pemPath" | Out-Null   # persists for future processes
    $env:NODE_EXTRA_CA_CERTS = $pemPath              # applies to this session now

    Write-Host "  New value      : $pemPath" -ForegroundColor Green
    Write-Host '  (setx only affects NEW processes - already-running terminals keep the old value)' -ForegroundColor Yellow
} else {
    Write-Host '  PEM file missing - environment variable not set.' -ForegroundColor Red
}

# ---------------------------------------------------------------------------
Write-Step 4 'Verify: is the variable set, and is the cert error gone?'
# ---------------------------------------------------------------------------
Write-Host "  Session  (`$env:) : $env:NODE_EXTRA_CA_CERTS"
Write-Host "  Persisted (User) : $([Environment]::GetEnvironmentVariable('NODE_EXTRA_CA_CERTS','User'))"
if ($env:NODE_EXTRA_CA_CERTS) {
    Write-Host "  File exists      : $(Test-Path $env:NODE_EXTRA_CA_CERTS)"
}
Write-Host ""

# Test A - .NET / PowerShell. Uses the Windows trust store, so this normally
# passes even before the fix. It tells you whether the network path itself works.
Write-Host '  [Test A] PowerShell HTTPS request...' -ForegroundColor Cyan
try {
    $resp = Invoke-WebRequest -Uri "https://$targetHost/v1/models" -Method GET -TimeoutSec 20 -UseBasicParsing
    Write-Host "  TLS OK - HTTP $($resp.StatusCode)" -ForegroundColor Green
} catch {
    if ($_.Exception.Response) {
        $code = [int]$_.Exception.Response.StatusCode
        Write-Host "  TLS OK - HTTP $code (401 is expected, no API key was sent)" -ForegroundColor Green
    } else {
        Write-Host "  FAILED: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Test B - Node.js. This is the one that matters: Claude Code runs on Node.
Write-Host ""
Write-Host '  [Test B] Node.js HTTPS request (the real test)...' -ForegroundColor Cyan
$node = Get-Command node -ErrorAction SilentlyContinue
if ($node) {
    Write-Host "  Node : $(node -v)  ($($node.Source))"
    $js = 'const https=require("https");' +
          'https.get("https://api.anthropic.com/v1/models",r=>{' +
          'console.log("  NODE TLS OK   -> HTTP "+r.statusCode+"  (401 expected - certificate problem solved)");' +
          'process.exit(0)}).on("error",e=>{' +
          'console.log("  NODE TLS FAIL -> "+(e.code||e.message));process.exit(1)});'
    node -e $js
    if ($LASTEXITCODE -eq 0) {
        Write-Host '  >> Certificate issue is FIXED.' -ForegroundColor Green
    } else {
        Write-Host '  >> Still failing. Two likely causes:' -ForegroundColor Red
        Write-Host '     - SELF_SIGNED_CERT_IN_CHAIN / UNABLE_TO_GET_ISSUER_CERT_LOCALLY:' -ForegroundColor Red
        Write-Host '       the PEM is missing the CA. See the manual export steps in STEP 2.' -ForegroundColor Red
        Write-Host '     - ECONNREFUSED / ETIMEDOUT / 407: a proxy problem, not a certificate' -ForegroundColor Red
        Write-Host '       problem. Check the variables printed in STEP 5.' -ForegroundColor Red
    }
} else {
    Write-Host '  node not found on PATH - skipping Test B.' -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
Write-Step 5 'Proxy environment variables'
# ---------------------------------------------------------------------------
foreach ($name in 'HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY', 'http_proxy', 'https_proxy', 'no_proxy') {
    $proc    = [Environment]::GetEnvironmentVariable($name, 'Process')
    $user    = [Environment]::GetEnvironmentVariable($name, 'User')
    $machine = [Environment]::GetEnvironmentVariable($name, 'Machine')
    if ($proc -or $user -or $machine) {
        Write-Host ("  {0,-12} Process={1}  User={2}  Machine={3}" -f $name, $proc, $user, $machine) -ForegroundColor Yellow
    } else {
        Write-Host ("  {0,-12} <not set>" -f $name) -ForegroundColor DarkGray
    }
}

Write-Host ""
Write-Host '  WinINET system proxy (Internet Options):' -ForegroundColor Cyan
$inet = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
Write-Host "    ProxyEnable   : $($inet.ProxyEnable)"
Write-Host "    ProxyServer   : $($inet.ProxyServer)"
Write-Host "    AutoConfigURL : $($inet.AutoConfigURL)"

Write-Host ""
Write-Host ('=' * 64) -ForegroundColor DarkCyan
Write-Host " DONE" -ForegroundColor Cyan
Write-Host "   PEM                 : $pemPath"
Write-Host "   NODE_EXTRA_CA_CERTS : persisted to the User environment"
Write-Host ""
Write-Host "   Now fully close VS Code (all windows) and reopen it." -ForegroundColor Yellow
Write-Host "   'Reload Window' is NOT enough - the process must restart to pick up setx." -ForegroundColor Yellow
Write-Host ('=' * 64) -ForegroundColor DarkCyan
