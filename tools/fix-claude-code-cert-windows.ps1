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
        2. Saves the certificate chain as PEM to %USERPROFILE%\proxy-ca.pem
        3. Sets NODE_EXTRA_CA_CERTS permanently (setx) and for the current session
        4. Tests with Node.js and, if that fails, widens the bundle and retries
           on its own before asking you to do anything by hand
        5. Prints HTTP_PROXY / HTTPS_PROXY / NO_PROXY

    What this script does NOT do:
        Nothing is deleted. An existing proxy-ca.pem is backed up and its
        certificates are kept. It creates one .pem file and sets one user
        environment variable.

    Usage:
        Run in a normal (non-admin) PowerShell window.
        If script execution is blocked:
            powershell -ExecutionPolicy Bypass -File .\fix-claude-code-cert-windows.ps1
#>

$ErrorActionPreference = 'Continue'
$targetHost = 'api.anthropic.com'
$targetPort = 443
$testUrl    = "https://$targetHost/v1/models"
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

# Pull the raw PEM blocks out of an existing bundle so a previously configured
# NODE_EXTRA_CA_CERTS file can be carried over instead of being replaced.
function Get-PemBlock {
    param([string]$Path)
    $blocks = @()
    if ([string]::IsNullOrEmpty($Path) -or -not (Test-Path $Path)) { return $blocks }
    $text = Get-Content -Path $Path -Raw -ErrorAction SilentlyContinue
    if (-not $text) { return $blocks }
    $pattern = [regex]'(?s)-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----'
    foreach ($match in $pattern.Matches($text)) { $blocks += $match.Value }
    return $blocks
}

# Whitespace-insensitive identity for a PEM block, used to avoid duplicates.
function Get-PemBody {
    param([string]$Block)
    return ($Block -replace '-----[A-Z ]+-----', '' -replace '\s', '')
}

# Read back the finished bundle, so certificates that arrived by any route -
# handshake, trust store, carry-over, manual export - are checked the same way.
function Get-PemCert {
    param([string]$Path)
    $certs = @()
    foreach ($block in (Get-PemBlock -Path $Path)) {
        try {
            $bytes  = [Convert]::FromBase64String((Get-PemBody $block))
            $certs += New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (, [byte[]]$bytes)
        } catch {
            continue
        }
    }
    return $certs
}

# NODE_EXTRA_CA_CERTS is only useful for CA certificates. Note that the CA named
# in the leaf's ISSUER field does not have to be in the bundle: it is often an
# intermediate sent during the handshake, anchored by a root that is.
function Test-IsCaCert {
    param($Cert)
    foreach ($ext in $Cert.Extensions) {
        if ($ext.Oid.Value -eq '2.5.29.19') {
            $basic = $ext -as [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]
            if ($basic -and $basic.CertificateAuthority) { return $true }
        }
    }
    return $false
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

# Everything Windows itself trusts. Used when the targeted search comes up short:
# making Node trust what Windows trusts is the whole point of the exercise.
function Get-AllStoreCert {
    return @(Get-ChildItem Cert:\LocalMachine\Root, Cert:\CurrentUser\Root, Cert:\LocalMachine\CA `
                 -ErrorAction SilentlyContinue | Where-Object { Test-UsableCert $_ })
}

function Find-NodeExe {
    $found = Get-Command node -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found) { return $found.Source }

    # VS Code and the Claude Code installer can leave node off the PATH.
    $candidates = @()
    foreach ($root in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
        if ($root) { $candidates += (Join-Path $root 'nodejs\node.exe') }
    }
    if ($env:LOCALAPPDATA) { $candidates += (Join-Path $env:LOCALAPPDATA 'Programs\nodejs\node.exe') }
    if ($env:APPDATA)      { $candidates += (Join-Path $env:APPDATA 'nvm\node.exe') }

    foreach ($candidate in $candidates) {
        if (Test-Path $candidate) { return $candidate }
    }
    return $null
}

# Writes the bundle, carrying over certificates from the file being replaced and
# from any other bundle NODE_EXTRA_CA_CERTS already points at. A write that would
# change nothing is skipped entirely, so re-runs do not pile up backups.
function Save-CaBundle {
    param($Certs, [string]$Path, [string]$PreviousCaFile)

    $existingBlocks = @(Get-PemBlock -Path $Path)

    $pemLines   = New-Object System.Collections.Generic.List[string]
    $seenBodies = @()
    foreach ($cert in $Certs) {
        $b64 = [Convert]::ToBase64String($cert.RawData)
        if ($seenBodies -contains $b64) { continue }
        $seenBodies += $b64
        $pemLines.Add("# Subject: $($cert.Subject)")
        $pemLines.Add("# Issuer : $($cert.Issuer)")
        $pemLines.Add('-----BEGIN CERTIFICATE-----')
        for ($pos = 0; $pos -lt $b64.Length; $pos += 64) {
            $pemLines.Add($b64.Substring($pos, [Math]::Min(64, $b64.Length - $pos)))
        }
        $pemLines.Add('-----END CERTIFICATE-----')
        $pemLines.Add('')
    }

    # An ordered hashtable, not an array of pairs: "+= ,@(a,b)" nests the pair one
    # level deeper than expected and the inner list comes back empty.
    $carryOver = [ordered]@{}
    $carryOver['the previous ' + (Split-Path $Path -Leaf)] = $existingBlocks
    if ($PreviousCaFile -and $PreviousCaFile -ne $Path -and (Test-Path $PreviousCaFile)) {
        $carryOver[$PreviousCaFile] = @(Get-PemBlock -Path $PreviousCaFile)
    }

    foreach ($label in @($carryOver.Keys)) {
        $carried = 0
        foreach ($block in @($carryOver[$label])) {
            if ($seenBodies -notcontains (Get-PemBody $block)) {
                $seenBodies += (Get-PemBody $block)
                $pemLines.Add("# Carried over from $label")
                foreach ($line in ($block -split "`r?`n")) { $pemLines.Add($line) }
                $pemLines.Add('')
                $carried++
            }
        }
        if ($carried -gt 0) {
            Write-Host "  Carried over $carried certificate(s) from $label" -ForegroundColor Green
        }
    }

    $existingBodies = @($existingBlocks | ForEach-Object { Get-PemBody $_ } | Sort-Object) -join '|'
    $newBodies      = @($seenBodies | Sort-Object) -join '|'

    if ((Test-Path $Path) -and $existingBodies -eq $newBodies) {
        Write-Host '  Bundle already holds exactly these certificates - left untouched.' -ForegroundColor Green
    } else {
        # Never destroy an existing bundle: keep a timestamped copy first.
        if (Test-Path $Path) {
            $backupPath = "$Path.bak-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
            Copy-Item -Path $Path -Destination $backupPath -Force
            Write-Host "  Existing file backed up -> $backupPath" -ForegroundColor Yellow
        }
        # ASCII, no BOM - OpenSSL/Node reject a BOM at the start of a PEM file.
        [System.IO.File]::WriteAllLines($Path, $pemLines, (New-Object System.Text.ASCIIEncoding))
    }

    $pemCerts = @(Get-PemCert -Path $Path)
    $caCerts  = @($pemCerts | Where-Object { Test-IsCaCert $_ })

    Write-Host "  Saved -> $Path" -ForegroundColor Green
    Write-Host "  Size  : $((Get-Item $Path).Length) bytes"
    Write-Host "  Certs : $($pemCerts.Count) ($($caCerts.Count) of them CA certificates)"

    return New-Object PSObject -Property @{
        Total   = $pemCerts.Count
        CaCount = $caCerts.Count
    }
}

# The decisive test: Claude Code runs on Node, so Node is what has to be happy.
function Invoke-NodeTlsTest {
    param([string]$NodeExe, [string]$Url)
    $js = 'const https=require("https");' +
          "https.get('$Url',r=>{" +
          'console.log("  NODE TLS OK   -> HTTP "+r.statusCode+"  (401 expected - certificate problem solved)");' +
          'process.exit(0)}).on("error",e=>{' +
          'console.log("  NODE TLS FAIL -> "+(e.code||e.message));process.exit(1)});'

    # Capture node's output instead of letting it fall into the pipeline: it
    # would be returned alongside the boolean and the caller would get an array,
    # which is truthy no matter how the test went.
    $output = & $NodeExe -e $js 2>&1
    $passed = ($LASTEXITCODE -eq 0)
    foreach ($line in $output) { Write-Host $line }
    return $passed
}

# ---------------------------------------------------------------------------
Write-Step 1 'TLS handshake -> who is issuing the certificate?'
# ---------------------------------------------------------------------------
$chainCerts    = @()
$leaf          = $null
$haveIssuingCa = $false
$caCount       = 0
$totalCount    = 0
$persistOk     = $false
$nodeOk        = $false
$escalated     = $false
$nodeExe       = Find-NodeExe

try {
    # Add TLS 1.2 rather than replacing whatever is already enabled, so nothing
    # the session had configured is turned off.
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

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
if ($leaf) {
    $chainCerts = @($leaf)

    # Source A: chain .NET built during the handshake (server-supplied intermediates)
    foreach ($cert in $script:wireChain) {
        if (-not (Test-UsableCert $cert)) { continue }
        if (@($chainCerts | ForEach-Object { $_.Thumbprint }) -notcontains $cert.Thumbprint) {
            $chainCerts += $cert
        }
    }

    # Source A2: build the chain explicitly. Belt and braces - if the validation
    # delegate above did not populate (it is invoked through a .NET callback,
    # which behaves differently across PowerShell versions) this still finds the
    # intermediates the platform can resolve.
    try {
        $x509chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
        $x509chain.ChainPolicy.RevocationMode    = 'NoCheck'
        $x509chain.ChainPolicy.VerificationFlags = 'AllFlags'
        [void]$x509chain.Build($leaf)
        foreach ($element in $x509chain.ChainElements) {
            $cert = $element.Certificate
            if (-not (Test-UsableCert $cert)) { continue }
            if (@($chainCerts | ForEach-Object { $_.Thumbprint }) -notcontains $cert.Thumbprint) {
                $chainCerts += $cert
            }
        }
    } catch {
        Write-Host "  (chain build skipped: $($_.Exception.Message))" -ForegroundColor DarkGray
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

    $haveIssuingCa = @($chainCerts | Where-Object { $_.Subject -eq $leaf.Issuer }).Count -gt 0

    # Without Node there is no way to test empirically, so widen the bundle now
    # rather than shipping one that might be missing the anchor.
    if (-not $haveIssuingCa -and -not $nodeExe) {
        Write-Host ''
        Write-Host '  Issuing CA not found and node is unavailable to test with -' -ForegroundColor Yellow
        Write-Host '  including every root Windows trusts as a precaution.' -ForegroundColor Yellow
        $chainCerts += Get-AllStoreCert
        $escalated = $true
    }

    # Final guard so the PEM writer never sees an unusable entry.
    $chainCerts = @($chainCerts | Where-Object { Test-UsableCert $_ })
}

# ---------------------------------------------------------------------------
Write-Step 2 'Save the certificate chain as PEM'
# ---------------------------------------------------------------------------
$previousCaFile = [Environment]::GetEnvironmentVariable('NODE_EXTRA_CA_CERTS', 'User')

if ($chainCerts.Count -eq 0) {
    Write-Host '  No certificates captured - cannot write the PEM file. Stopping here.' -ForegroundColor Red
} else {
    $result     = Save-CaBundle -Certs $chainCerts -Path $pemPath -PreviousCaFile $previousCaFile
    $caCount    = $result.CaCount
    $totalCount = $result.Total
}

# ---------------------------------------------------------------------------
Write-Step 3 'Set NODE_EXTRA_CA_CERTS (permanent + current session)'
# ---------------------------------------------------------------------------
if (Test-Path $pemPath) {
    if ($previousCaFile) {
        Write-Host "  Previous value : $previousCaFile"
        Write-Host '  (its certificates were carried into the new bundle in STEP 2)' -ForegroundColor DarkGray
    } else {
        Write-Host '  Previous value : <not set>'
    }

    # setx silently truncates values longer than 1024 characters.
    if ($pemPath.Length -gt 1024) {
        Write-Host '  Path is longer than 1024 chars - setx would truncate it.' -ForegroundColor Red
    }

    $setx = Get-Command setx -ErrorAction SilentlyContinue
    if ($setx) {
        & $setx.Source NODE_EXTRA_CA_CERTS "$pemPath" | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Host "  setx exited with code $LASTEXITCODE - trying the .NET API instead." -ForegroundColor Yellow
        }
    } else {
        Write-Host '  setx not found - using the .NET API instead.' -ForegroundColor Yellow
    }

    # Read back rather than trusting the call, and fall back if it did not stick.
    if ([Environment]::GetEnvironmentVariable('NODE_EXTRA_CA_CERTS', 'User') -ne $pemPath) {
        try {
            [Environment]::SetEnvironmentVariable('NODE_EXTRA_CA_CERTS', $pemPath, 'User')
        } catch {
            Write-Host "  Could not persist the variable: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    $persistOk = ([Environment]::GetEnvironmentVariable('NODE_EXTRA_CA_CERTS', 'User') -eq $pemPath)

    $env:NODE_EXTRA_CA_CERTS = $pemPath   # applies to this session immediately

    Write-Host "  New value      : $pemPath" -ForegroundColor Green
    if ($persistOk) {
        Write-Host '  Persisted      : YES (verified by reading it back)' -ForegroundColor Green
    } else {
        Write-Host '  Persisted      : NO - only this session has it.' -ForegroundColor Red
        Write-Host '  Set it by hand: System Properties -> Environment Variables -> New' -ForegroundColor Red
    }
    Write-Host '  (only NEW processes see it - already-running terminals keep the old value)' -ForegroundColor Yellow
} else {
    Write-Host '  PEM file missing - environment variable not set.' -ForegroundColor Red
}

# ---------------------------------------------------------------------------
Write-Step 4 'Verify, and widen the bundle automatically if it is not enough'
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
    $resp = Invoke-WebRequest -Uri $testUrl -Method GET -TimeoutSec 20 -UseBasicParsing
    Write-Host "  TLS OK - HTTP $($resp.StatusCode)" -ForegroundColor Green
} catch {
    if ($_.Exception.Response) {
        $code = [int]$_.Exception.Response.StatusCode
        Write-Host "  TLS OK - HTTP $code (401 is expected, no API key was sent)" -ForegroundColor Green
    } else {
        Write-Host "  FAILED: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host '  [Test B] Node.js HTTPS request (the decisive one)...' -ForegroundColor Cyan
if ($nodeExe) {
    Write-Host "  Node : $(& $nodeExe -v)  ($nodeExe)"
    $nodeOk = Invoke-NodeTlsTest -NodeExe $nodeExe -Url $testUrl

    # Self-repair: rather than telling you to export the CA by hand, put every
    # root Windows trusts into the bundle and test again.
    if (-not $nodeOk -and -not $escalated -and $chainCerts.Count -gt 0) {
        Write-Host ""
        Write-Host '  Not enough. Widening the bundle to every root Windows trusts...' -ForegroundColor Yellow
        $before = $chainCerts.Count
        $known  = @($chainCerts | ForEach-Object { $_.Thumbprint })
        foreach ($cert in (Get-AllStoreCert)) {
            if ($known -notcontains $cert.Thumbprint) {
                $chainCerts += $cert
                $known      += $cert.Thumbprint
            }
        }
        $escalated = $true
        Write-Host "  Added $($chainCerts.Count - $before) certificate(s) from the Windows stores." -ForegroundColor Yellow

        $result     = Save-CaBundle -Certs $chainCerts -Path $pemPath -PreviousCaFile $previousCaFile
        $caCount    = $result.CaCount
        $totalCount = $result.Total

        Write-Host ""
        Write-Host '  Retesting with the widened bundle...' -ForegroundColor Cyan
        $nodeOk = Invoke-NodeTlsTest -NodeExe $nodeExe -Url $testUrl
    }

    if ($nodeOk) {
        Write-Host '  >> Certificate issue is FIXED.' -ForegroundColor Green
    } else {
        Write-Host ''
        Write-Host '  >> Could not fix it automatically. What the error code means:' -ForegroundColor Red
        Write-Host '     SELF_SIGNED_CERT_IN_CHAIN / UNABLE_TO_GET_ISSUER_CERT_LOCALLY' -ForegroundColor Red
        Write-Host '       The CA is not installed on this machine at all. Export it:' -ForegroundColor Red
        Write-Host '       certmgr.msc -> Trusted Root Certification Authorities -> Certificates,' -ForegroundColor Red
        Write-Host "       find $(if ($leaf) { $leaf.Issuer }), right-click ->" -ForegroundColor Red
        Write-Host '       All Tasks -> Export -> Base-64 encoded X.509, save it over' -ForegroundColor Red
        Write-Host "       $pemPath and re-run this script." -ForegroundColor Red
        Write-Host '     ECONNREFUSED / ETIMEDOUT / 407 / ENOTFOUND' -ForegroundColor Red
        Write-Host '       Not a certificate problem - see the proxy variables in STEP 5.' -ForegroundColor Red
    }
} else {
    Write-Host '  node not found - skipping Test B. Open a new terminal and run:' -ForegroundColor Yellow
    Write-Host "    node -e `"require('https').get('$testUrl',r=>console.log(r.statusCode))`"" -ForegroundColor Yellow
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

# ---------------------------------------------------------------------------
Write-Host ""
Write-Host ('=' * 64) -ForegroundColor DarkCyan
Write-Host ' SUMMARY' -ForegroundColor Cyan
Write-Host ('=' * 64) -ForegroundColor DarkCyan

function Write-Check {
    param([bool]$Ok, [string]$Label, [string]$Detail = '')
    $mark = if ($Ok) { '[ OK ]' } else { '[FAIL]' }
    Write-Host ("   $mark  $Label $Detail") -ForegroundColor $(if ($Ok) { 'Green' } else { 'Red' })
}

$pemOk = Test-Path $pemPath
Write-Check $pemOk               'PEM file written             ' $pemPath
Write-Check ($caCount -gt 0)     'CA certificate(s) in bundle  ' "$caCount of $totalCount"
Write-Check $persistOk           'NODE_EXTRA_CA_CERTS persisted'
if ($nodeExe) {
    Write-Check $nodeOk          'Node.js TLS test             ' $(if ($escalated) { '(after widening the bundle)' } else { '' })
} else {
    Write-Host '   [SKIP]  Node.js TLS test              node not found' -ForegroundColor Yellow
}

Write-Host ""
# The Node test is the authoritative one - it exercises exactly what Claude Code
# does. The other checks only explain a failure when it does not pass.
$fixed = if ($nodeExe) { $nodeOk } else { $pemOk -and $caCount -gt 0 }

if ($fixed -and $persistOk) {
    Write-Host '   All checks passed.' -ForegroundColor Green
    Write-Host '   Now fully close VS Code (all windows) and reopen it.' -ForegroundColor Yellow
    Write-Host "   'Reload Window' is NOT enough - the process must restart to see the variable." -ForegroundColor Yellow
} elseif ($fixed -and -not $persistOk) {
    Write-Host '   TLS works, but the variable did not persist. It will be lost when this' -ForegroundColor Yellow
    Write-Host '   window closes - set it by hand under Environment Variables.' -ForegroundColor Yellow
} else {
    Write-Host '   Some checks failed - re-read the [FAIL] lines above before restarting.' -ForegroundColor Red
    Write-Host '   Restarting VS Code will not help until they pass.' -ForegroundColor Red
}
Write-Host ('=' * 64) -ForegroundColor DarkCyan
