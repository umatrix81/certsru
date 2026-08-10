<#
.SYNOPSIS
    Install (or refresh) the name-constrained CA pair into the Windows certificate stores.

.DESCRIPTION
    Imports myroot.crt as a trusted root and russian-root-constrained.crt as an
    intermediate. Re-running replaces the previously installed pair: certificates
    this script installed are tagged via FriendlyName, so old copies are found and
    removed even after the root's Common Name has changed.

    The unconstrained Russian root must NOT be trusted -- if it is, path building
    routes around the constrained cross-certificate and the constraint enforces
    nothing. The script detects that and refuses to continue unless you pass
    -RemoveUnconstrained.

.PARAMETER Machine
    Install into LocalMachine instead of CurrentUser. Requires elevation.

.PARAMETER RemoveUnconstrained
    Delete the unconstrained Russian root from the trust stores if present.

.PARAMETER Uninstall
    Remove everything this script installed, then exit.

.PARAMETER ShowOnly
    Print the certificates and their thumbprints, install nothing. Use this to
    verify a copy you received from someone else before running it.

.PARAMETER Export
    Write the certificates out as .crt files into the given directory and exit.
    Firefox keeps its own trust store and cannot be scripted here, so export
    first and import them by hand.

.EXAMPLE
    .\install-certs.ps1
.EXAMPLE
    .\install-certs.ps1 -Machine -RemoveUnconstrained
.EXAMPLE
    .\install-certs.ps1 -WhatIf
.EXAMPLE
    .\install-certs.ps1 -ShowOnly
.EXAMPLE
    .\install-certs.ps1 -Export .\certs
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [switch]$Machine,
    [switch]$RemoveUnconstrained,
    [switch]$Uninstall,
    [string]$Export,
    [switch]$ShowOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Tag = '[constrained-ru]'

# Certificates are embedded below by ./add-domain.sh when this script is staged,
# making the staged copy a single self-contained file. The copy in the source
# tree keeps this list empty and reads the .crt files beside it instead.
$EmbeddedCerts = @(
#<<<EMBEDDED>>>
)

$Location = if ($Machine) {
    [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
} else {
    [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
}

function Test-Elevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $id).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function New-CertFromB64([string]$B64) {
    $der = [Convert]::FromBase64String(($B64 -replace '\s', ''))
    New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (,$der)
}

function Read-Cert([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { throw "missing certificate file: $Path" }
    try {
        return New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $Path
    } catch {
        # Fallback for PEM on runtimes whose constructor rejects it.
        $text = Get-Content -LiteralPath $Path -Raw
        $m = [regex]::Match($text, '(?s)-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----')
        if (-not $m.Success) { throw "not a PEM certificate: $Path" }
        $der = [Convert]::FromBase64String(($m.Groups[1].Value -replace '\s', ''))
        return New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (,$der)
    }
}

# Certificates returned by X509Store.Certificates are cloned contexts that are not
# bound to the store, so assigning FriendlyName to them fails with "Access is
# denied". The Cert: provider hands back store-backed objects that accept it.
# The label is cosmetic -- never let a failure here abort the install.
function Set-FriendlyNameSafe {
    param([string]$StoreName, [string]$Thumbprint, [string]$Friendly)

    $path = "Cert:\$($Location.ToString())\$StoreName\$Thumbprint"
    try {
        $item = Get-Item -LiteralPath $path -ErrorAction Stop
        if ($item.FriendlyName -eq $Friendly) { return $true }
        $item.FriendlyName = $Friendly
        return $true
    } catch {
        Write-Warning "could not set friendly name on $StoreName\$Thumbprint : $($_.Exception.Message)"
        Write-Warning "cosmetic only, the certificate is installed and working -- set the label by hand in certmgr.msc if you want it"
        return $false
    }
}

function Use-Store([string]$Name, [scriptblock]$Body) {
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store $Name, $Location
    $store.Open('ReadWrite')
    try { & $Body $store } finally { $store.Close() }
}

function Remove-Managed {
    param([string]$StoreName, [string[]]$Subjects = @(), [string[]]$KeepThumbprints = @())

    Use-Store $StoreName {
        param($store)
        $doomed = @($store.Certificates | Where-Object {
            $KeepThumbprints -notcontains $_.Thumbprint -and (
                ($_.FriendlyName -and $_.FriendlyName.StartsWith($Tag)) -or
                ($Subjects -contains $_.Subject)
            )
        })
        foreach ($c in $doomed) {
            $label = if ($c.FriendlyName) { $c.FriendlyName } else { $c.Subject }
            if ($PSCmdlet.ShouldProcess("$StoreName / $($c.Thumbprint)", "remove '$label'")) {
                $store.Remove($c)
                Write-Host ("  removed  {0}  [{1}]" -f $c.Subject, $c.Thumbprint) -ForegroundColor Yellow
            }
        }
        if ($doomed.Count -eq 0) { Write-Host "  nothing stale in $StoreName" -ForegroundColor DarkGray }
    }
}

function Add-Cert {
    param([string]$StoreName, $Cert, [string]$Friendly)

    Use-Store $StoreName {
        param($store)
        $existing = @($store.Certificates | Where-Object { $_.Thumbprint -eq $Cert.Thumbprint })
        if ($existing.Count -gt 0) {
            Write-Host ("  present  {0}  [{1}]" -f $Cert.Subject, $Cert.Thumbprint) -ForegroundColor DarkGray
            if ($existing[0].FriendlyName -ne $Friendly -and
                $PSCmdlet.ShouldProcess("$StoreName\$($Cert.Thumbprint)", 'set friendly name')) {
                Set-FriendlyNameSafe -StoreName $StoreName -Thumbprint $Cert.Thumbprint -Friendly $Friendly | Out-Null
            }
            return
        }
        if ($PSCmdlet.ShouldProcess("$StoreName\$($Cert.Thumbprint)", "install '$Friendly'")) {
            $Cert.FriendlyName = $Friendly    # persists through Add on a fresh context
            $store.Add($Cert)
            Write-Host ("  imported {0}  [{1}]" -f $Cert.Subject, $Cert.Thumbprint) -ForegroundColor Green
            # Re-assert via the provider in case Add did not carry the label.
            Set-FriendlyNameSafe -StoreName $StoreName -Thumbprint $Cert.Thumbprint -Friendly $Friendly | Out-Null
        }
    }
}

# ---------------------------------------------------------------- preconditions
if ($Machine -and -not (Test-Elevated)) {
    throw '-Machine requires an elevated PowerShell session (Run as administrator).'
}

Write-Host "store location: $Location" -ForegroundColor Cyan

if ($Uninstall) {
    Write-Host "`nRemoving everything tagged '$Tag':"
    Remove-Managed -StoreName 'Root'
    Remove-Managed -StoreName 'CA'
    Write-Host "`nDone. Firefox keeps its own store -- remove the pair there separately." -ForegroundColor Cyan
    return
}

# ---------------------------------------------------- load embedded or on-disk
$root      = $null
$crossPair = @()   # @{ Name; Cert }
$origPair  = @()

if ($EmbeddedCerts.Count -gt 0) {
    Write-Host "certificates: embedded in this script ($($EmbeddedCerts.Count))" -ForegroundColor DarkGray
    foreach ($e in $EmbeddedCerts) {
        $c = New-CertFromB64 $e.B64
        switch ($e.Kind) {
            'root'        { $root = $c }
            'constrained' { $crossPair += @{ Name = $e.Name; Cert = $c } }
            'original'    { $origPair  += @{ Name = $e.Name; Cert = $c } }
            default       { throw "unknown embedded kind '$($e.Kind)'" }
        }
    }
    if (-not $root) { throw 'embedded data has no root certificate' }
} else {
    $rootFile = Join-Path $PSScriptRoot 'myroot.crt'
    Write-Host "certificates: read from $PSScriptRoot" -ForegroundColor DarkGray
    $root = Read-Cert $rootFile
    foreach ($f in @(Get-ChildItem -Path (Join-Path $PSScriptRoot '*-constrained.crt') -ErrorAction SilentlyContinue)) {
        $crossPair += @{ Name = $f.BaseName -replace '-constrained$', ''; Cert = Read-Cert $f.FullName }
    }
    foreach ($f in @(Get-ChildItem -Path (Join-Path $PSScriptRoot '*-original.crt') -ErrorAction SilentlyContinue)) {
        $origPair += @{ Name = $f.BaseName -replace '-original$', ''; Cert = Read-Cert $f.FullName }
    }
}

if ($crossPair.Count -eq 0) {
    throw "no constrained certificates found -- run ./add-domain.sh --restage"
}

# ------------------------------------------------------- inspect / export only
if ($ShowOnly -or $Export) {
    Write-Host "`nRoot (trust anchor):" -ForegroundColor Cyan
    Write-Host ("  {0}`n    {1}  expires {2:yyyy-MM-dd}" -f $root.Subject, $root.Thumbprint, $root.NotAfter)
    Write-Host "Constrained intermediates:" -ForegroundColor Cyan
    foreach ($p in $crossPair) {
        Write-Host ("  {0}`n    {1}  expires {2:yyyy-MM-dd}" -f $p.Cert.Subject, $p.Cert.Thumbprint, $p.Cert.NotAfter)
    }
}
if ($Export) {
    if (-not (Test-Path -LiteralPath $Export)) { New-Item -ItemType Directory -Path $Export | Out-Null }
    function Write-Pem($Cert, $Path) {
        $b = [Convert]::ToBase64String($Cert.RawData, 'InsertLineBreaks')
        Set-Content -LiteralPath $Path -Value "-----BEGIN CERTIFICATE-----`n$b`n-----END CERTIFICATE-----" -Encoding ascii
    }
    Write-Pem $root (Join-Path $Export 'myroot.crt')
    foreach ($p in $crossPair) { Write-Pem $p.Cert (Join-Path $Export "$($p.Name)-constrained.crt") }
    foreach ($p in $origPair)  { Write-Pem $p.Cert (Join-Path $Export "$($p.Name)-original.crt") }
    Write-Host "`nExported to $Export -- use these for the manual Firefox import." -ForegroundColor Cyan
}
if ($ShowOnly -or $Export) { return }

$crosses = @()
foreach ($p in $crossPair) {
    $c = $p.Cert
    # Each cross-certificate must actually chain to this root, or we would install
    # something that cannot validate anything.
    if ($c.Issuer -ne $root.Subject) {
        throw ("$($f.Name) issuer does not match the root:`n" +
               "  cross issuer : $($c.Issuer)`n" +
               "  root subject : $($root.Subject)`n" +
               "Re-run ./add-domain.sh --resign to regenerate.")
    }
    $crosses += $c
}

# --------------------------------------------------- unconstrained root check
$originals = @{}
foreach ($p in $origPair) { $originals[$p.Cert.Thumbprint] = $p.Cert }
if ($originals.Count -gt 0) {
    $found = @()
    foreach ($loc in 'CurrentUser', 'LocalMachine') {
        foreach ($name in 'Root', 'CA', 'AuthRoot') {
            try {
                $s = New-Object System.Security.Cryptography.X509Certificates.X509Store $name, $loc
                $s.Open('ReadOnly')
                $hit = @($s.Certificates | Where-Object { $originals.ContainsKey($_.Thumbprint) })
                foreach ($h in $hit) { $found += [pscustomobject]@{ Location = $loc; Store = $name; Cert = $h } }
                $s.Close()
            } catch { }
        }
    }

    if ($found.Count -gt 0) {
        Write-Host "`nAn UNCONSTRAINED original root is trusted here:" -ForegroundColor Red
        $found | ForEach-Object {
            Write-Host ("  {0}\{1}  {2}" -f $_.Location, $_.Store, $_.Cert.Subject) -ForegroundColor Red }

        if (-not $RemoveUnconstrained) {
            throw ("While that certificate is trusted, chain building bypasses the constrained " +
                   "cross-certificate entirely and the name constraints enforce nothing. " +
                   "Re-run with -RemoveUnconstrained, or delete it by hand first.")
        }
        foreach ($f in $found) {
            if ($f.Location -eq 'LocalMachine' -and -not (Test-Elevated)) {
                Write-Warning "cannot remove from LocalMachine\$($f.Store) without elevation -- skipped"
                continue
            }
            $s = New-Object System.Security.Cryptography.X509Certificates.X509Store $f.Store, $f.Location
            $s.Open('ReadWrite')
            if ($PSCmdlet.ShouldProcess("$($f.Location)\$($f.Store)", 'remove unconstrained root')) {
                $s.Remove($f.Cert)
                Write-Host ("  removed unconstrained root from {0}\{1}" -f $f.Location, $f.Store) -ForegroundColor Yellow
            }
            $s.Close()
        }
    }
}

# ------------------------------------------------------------------- install
$issuedBy     = $root.Subject -replace '^CN=', ''
$rootFriendly = "$Tag root - trust anchor (do not delete)"

Write-Host "`nRoot store:"
Remove-Managed -StoreName 'Root' -Subjects @($root.Subject) -KeepThumbprints @($root.Thumbprint)
Add-Cert       -StoreName 'Root' -Cert $root -Friendly $rootFriendly

Write-Host "`nIntermediate (CA) store:"
Remove-Managed -StoreName 'CA' -Subjects @($crosses | ForEach-Object { $_.Subject }) `
               -KeepThumbprints @($crosses | ForEach-Object { $_.Thumbprint })
foreach ($c in $crosses) {
    $cn = ($c.Subject -split ',' | Where-Object { $_ -match 'CN=' }) -replace '.*CN=', ''
    Add-Cert -StoreName 'CA' -Cert $c -Friendly "$Tag $cn CONSTRAINED - issued by $issuedBy"
}

# -------------------------------------------------------------------- summary
Write-Host "`nInstalled:" -ForegroundColor Cyan
Write-Host ("  root  {0}" -f $root.Subject)
Write-Host ("        thumbprint {0}, expires {1:yyyy-MM-dd}" -f $root.Thumbprint, $root.NotAfter)
foreach ($c in $crosses) {
    Write-Host ("  cross {0}" -f $c.Subject)
    Write-Host ("        thumbprint {0}, expires {1:yyyy-MM-dd}" -f $c.Thumbprint, $c.NotAfter)
    $nc = $c.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.30' }
    if ($nc) {
        $names = [regex]::Matches($nc.Format($true), 'DNS Name=([^\r\n,]+)') |
                 ForEach-Object { $_.Groups[1].Value.Trim() }
        if ($names) { Write-Host ("        permitted: {0}" -f ($names -join ', ')) }
    }
}

Write-Host "`nRestart Chrome and Edge to pick this up." -ForegroundColor Cyan
Write-Host "Firefox uses its own store. Run:  .\install-certs.ps1 -Export .\certs" -ForegroundColor Cyan
Write-Host "then import myroot.crt (trusted for websites) and every" -ForegroundColor Cyan
Write-Host "*-constrained.crt (NO trust bits) under Authorities." -ForegroundColor Cyan
