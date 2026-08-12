<#
.SYNOPSIS
    Устанавливает (или обновляет) пару сертификатов с ограничением имён в хранилища Windows.

.DESCRIPTION
    Импортирует локальный корневой сертификат как доверенный корневой, а каждый
    ограниченный кросс-сертификат -- как промежуточный. Повторный запуск заменяет
    ранее установленный набор: сертификаты, установленные этим скриптом, помечены
    через FriendlyName, поэтому старые копии находятся и удаляются даже после
    смены Common Name корневого сертификата.

    Неограниченный российский корневой сертификат НЕ должен быть доверенным: если
    он доверен, построение цепочки обходит ограниченный кросс-сертификат стороной,
    и ограничение не значит ничего. Скрипт это обнаруживает и отказывается
    продолжать, пока не будет передан -RemoveUnconstrained.

.PARAMETER Machine
    Устанавливать в LocalMachine вместо CurrentUser. Требует прав администратора.

.PARAMETER RemoveUnconstrained
    Удалить неограниченный российский корневой сертификат из хранилищ доверия,
    если он там есть.

.PARAMETER Uninstall
    Удалить всё, что установил этот скрипт, и выйти.

.PARAMETER ShowOnly
    Показать сертификаты и их отпечатки, ничего не устанавливая. Используйте это,
    чтобы проверить копию, полученную от кого-то ещё, прежде чем её запускать.

.PARAMETER Export
    Выгрузить сертификаты файлами .crt в указанный каталог и выйти. У Firefox
    своё хранилище доверия, управлять им отсюда нельзя, поэтому сначала выгрузите
    файлы и импортируйте их вручную. Всё, что записано непосредственно в этот
    каталог, предназначено для импорта; неограниченные оригиналы попадают в
    подкаталог do-not-import, и их нельзя добавлять ни в одно хранилище доверия.

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

# Deliberately not translated: this marker is written into FriendlyName and matched
# on the next run to find this script's own earlier copies. Changing it orphans
# every certificate installed by an earlier version.
$Tag = '[constrained-ru]'

# Certificates are embedded below by `rucerts artifacts` when this script is
# staged, making the staged copy a single self-contained file. The copy in the
# source tree keeps this list empty and reads the .crt files beside it instead.
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
    if (-not (Test-Path -LiteralPath $Path)) { throw "нет файла сертификата: $Path" }
    try {
        return New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $Path
    } catch {
        # Fallback for PEM on runtimes whose constructor rejects it.
        $text = Get-Content -LiteralPath $Path -Raw
        $m = [regex]::Match($text, '(?s)-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----')
        if (-not $m.Success) { throw "это не сертификат в формате PEM: $Path" }
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
        Write-Warning "не удалось задать понятное имя для $StoreName\$Thumbprint : $($_.Exception.Message)"
        Write-Warning "это только косметика, сертификат установлен и работает -- при желании задайте подпись вручную в certmgr.msc"
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
            if ($PSCmdlet.ShouldProcess("$StoreName / $($c.Thumbprint)", "удалить '$label'")) {
                $store.Remove($c)
                Write-Host ("  удалён      {0}  [{1}]" -f $c.Subject, $c.Thumbprint) -ForegroundColor Yellow
            }
        }
        if ($doomed.Count -eq 0) { Write-Host "  в $StoreName нет устаревших копий" -ForegroundColor DarkGray }
    }
}

function Add-Cert {
    param([string]$StoreName, $Cert, [string]$Friendly)

    Use-Store $StoreName {
        param($store)
        $existing = @($store.Certificates | Where-Object { $_.Thumbprint -eq $Cert.Thumbprint })
        if ($existing.Count -gt 0) {
            Write-Host ("  уже есть    {0}  [{1}]" -f $Cert.Subject, $Cert.Thumbprint) -ForegroundColor DarkGray
            if ($existing[0].FriendlyName -ne $Friendly -and
                $PSCmdlet.ShouldProcess("$StoreName\$($Cert.Thumbprint)", 'задать понятное имя')) {
                Set-FriendlyNameSafe -StoreName $StoreName -Thumbprint $Cert.Thumbprint -Friendly $Friendly | Out-Null
            }
            return
        }
        if ($PSCmdlet.ShouldProcess("$StoreName\$($Cert.Thumbprint)", "установить '$Friendly'")) {
            $Cert.FriendlyName = $Friendly    # persists through Add on a fresh context
            $store.Add($Cert)
            Write-Host ("  установлен  {0}  [{1}]" -f $Cert.Subject, $Cert.Thumbprint) -ForegroundColor Green
            # Re-assert via the provider in case Add did not carry the label.
            Set-FriendlyNameSafe -StoreName $StoreName -Thumbprint $Cert.Thumbprint -Friendly $Friendly | Out-Null
        }
    }
}

# ---------------------------------------------------------------- preconditions
if ($Machine -and -not (Test-Elevated)) {
    throw '-Machine требует сеанс PowerShell с правами администратора (запуск от имени администратора).'
}

Write-Host "хранилище: $Location" -ForegroundColor Cyan

if ($Uninstall) {
    Write-Host "`nУдаляю всё, помеченное '$Tag':"
    Remove-Managed -StoreName 'Root'
    Remove-Managed -StoreName 'CA'
    Write-Host "`nГотово. У Firefox своё хранилище -- удалите сертификаты там отдельно." -ForegroundColor Cyan
    return
}

# ---------------------------------------------------- load embedded or on-disk
$root      = $null
$crossPair = @()   # @{ Name; Cert }
$origPair  = @()

if ($EmbeddedCerts.Count -gt 0) {
    Write-Host "сертификаты: вшиты в этот скрипт ($($EmbeddedCerts.Count))" -ForegroundColor DarkGray
    foreach ($e in $EmbeddedCerts) {
        $c = New-CertFromB64 $e.B64
        switch ($e.Kind) {
            'root'        { $root = $c }
            'constrained' { $crossPair += @{ Name = $e.Name; Cert = $c } }
            'original'    { $origPair  += @{ Name = $e.Name; Cert = $c } }
            default       { throw "неизвестный тип вшитых данных '$($e.Kind)'" }
        }
    }
    if (-not $root) { throw 'во вшитых данных нет корневого сертификата' }
} else {
    $rootFile = Join-Path $PSScriptRoot 'myroot.crt'
    Write-Host "сертификаты: прочитаны из $PSScriptRoot" -ForegroundColor DarkGray
    $root = Read-Cert $rootFile
    foreach ($f in @(Get-ChildItem -Path (Join-Path $PSScriptRoot '*-constrained.crt') -ErrorAction SilentlyContinue)) {
        $crossPair += @{ Name = $f.BaseName -replace '-constrained$', ''; Cert = Read-Cert $f.FullName }
    }
    foreach ($f in @(Get-ChildItem -Path (Join-Path $PSScriptRoot '*-original.crt') -ErrorAction SilentlyContinue)) {
        $origPair += @{ Name = $f.BaseName -replace '-original$', ''; Cert = Read-Cert $f.FullName }
    }
}

if ($crossPair.Count -eq 0) {
    throw "не найдено ни одного ограниченного сертификата -- выполните 'rucerts artifacts', чтобы пересоздать этот скрипт"
}

# ------------------------------------------------------- inspect / export only
if ($ShowOnly -or $Export) {
    Write-Host "`nКорневой сертификат (якорь доверия):" -ForegroundColor Cyan
    Write-Host ("  {0}`n    {1}  истекает {2:yyyy-MM-dd}" -f $root.Subject, $root.Thumbprint, $root.NotAfter)
    Write-Host "Ограниченные промежуточные сертификаты:" -ForegroundColor Cyan
    foreach ($p in $crossPair) {
        Write-Host ("  {0}`n    {1}  истекает {2:yyyy-MM-dd}" -f $p.Cert.Subject, $p.Cert.Thumbprint, $p.Cert.NotAfter)
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

    # The unconstrained originals go one directory down, deliberately. Everything in
    # $Export is meant to be imported into Firefox; an original imported with trust
    # bits is exactly the failure this whole design prevents, and the import dialog
    # gives no hint which file is which. They are still written out because the
    # unconstrained-root check skips itself when no original is available.
    if ($origPair.Count -gt 0) {
        $noImport = Join-Path $Export 'do-not-import'
        if (-not (Test-Path -LiteralPath $noImport)) {
            New-Item -ItemType Directory -Path $noImport | Out-Null
        }
        foreach ($p in $origPair) { Write-Pem $p.Cert (Join-Path $noImport "$($p.Name)-original.crt") }
    }

    Write-Host "`nЭкспортированы в $Export -- используйте их для ручного импорта в Firefox." -ForegroundColor Cyan
    Write-Host "Импортируйте оба файла из этой папки: myroot.crt (с доверием к веб-сайтам)" -ForegroundColor Cyan
    Write-Host "и *-constrained.crt (без единой галочки)." -ForegroundColor Cyan
    if ($origPair.Count -gt 0) {
        Write-Host "Папка do-not-import\ содержит НЕОГРАНИЧЕННЫЕ оригиналы: не импортируйте их" -ForegroundColor Yellow
        Write-Host "никуда. Они нужны только для сверки и обхода хранилищ доверия." -ForegroundColor Yellow
    }
}
if ($ShowOnly -or $Export) { return }

$crosses = @()
foreach ($p in $crossPair) {
    $c = $p.Cert
    # Each cross-certificate must actually chain to this root, or we would install
    # something that cannot validate anything.
    if ($c.Issuer -ne $root.Subject) {
        throw ("издатель кросс-сертификата $($p.Name) не совпадает с корнем:`n" +
               "  издатель кросс-сертификата : $($c.Issuer)`n" +
               "  субъект корня              : $($root.Subject)`n" +
               "Выполните 'rucerts resign', чтобы пересоздать его.")
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
        Write-Host "`nЗдесь доверен НЕОГРАНИЧЕННЫЙ исходный корневой сертификат:" -ForegroundColor Red
        $found | ForEach-Object {
            Write-Host ("  {0}\{1}  {2}" -f $_.Location, $_.Store, $_.Cert.Subject) -ForegroundColor Red }

        if (-not $RemoveUnconstrained) {
            throw ("Пока этот сертификат доверен, построение цепочки полностью обходит " +
                   "ограниченный кросс-сертификат, и ограничения имён не значат ничего. " +
                   "Запустите заново с -RemoveUnconstrained либо сначала удалите его вручную.")
        }
        foreach ($f in $found) {
            if ($f.Location -eq 'LocalMachine' -and -not (Test-Elevated)) {
                Write-Warning "не могу удалить из LocalMachine\$($f.Store) без прав администратора -- пропущено"
                continue
            }
            $s = New-Object System.Security.Cryptography.X509Certificates.X509Store $f.Store, $f.Location
            $s.Open('ReadWrite')
            if ($PSCmdlet.ShouldProcess("$($f.Location)\$($f.Store)", 'удалить неограниченный корневой сертификат')) {
                $s.Remove($f.Cert)
                Write-Host ("  неограниченный корень удалён из {0}\{1}" -f $f.Location, $f.Store) -ForegroundColor Yellow
            }
            $s.Close()
        }
    }
}

# ------------------------------------------------------------------- install
$issuedBy     = $root.Subject -replace '^CN=', ''
$rootFriendly = "$Tag корневой - якорь доверия (не удалять)"

Write-Host "`nХранилище корневых сертификатов:"
Remove-Managed -StoreName 'Root' -Subjects @($root.Subject) -KeepThumbprints @($root.Thumbprint)
Add-Cert       -StoreName 'Root' -Cert $root -Friendly $rootFriendly

Write-Host "`nХранилище промежуточных центров сертификации (CA):"
Remove-Managed -StoreName 'CA' -Subjects @($crosses | ForEach-Object { $_.Subject }) `
               -KeepThumbprints @($crosses | ForEach-Object { $_.Thumbprint })
foreach ($c in $crosses) {
    $cn = ($c.Subject -split ',' | Where-Object { $_ -match 'CN=' }) -replace '.*CN=', ''
    Add-Cert -StoreName 'CA' -Cert $c -Friendly "$Tag $cn ОГРАНИЧЕН - выдан $issuedBy"
}

# -------------------------------------------------------------------- summary
Write-Host "`nУстановлено:" -ForegroundColor Cyan
Write-Host ("  корень {0}" -f $root.Subject)
Write-Host ("         отпечаток {0}, истекает {1:yyyy-MM-dd}" -f $root.Thumbprint, $root.NotAfter)
foreach ($c in $crosses) {
    Write-Host ("  кросс  {0}" -f $c.Subject)
    Write-Host ("         отпечаток {0}, истекает {1:yyyy-MM-dd}" -f $c.Thumbprint, $c.NotAfter)
    $nc = $c.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.30' }
    if ($nc) {
        # Format() renders through the platform, and the label differs by all of
        # OS, locale and runtime: Windows prints "DNS Name=host" (localised, so
        # "DNS-имя=" on a Russian install) while the OpenSSL-backed runtimes print
        # "DNS:host". All three shapes are matched; an unrecognised one costs only
        # this one informational line.
        $names = [regex]::Matches($nc.Format($true), 'DNS(?:\s*Name)?(?:-имя)?\s*[:=]\s*([^\r\n,]+)') |
                 ForEach-Object { $_.Groups[1].Value.Trim() }
        if ($names) { Write-Host ("         разрешено: {0}" -f ($names -join ', ')) }
    }
}

Write-Host "`nПерезапустите Chrome и Edge, чтобы изменения вступили в силу." -ForegroundColor Cyan
Write-Host "У Firefox своё хранилище. Выполните:  .\install-certs.ps1 -Export .\certs" -ForegroundColor Cyan
Write-Host "затем импортируйте myroot.crt (с доверием к веб-сайтам) и каждый" -ForegroundColor Cyan
Write-Host "*-constrained.crt (БЕЗ флагов доверия) в разделе «Центры сертификации»." -ForegroundColor Cyan
