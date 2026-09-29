param([switch]$Quiet)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$ProgressPreference = 'SilentlyContinue'

$Root = Split-Path -Parent $PSScriptRoot
$Tools = Join-Path $Root 'tools'
$Bin = Join-Path $Tools 'bin'
New-Item -ItemType Directory -Force -Path $Bin | Out-Null

function Say($m) { if (-not $Quiet) { Write-Host $m } }

function Have($exe) {
    if (Test-Path (Join-Path $Bin $exe)) { return $true }
    return [bool](Get-Command $exe -ErrorAction SilentlyContinue)
}

function Get-Release($repo) {
    $h = @{ 'User-Agent' = 'vulndetect-installer' }
    if ($env:GITHUB_TOKEN) { $h['Authorization'] = "Bearer $env:GITHUB_TOKEN" }
    Invoke-RestMethod -Headers $h -Uri "https://api.github.com/repos/$repo/releases/latest"
}

function Get-Asset($repo, $pattern) {
    $rel = Get-Release $repo
    $a = $rel.assets | Where-Object { $_.name -match $pattern } | Select-Object -First 1
    if (-not $a) { throw "No asset matching $pattern in $repo" }
    $a.browser_download_url
}

function Get-Extracted($url, $name) {
    $zip = Join-Path $env:TEMP "$name.zip"
    $tmp = Join-Path $env:TEMP "$name-extract"
    Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $zip
    if (Test-Path $tmp) { Remove-Item -Recurse -Force $tmp }
    Expand-Archive -Path $zip -DestinationPath $tmp -Force
    Remove-Item -Force $zip
    return $tmp
}

function Install-Zip($name, $exe, $repo, $pattern) {
    if (Have $exe) { Say "[ok] $name"; return }
    Say "[..] installing $name"
    $tmp = Get-Extracted (Get-Asset $repo $pattern) $name
    $found = Get-ChildItem -Path $tmp -Recurse -Filter $exe | Select-Object -First 1
    if (-not $found) { throw "$exe not found in $name archive" }
    Copy-Item $found.FullName (Join-Path $Bin $exe) -Force
    Remove-Item -Recurse -Force $tmp
    Say "[ok] $name installed"
}

function Install-Exe($name, $exe, $repo, $pattern) {
    if (Have $exe) { Say "[ok] $name"; return }
    Say "[..] installing $name"
    Invoke-WebRequest -UseBasicParsing -Uri (Get-Asset $repo $pattern) -OutFile (Join-Path $Bin $exe)
    Say "[ok] $name installed"
}

function Install-Tree($url, $name) {
    $dest = Join-Path $Tools $name
    if (Test-Path $dest) { Remove-Item -Recurse -Force $dest }
    $tmp = Get-Extracted $url $name
    Move-Item (Get-ChildItem $tmp -Directory | Select-Object -First 1).FullName $dest
    Remove-Item -Recurse -Force $tmp
}

function Find-Jdk {
    $roots = @("$env:ProgramFiles\Eclipse Adoptium", "$env:ProgramFiles\Java", "$env:ProgramFiles\Microsoft", "$env:ProgramFiles\Zulu")
    foreach ($r in $roots) {
        if (-not (Test-Path $r)) { continue }
        $d = Get-ChildItem $r -Directory | Where-Object { $_.Name -match '(jdk|jre)-?(\d+)' -and [int]$Matches[2] -ge 17 } |
            Sort-Object Name -Descending | Select-Object -First 1
        if ($d) { return $d.FullName }
    }
    return $null
}

function Install-Zap {
    $wrapper = Join-Path $Bin 'zap.bat'
    if (Test-Path $wrapper) { Say '[ok] zap'; return }
    $jdk = Find-Jdk
    if (-not $jdk) { Say '[!!] zap skipped: needs a Java 17+ JDK (winget install EclipseAdoptium.Temurin.21.JDK)'; return }
    Say '[..] installing zap'
    Install-Tree (Get-Asset 'zaproxy/zaproxy' 'Crossplatform\.zip$') 'zap'
    $jar = (Get-ChildItem (Join-Path $Tools 'zap') -Filter 'zap-*.jar' | Select-Object -First 1).Name
    $lines = @(
        '@echo off',
        'pushd "%~dp0..\zap"',
        "`"$jdk\bin\java.exe`" -jar $jar %*",
        'set "ZAP_EXIT=%ERRORLEVEL%"',
        'popd',
        'exit /b %ZAP_EXIT%'
    )
    Set-Content -Encoding ASCII -Path $wrapper -Value $lines
    Say '[ok] zap installed'
}

function Find-Perl {
    $sp = 'C:\Strawberry\perl\bin\perl.exe'
    if (Test-Path $sp) { return $sp }
    Say '[..] installing strawberry perl (for nikto)'
    winget install --id StrawberryPerl.StrawberryPerl -e --silent --accept-package-agreements --accept-source-agreements | Out-Null
    if (Test-Path $sp) { return $sp }
    return $null
}

function Install-Nikto {
    $wrapper = Join-Path $Bin 'nikto.cmd'
    if (Test-Path $wrapper) { Say '[ok] nikto'; return }
    $perl = Find-Perl
    if (-not $perl) { Say '[!!] nikto skipped: no Perl found'; return }
    Say '[..] installing nikto'
    Install-Tree 'https://github.com/sullo/nikto/archive/refs/heads/master.zip' 'nikto'
    $lw2 = Join-Path $Tools 'nikto\program\plugins\LW2.pm'
    $src = Get-Content -Raw $lw2
    $bad = 'if ( $! != EINPROGRESS && $! != EWOULDBLOCK )'
    $good = 'if ( $! != EINPROGRESS && $! != EWOULDBLOCK && $! != 10035 && $! != 10036 && $! != 140 )'
    Set-Content -NoNewline -Encoding ASCII -Path $lw2 -Value $src.Replace($bad, $good)
    $env:Path = "$(Split-Path $perl);C:\Strawberry\c\bin;$env:Path"
    $ErrorActionPreference = 'Continue'
    & $perl -MXML::Writer -e 1 *> $null
    if ($LASTEXITCODE -ne 0) { & (Join-Path (Split-Path $perl) 'cpanm.bat') --notest --quiet XML::Writer *> $null }
    $ErrorActionPreference = 'Stop'
    $pdir = Split-Path $perl
    $lines = @(
        '@echo off',
        "set `"PATH=$pdir;C:\Strawberry\c\bin;%PATH%`"",
        "`"$perl`" `"%~dp0..\nikto\program\nikto.pl`" %*"
    )
    Set-Content -Encoding ASCII -Path $wrapper -Value $lines
    Say '[ok] nikto installed'
}

function Find-Ruby {
    $c = Get-Command ruby -ErrorAction SilentlyContinue
    if ($c) { return $c.Source }
    $hits = Get-ChildItem 'C:\Ruby*\bin\ruby.exe', "$env:LOCALAPPDATA\Programs\Ruby*\bin\ruby.exe" -ErrorAction SilentlyContinue
    foreach ($p in $hits) { return $p.FullName }
    return $null
}

function Install-WhatWeb {
    $wrapper = Join-Path $Bin 'whatweb.cmd'
    if (Test-Path $wrapper) { Say '[ok] whatweb'; return }
    $ruby = Find-Ruby
    if (-not $ruby) {
        Say '[..] installing ruby (for whatweb)'
        winget install --id RubyInstallerTeam.Ruby.3.4 -e --silent --accept-package-agreements --accept-source-agreements | Out-Null
        $ruby = Find-Ruby
    }
    if (-not $ruby) { Say '[!!] whatweb skipped: Ruby not available'; return }
    & (Join-Path (Split-Path $ruby) 'gem.cmd') install addressable --no-document | Out-Null
    Say '[..] installing whatweb'
    Install-Tree 'https://github.com/urbanadventurer/WhatWeb/archive/refs/heads/master.zip' 'whatweb'
    $lines = @('@echo off', "`"$ruby`" `"%~dp0..\whatweb\whatweb`" %*")
    Set-Content -Encoding ASCII -Path $wrapper -Value $lines
    Say '[ok] whatweb installed'
}

function Install-Nmap {
    if (Have 'nmap.exe') { Say '[ok] nmap'; return }
    Say '[..] installing nmap'
    winget install --id Insecure.Nmap -e --silent --accept-package-agreements --accept-source-agreements | Out-Null
}

function Add-UserPath($dir) {
    $cur = [Environment]::GetEnvironmentVariable('Path', 'User')
    $parts = @()
    if ($cur) { $parts = $cur.Split(';') | Where-Object { $_ } }
    if ($parts -notcontains $dir) {
        [Environment]::SetEnvironmentVariable('Path', (($parts + $dir) -join ';'), 'User')
        Say "[ok] added $dir to your user PATH"
    }
    if (($env:Path.Split(';')) -notcontains $dir) { $env:Path = "$env:Path;$dir" }
}

$steps = @(
    { Install-Nmap },
    { Install-Zip 'nuclei' 'nuclei.exe' 'projectdiscovery/nuclei' 'windows_amd64\.zip$' },
    { Install-Zip 'trivy' 'trivy.exe' 'aquasecurity/trivy' 'windows-64bit\.zip$' },
    { Install-Zip 'grype' 'grype.exe' 'anchore/grype' 'windows_amd64\.zip$' },
    { Install-Exe 'osv-scanner' 'osv-scanner.exe' 'google/osv-scanner' '^osv-scanner_windows_amd64\.exe$' },
    { Install-Zap },
    { Install-Nikto },
    { Install-WhatWeb }
)
foreach ($s in $steps) {
    try { & $s } catch { Say "[!!] $($_.Exception.Message)" }
}

Add-UserPath $Bin
$nucleiExe = Join-Path $Bin 'nuclei.exe'
if ((Test-Path $nucleiExe) -and -not (Test-Path (Join-Path $env:USERPROFILE 'nuclei-templates'))) {
    Say '[..] downloading nuclei templates'
    & $nucleiExe -update-templates -silent 2>$null | Out-Null
}
Say 'Tool check complete.'
