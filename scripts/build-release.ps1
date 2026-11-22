$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$manifest = Get-Content manifest.json -Raw | ConvertFrom-Json
$version = $manifest.version
$id = $manifest.id

$goVersion = [regex]::Match((Get-Content main.go -Raw), 'pluginVersion\s*=\s*"([^"]+)"').Groups[1].Value
$mainAgentVersion = [regex]::Match((Get-Content main.go -Raw), 'req\.Header\.Set\("User-Agent",\s*"LucX-DoH-HealthMonitor/([^"]+)"\)').Groups[1].Value
$probeVersion = [regex]::Match((Get-Content active_doh.go -Raw), 'activeDoHUserAgent\s*=\s*"LucX-DoH-HealthMonitor/([^"]+)"').Groups[1].Value
$menuVersion = [regex]::Match((Get-Content scripts/plugin-management.sh -Raw), 'DoH Health Monitor ([0-9.]+) — управление').Groups[1].Value
$readme = Get-Content README.md -Raw -Encoding UTF8
if ($goVersion -ne $version) { throw "Version mismatch: manifest=$version main.go=$goVersion" }
if ($mainAgentVersion -ne $version) { throw "Version mismatch: manifest=$version main.go User-Agent=$mainAgentVersion" }
if ($probeVersion -ne $version) { throw "Version mismatch: manifest=$version active_doh.go=$probeVersion" }
if ($menuVersion -ne $version) { throw "Version mismatch: manifest=$version plugin-management.sh=$menuVersion" }
if ($readme -notmatch [regex]::Escape("$id-v$version.zip")) { throw "README does not mention $id-v$version.zip" }
if ($readme -notmatch [regex]::Escape("**Версия:** $version")) { throw "README version header is not $version" }
if ((Get-Content CHANGELOG.md -Raw) -notmatch [regex]::Escape("[$version]")) { throw "CHANGELOG.md has no [$version] entry" }

go vet ./...
if ($LASTEXITCODE) { throw 'go vet failed' }
go test ./...
if ($LASTEXITCODE) { throw 'go test failed' }

$stage = Join-Path $root "dist/stage"
if (Test-Path $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
New-Item -ItemType Directory -Force "$stage/bin", "$stage/scripts" | Out-Null

$env:GOOS = 'linux'; $env:GOARCH = 'amd64'; $env:CGO_ENABLED = '0'
go build -trimpath -ldflags '-s -w' -o "$stage/bin/$id" .
if ($LASTEXITCODE) { throw 'go build failed' }
Remove-Item Env:GOOS, Env:GOARCH, Env:CGO_ENABLED

Copy-Item manifest.json $stage
Copy-Item scripts/plugin-management.sh, scripts/check-dns-integration.sh "$stage/scripts/"
if (!(Test-Path "$stage/scripts/plugin-management.sh") -or !(Test-Path "$stage/scripts/check-dns-integration.sh")) { throw 'Management scripts are missing from the staging package' }

$zip = Join-Path $root "dist/$id-v$version.zip"
if (Test-Path $zip) { Remove-Item -LiteralPath $zip -Force }
Compress-Archive -Path "$stage/*" -DestinationPath $zip
Remove-Item -LiteralPath $stage -Recurse -Force
Write-Host "Built $zip"
Write-Host "SHA256 $((Get-FileHash $zip -Algorithm SHA256).Hash)"
