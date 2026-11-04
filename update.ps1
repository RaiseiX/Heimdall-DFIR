[CmdletBinding()]
param(
    [switch]$DryRun,
    [Alias('y')][switch]$Yes,
    [switch]$AcceptAuditProblems,
    [switch]$RealignDbPassword,
    [switch]$Help,
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$Rest
)

$ErrorActionPreference = 'Continue'

$Root = $PSScriptRoot
if (-not $Root) { $Root = (Get-Location).Path }
Set-Location -LiteralPath $Root
[Environment]::CurrentDirectory = $Root

function Show-Usage {
    Write-Host 'Usage : .\update.ps1 [-DryRun] [-Yes] [-AcceptAuditProblems] [-RealignDbPassword]'
    Write-Host ''
    Write-Host '  -DryRun                 contrôles en lecture seule, puis affiche les étapes sans rien modifier'
    Write-Host '  -Yes                    ne pas demander de confirmation'
    Write-Host '  -AcceptAuditProblems    poursuivre même si la chaîne d''audit est déjà en défaut avant la mise à jour'
    Write-Host '  -RealignDbPassword      aligner le mot de passe du rôle forensiclab sur DB_PASSWORD de .env, sans toucher aux données'
    Write-Host ''
    Write-Host 'La mise à jour ne supprime jamais de volume, de base ni de fichier de preuve.'
}

if ($Help) { Show-Usage; exit 0 }
if ($Rest -and $Rest.Count -gt 0) {
    Write-Host ("Option inconnue : " + ($Rest -join ' ')) -ForegroundColor Red
    Show-Usage
    exit 64
}

function Get-IntSetting([string]$name, [int64]$default) {
    $raw = [Environment]::GetEnvironmentVariable($name)
    if ([string]::IsNullOrWhiteSpace($raw)) { return $default }
    if ($raw.Trim() -notmatch '^[0-9]+$') {
        Write-Host ("  [XX] $name doit être un entier positif : $raw") -ForegroundColor Red
        exit 64
    }
    return [int64]$raw.Trim()
}

$MinDockerFreeMb = Get-IntSetting 'HEIMDALL_MIN_DOCKER_FREE_MB' 5120
$BackupMarginMb = Get-IntSetting 'HEIMDALL_BACKUP_MARGIN_MB' 512
$HealthTimeout = Get-IntSetting 'HEIMDALL_HEALTH_TIMEOUT' 300
$BackupRoot = $env:HEIMDALL_BACKUP_DIR
if ([string]::IsNullOrWhiteSpace($BackupRoot)) { $BackupRoot = 'backups/updates' }
$EnvBackupRoot = $env:HEIMDALL_ENV_BACKUP_DIR
if ([string]::IsNullOrWhiteSpace($EnvBackupRoot)) {
    $backupParent = Split-Path -Parent $BackupRoot
    if ([string]::IsNullOrEmpty($backupParent)) { $backupParent = '.' }
    $EnvBackupRoot = Join-Path $backupParent 'env'
}
$EnvBackup = ''
$AnchorAfter = ''
$Stamp = (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + $PID
$BackupDir = ''
$DumpFile = ''
$DumpName = ''
$DumpSha = ''
$FromCommit = 'unknown'
$ToCommit = 'unknown'
$Phase = 'preflight'
$Total = 10
$DockerPath = ''
$Utf8 = New-Object System.Text.UTF8Encoding($false)

function Write-Ok  ($msg) { Write-Host "  [OK] $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "  [!!] $msg" -ForegroundColor Yellow }
function Write-Err ($msg) { Write-Host "  [XX] $msg" -ForegroundColor Red }
function Write-Info($msg) { Write-Host "    $msg" }
function Write-Step([int]$n, [string]$msg) { Write-Host "`n[$n/$Total] $msg" -ForegroundColor Cyan }
function Write-DryRun($msg) { Write-Host "  [dry-run] $msg" -ForegroundColor Yellow }
function Write-DoneOk($msg) { if (-not $DryRun) { Write-Ok $msg } }

function ConvertTo-ArgToken([string]$s) {
    if ($s.Length -eq 0) { return '""' }
    if ($s -notmatch '[\s"]') { return $s }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append([char]34)
    $backslashes = 0
    foreach ($c in $s.ToCharArray()) {
        if ([int]$c -eq 92) {
            $backslashes++
        } elseif ([int]$c -eq 34) {
            [void]$sb.Append([char]92, ($backslashes * 2 + 1))
            [void]$sb.Append([char]34)
            $backslashes = 0
        } else {
            if ($backslashes -gt 0) {
                [void]$sb.Append([char]92, $backslashes)
                $backslashes = 0
            }
            [void]$sb.Append($c)
        }
    }
    if ($backslashes -gt 0) { [void]$sb.Append([char]92, ($backslashes * 2)) }
    [void]$sb.Append([char]34)
    return $sb.ToString()
}

function Invoke-Docker {
    param(
        [string[]]$Arguments,
        [byte[]]$StdinBytes = $null,
        [string]$StdinFile = '',
        [string]$StdoutFile = '',
        [hashtable]$ExtraEnv = @{}
    )
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $script:DockerPath
    $psi.Arguments = (($Arguments | ForEach-Object { ConvertTo-ArgToken $_ }) -join ' ')
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.StandardOutputEncoding = $script:Utf8
    $psi.StandardErrorEncoding = $script:Utf8
    foreach ($key in $ExtraEnv.Keys) { $psi.EnvironmentVariables[$key] = [string]$ExtraEnv[$key] }
    $result = [pscustomobject]@{ Code = 1; Out = ''; Err = '' }
    $outStream = $null
    try {
        $proc = [System.Diagnostics.Process]::Start($psi)
    } catch {
        $result.Err = $_.Exception.Message
        return $result
    }
    try {
        if ($StdoutFile) {
            $outStream = [System.IO.File]::Open($StdoutFile, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
            $outTask = $proc.StandardOutput.BaseStream.CopyToAsync($outStream)
        } else {
            $outTask = $proc.StandardOutput.ReadToEndAsync()
        }
        $errTask = $proc.StandardError.ReadToEndAsync()
        try {
            $stdin = $proc.StandardInput.BaseStream
            if ($StdinBytes -and $StdinBytes.Length -gt 0) {
                $stdin.Write($StdinBytes, 0, $StdinBytes.Length)
            } elseif ($StdinFile) {
                $in = [System.IO.File]::OpenRead($StdinFile)
                try { $in.CopyTo($stdin) } finally { $in.Dispose() }
            }
            $stdin.Flush()
        } catch {
        } finally {
            try { $proc.StandardInput.Close() } catch {}
        }
        $proc.WaitForExit()
        $outTask.Wait()
        $errTask.Wait()
        $result.Code = $proc.ExitCode
        if (-not $StdoutFile) { $result.Out = [string]$outTask.Result }
        $result.Err = [string]$errTask.Result
    } finally {
        if ($outStream) { $outStream.Dispose() }
        $proc.Dispose()
    }
    return $result
}

function Invoke-DockerLive([string[]]$Arguments) {
    & $script:DockerPath @Arguments | Out-Host
    return $LASTEXITCODE
}

function Invoke-Mutation([string[]]$Arguments) {
    if ($DryRun) {
        Write-DryRun ('docker ' + ($Arguments -join ' '))
        return 0
    }
    return (Invoke-DockerLive $Arguments)
}

function Get-LastLine([string]$text) {
    if ([string]::IsNullOrEmpty($text)) { return '' }
    $lines = @($text -split "\r?\n" | Where-Object { $_.Trim().Length -gt 0 })
    if ($lines.Count -eq 0) { return '' }
    return $lines[$lines.Count - 1].Trim()
}

function Get-EnvValue([string]$key) {
    if (-not (Test-Path -LiteralPath '.env')) { return '' }
    $prefix = $key + '='
    $found = ''
    foreach ($line in [System.IO.File]::ReadAllLines((Join-Path $Root '.env'))) {
        if ($line.StartsWith($prefix, [System.StringComparison]::Ordinal)) { $found = $line.Substring($prefix.Length).TrimEnd("`r") }
    }
    return $found
}

function Get-JsonField([string]$json, [string]$field) {
    $m = [regex]::Match($json, '"' + [regex]::Escape($field) + '":"([^"]*)"')
    if ($m.Success) { return $m.Groups[1].Value }
    return ''
}

function Test-CountsNotWorse([string]$before, [string]$after) {
    foreach ($m in [regex]::Matches($after, '"([a-z_]+)":(\d+)')) {
        $key = $m.Groups[1].Value
        $n = [int64]$m.Groups[2].Value
        $prev = [regex]::Match($before, '"' + $key + '":(\d+)')
        if (-not $prev.Success) { return $false }
        if ($n -gt [int64]$prev.Groups[1].Value) { return $false }
    }
    return $true
}

function Get-JsonObject([string]$json, [string]$field) {
    $m = [regex]::Match($json, '"' + [regex]::Escape($field) + '":(\{[^}]*\})')
    if ($m.Success) { return $m.Groups[1].Value }
    return ''
}

function Get-ContainerHealth([string]$name) {
    $r = Invoke-Docker -Arguments @('inspect', '-f', '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}', $name)
    if ($r.Code -ne 0) { return 'absent' }
    $status = $r.Out.Trim()
    if (-not $status) { return 'absent' }
    return $status
}

function Wait-Healthy([string]$name) {
    $deadline = (Get-Date).AddSeconds($HealthTimeout)
    while ($true) {
        $status = Get-ContainerHealth $name
        if ($status -eq 'healthy' -or $status -eq 'running') {
            $script:LastHealthStatus = $status
            return $true
        }
        if ((Get-Date) -ge $deadline) {
            $script:LastHealthStatus = $status
            return $false
        }
        Start-Sleep -Seconds 2
    }
}

function Resolve-RepoPath([string]$path) {
    if ([System.IO.Path]::IsPathRooted($path)) { return [System.IO.Path]::GetFullPath($path) }
    return [System.IO.Path]::GetFullPath((Join-Path $Root $path))
}

function Get-FreeMb([string]$path) {
    try {
        if ($path.StartsWith('/')) { return $null }
        $target = Resolve-RepoPath $path
        while ($target -and -not (Test-Path -LiteralPath $target -PathType Container)) {
            $parent = Split-Path -Parent $target
            if (-not $parent -or $parent -eq $target) { return $null }
            $target = $parent
        }
        $driveRoot = [System.IO.Path]::GetPathRoot($target)
        if ($driveRoot -notmatch '^[A-Za-z]:\\') { return $null }
        $drive = New-Object System.IO.DriveInfo($driveRoot)
        return [int64][math]::Floor($drive.AvailableFreeSpace / 1MB)
    } catch {
        return $null
    }
}

function Set-OwnerOnlyAcl([string]$path) {
    try {
        $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        if ($item.PSIsContainer) {
            $acl = New-Object System.Security.AccessControl.DirectorySecurity
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        } else {
            $acl = New-Object System.Security.AccessControl.FileSecurity
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', 'Allow')
        }
        $acl.SetAccessRuleProtection($true, $false)
        $acl.AddAccessRule($rule)
        Set-Acl -LiteralPath $path -AclObject $acl -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

function Write-TextFile([string]$path, [string]$text) {
    [System.IO.File]::WriteAllText($path, $text, $script:Utf8)
}

function Show-State {
    Write-Host ''
    Write-Host '  État de la plateforme :' -ForegroundColor White
    switch ($script:Phase) {
        'preflight' {
            Write-Info 'Rien n''a été modifié. Les services tournent comme avant la mise à jour.'
        }
        'built' {
            Write-Info 'Les nouvelles images sont construites, mais les conteneurs en marche n''ont pas été touchés.'
            Write-Info 'La base n''a pas été modifiée.'
        }
        'stopped' {
            Write-Info 'Le backend et le worker sont arrêtés. La base et les volumes sont intacts.'
            Write-Info 'Relance des anciens conteneurs, sans recréation :'
            if ($script:DryRun) {
                Write-DryRun 'docker compose start backend worker'
            } else {
                $code = Invoke-DockerLive @('compose', 'start', 'backend', 'worker')
                if ($code -eq 0) {
                    Write-Ok 'backend et worker relancés sur leurs images d''avant la mise à jour'
                } else {
                    Write-Warn 'relance impossible, à faire à la main : docker compose start backend worker'
                }
            }
        }
        'migrating' {
            Write-Info 'Une migration a échoué. Le backend et le worker restent arrêtés : ne les relance pas sur un schéma incomplet.'
            Write-Info "Sauvegarde vérifiée : $($script:DumpFile)"
            Write-Info ''
            Write-Info 'Option 1, recommandée : corrige la cause affichée plus haut, puis relance « .\update.ps1 ».'
            Write-Info '  Les migrations déjà passées sont inscrites dans schema_migrations et ne seront pas rejouées.'
            Write-Info ''
            Write-Info 'Option 2 : revenir à l''état d''avant la mise à jour. Le contenu actuel de la base est remplacé par la sauvegarde,'
            Write-Info "  à lancer seulement après confirmation, une fois le code ramené au commit précédent ($($script:FromCommit)) :"
            Write-Info "  à lancer dans cmd.exe (pas dans PowerShell) :"
            Write-Info "  docker compose exec -T db pg_restore -U forensiclab -d forensiclab --clean --if-exists --single-transaction --no-owner < `"$($script:DumpFile)`""
            Write-Info '  docker compose build ; docker compose up -d'
        }
        'started' {
            Write-Info "Les migrations sont appliquées et les services ont été relancés. La sauvegarde reste disponible : $($script:DumpFile)"
            Write-Info 'Diagnostic : docker compose ps ; docker logs odin --tail 100 ; docker logs huginn --tail 100'
        }
    }
}

function Stop-Update([string]$message) {
    Write-Err $message
    Show-State
    exit 1
}

function Get-ManifestEntries {
    $manifest = Join-Path $Root 'db/migrations.manifest'
    $entries = New-Object System.Collections.Generic.List[string]
    foreach ($raw in [System.IO.File]::ReadAllLines($manifest)) {
        $line = $raw.TrimEnd("`r")
        if ($line.Length -eq 0) { continue }
        if ([int]$line[0] -eq 35) { continue }
        $entries.Add($line)
    }
    return , $entries
}

function Test-ManifestCoverage {
    $manifest = Join-Path $Root 'db/migrations.manifest'
    if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) {
        Write-Err 'Manifeste de migrations introuvable : db/migrations.manifest'
        return $false
    }
    $listed = Get-ManifestEntries
    $complete = $true
    $files = @()
    foreach ($dir in @('db', 'db/migrations')) {
        $full = Join-Path $Root $dir
        if (Test-Path -LiteralPath $full -PathType Container) {
            foreach ($f in (Get-ChildItem -LiteralPath $full -Filter '*.sql' -File | Sort-Object Name)) {
                $files += ($dir + '/' + $f.Name)
            }
        }
    }
    foreach ($rel in $files) {
        if ($rel -eq 'db/init.sql') { continue }
        if (-not $listed.Contains($rel)) {
            Write-Err "Absent de db/migrations.manifest : $rel"
            $complete = $false
        }
    }
    if (-not $complete) {
        Write-Err 'Ajoute les fichiers ci-dessus à db/migrations.manifest (dans le bon ordre) puis relance.'
    }
    return $complete
}

function Invoke-Psql([string[]]$PsqlArguments, [byte[]]$StdinBytes = $null) {
    $all = @('compose', 'exec', '-T', 'db', 'psql', '-U', 'forensiclab', 'forensiclab') + $PsqlArguments
    return (Invoke-Docker -Arguments $all -StdinBytes $StdinBytes)
}

function Invoke-Migrations {
    Write-Host '  Initialisation du suivi des migrations' -ForegroundColor Cyan
    $create = Invoke-Psql @('-v', 'ON_ERROR_STOP=1', '-c', 'CREATE TABLE IF NOT EXISTS schema_migrations (filename TEXT PRIMARY KEY, applied_at TIMESTAMPTZ DEFAULT NOW());')
    if ($create.Code -ne 0) {
        Write-Err "Création de schema_migrations impossible : $($create.Err.Trim())"
        return $false
    }
    Write-Host ''
    Write-Host '  Application des migrations (ordre du manifeste)' -ForegroundColor Cyan
    foreach ($rel in (Get-ManifestEntries)) {
        $path = Join-Path $Root ($rel -replace '/', [System.IO.Path]::DirectorySeparatorChar)
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
        $name = [System.IO.Path]::GetFileName($rel)
        if ($name -notmatch '^[A-Za-z0-9._-]+$') {
            Write-Err "Nom de migration refusé : $name"
            return $false
        }
        $count = Invoke-Psql @('-t', '-c', "SELECT COUNT(*) FROM schema_migrations WHERE filename='$name';")
        if ($count.Code -ne 0) {
            Write-Err "Lecture de schema_migrations impossible : $($count.Err.Trim())"
            return $false
        }
        $done = ($count.Out -replace '[^0-9]', '')
        if ($done -and [int]$done -gt 0) {
            Write-Host "  [passée] $name" -ForegroundColor Yellow
            continue
        }
        Write-Host "  [appliquer] $name"
        $sql = [System.IO.File]::ReadAllBytes($path)
        $apply = Invoke-Psql @('-v', 'ON_ERROR_STOP=1') $sql
        if ($apply.Code -ne 0) {
            Write-Err "Échec : $name"
            Write-Host '     Détails de l''erreur :' -ForegroundColor Red
            foreach ($l in (($apply.Out + $apply.Err) -split "\r?\n")) { if ($l.Length -gt 0) { Write-Host "       $l" } }
            Write-Host ''
            Write-Info 'Pour ignorer si déjà appliquée à la main :'
            Write-Info "  docker compose exec db psql -U forensiclab forensiclab -c `"INSERT INTO schema_migrations(filename) VALUES('$name') ON CONFLICT DO NOTHING;`""
            return $false
        }
        $mark = Invoke-Psql @('-v', 'ON_ERROR_STOP=1', '-c', "INSERT INTO schema_migrations(filename) VALUES('$name');")
        if ($mark.Code -ne 0) {
            Write-Err "Inscription de $name dans schema_migrations impossible : $($mark.Err.Trim())"
            return $false
        }
        Write-Host "  [OK] $name" -ForegroundColor Green
    }
    return $true
}

function Initialize-Docker {
    $cmd = Get-Command docker -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $cmd) { Stop-Update 'Docker n''est pas installé.' }
    $script:DockerPath = $cmd.Source
}

function Backup-Env {
    if ($script:EnvBackup) { return $true }
    try {
        $dir = Resolve-RepoPath $script:EnvBackupRoot
        if (-not (Test-Path -LiteralPath $dir -PathType Container)) {
            New-Item -ItemType Directory -Path $dir -ErrorAction Stop | Out-Null
        }
        if (-not (Set-OwnerOnlyAcl $dir)) { Write-Warn 'Droits du dossier de copie de .env non restreints à l''utilisateur courant' }
        $target = Join-Path $dir ($script:Stamp + '.env')
        if (Test-Path -LiteralPath $target) { return $false }
        $source = Join-Path $Root '.env'
        Copy-Item -LiteralPath $source -Destination $target -ErrorAction Stop
        [void](Set-OwnerOnlyAcl $target)
        $a = [System.IO.File]::ReadAllBytes($source)
        $b = [System.IO.File]::ReadAllBytes($target)
        if ($a.Length -ne $b.Length) { return $false }
        for ($i = 0; $i -lt $a.Length; $i++) { if ($a[$i] -ne $b[$i]) { return $false } }
        $script:EnvBackup = (Resolve-Path -LiteralPath $target).ProviderPath
        return $true
    } catch {
        return $false
    }
}

function Test-DbAuth {
    $bytes = $script:Utf8.GetBytes((Get-EnvValue 'DB_PASSWORD') + "`n")
    return (Invoke-Docker -Arguments @('compose', 'exec', '-T', 'db', 'sh', '-c', 'IFS= read -r PGPASSWORD; export PGPASSWORD; psql -h db -U forensiclab -d forensiclab -tAc "SELECT 1"') -StdinBytes $bytes)
}

function Invoke-RealignDbPassword {
    $payload = (Get-EnvValue 'DB_PASSWORD') + "`n" + '\getenv pw p' + "`n" + "ALTER ROLE forensiclab PASSWORD :'pw';" + "`n"
    $bytes = $script:Utf8.GetBytes($payload)
    return (Invoke-Docker -Arguments @('compose', 'exec', '-T', 'db', 'sh', '-c', 'IFS= read -r p; export p; exec psql -U forensiclab -d forensiclab -v ON_ERROR_STOP=1 -q') -StdinBytes $bytes)
}

function Get-EnvLineList([string]$text) {
    $lines = New-Object System.Collections.Generic.List[string]
    if ($text.Length -eq 0) { return , $lines }
    $parts = $text -split "\n"
    $count = $parts.Length
    if ($text.EndsWith("`n")) { $count-- }
    for ($i = 0; $i -lt $count; $i++) { $lines.Add($parts[$i].TrimEnd("`r")) }
    return , $lines
}

Write-Host 'Heimdall DFIR : mise à jour sans perte de données' -ForegroundColor Cyan
if ($DryRun) { Write-Host 'Mode à blanc (dry-run) : seuls des contrôles en lecture seule sont exécutés.' -ForegroundColor Yellow }

if ($RealignDbPassword) {
    Initialize-Docker
    if (-not (Test-Path -LiteralPath '.env' -PathType Leaf)) { Stop-Update 'Fichier .env introuvable.' }
    if (-not (Get-EnvValue 'DB_PASSWORD')) { Stop-Update 'DB_PASSWORD absent de .env.' }
    if ((Get-ContainerHealth 'yggdrasil') -ne 'healthy') { Stop-Update 'PostgreSQL (yggdrasil) n''est pas sain : docker compose up -d db, puis relance.' }
    if ($DryRun) {
        Write-DryRun 'ALTER ROLE forensiclab PASSWORD <DB_PASSWORD de .env>, par la connexion locale du conteneur'
        exit 0
    }
    if (-not $Yes) {
        if (-not ([Environment]::UserInteractive -and -not [Console]::IsInputRedirected)) { Stop-Update 'Pas de terminal pour confirmer : relance avec -Yes.' }
        $answer = Read-Host '  Remplacer le mot de passe du rôle forensiclab par DB_PASSWORD de .env ? Aucune donnée n''est touchée. [o/N]'
        if ($answer -cnotmatch '^[oOyY]$') { Stop-Update 'Annulé.' }
    }
    $realign = Invoke-RealignDbPassword
    if ($realign.Code -ne 0) { Stop-Update 'ALTER ROLE a échoué. Diagnostic : docker compose logs db' }
    $recheck = Test-DbAuth
    if ($recheck.Code -ne 0) { Stop-Update ("Le mot de passe est réaligné mais la connexion TCP échoue encore : " + ($recheck.Out + $recheck.Err).Trim()) }
    Write-Ok 'Rôle forensiclab aligné sur .env ; les données n''ont pas été touchées'
    Write-Info 'Suite : .\update.ps1, ou docker compose up -d si tu ne mets pas à jour.'
    exit 0
}

Write-Step 1 'Prérequis'
Initialize-Docker
$composeVersion = Invoke-Docker -Arguments @('compose', 'version')
if ($composeVersion.Code -ne 0) { Stop-Update 'Docker Compose v2 n''est pas disponible.' }
if (-not (Get-Command Get-FileHash -ErrorAction SilentlyContinue)) { Stop-Update 'Get-FileHash est requis pour contrôler la sauvegarde.' }
if (-not (Test-Path -LiteralPath 'docker-compose.yml' -PathType Leaf)) { Stop-Update 'docker-compose.yml introuvable : lance le script depuis la racine du dépôt.' }
if (-not (Test-Path -LiteralPath '.env' -PathType Leaf)) { Stop-Update 'Fichier .env introuvable. Une mise à jour a besoin du .env de l''installation existante ; pour une première installation, utilise start.ps1.' }
Write-Ok 'Docker, Docker Compose, .env présents'

Write-Step 2 'Variables d''environnement'
$required = @('DB_PASSWORD', 'REDIS_PASSWORD', 'JWT_SECRET', 'VOLWEB_DJANGO_SECRET', 'VOLWEB_PASSWORD', 'MINIO_ROOT_USER', 'MINIO_ROOT_PASSWORD')
$bad = @()
foreach ($key in $required) {
    $value = Get-EnvValue $key
    if ([string]::IsNullOrEmpty($value) -or $value.StartsWith('CHANGEME', [System.StringComparison]::Ordinal)) { $bad += $key }
}
if ($bad.Count -gt 0) {
    Stop-Update ("Variables absentes ou laissées à CHANGEME dans .env : " + ($bad -join ' ') + "`n     Elles ne sont pas régénérées : la base, Redis et MinIO gardent les valeurs d'origine.`n     Reprends-les depuis la sauvegarde de ton .env.")
}
$jwtValue = Get-EnvValue 'JWT_SECRET'
$auditValue = Get-EnvValue 'AUDIT_HMAC_KEY'
$generateAuditKey = $false
if ([string]::IsNullOrEmpty($auditValue) -or $auditValue.StartsWith('CHANGEME', [System.StringComparison]::Ordinal)) {
    $generateAuditKey = $true
    Write-Warn 'AUDIT_HMAC_KEY absente : elle sera générée dans .env, sans être affichée'
} elseif ($auditValue -ceq $jwtValue) {
    Stop-Update "AUDIT_HMAC_KEY est identique à JWT_SECRET. Elle n'est pas remplacée automatiquement : des lignes d'audit ont pu être signées avec elle.`n     Choisis la suite à donner avant de relancer la mise à jour."
} elseif ($auditValue.Length -lt 32) {
    Stop-Update 'AUDIT_HMAC_KEY fait moins de 32 caractères.'
}
$jwtValue = $null
$auditValue = $null
$otherChangeMe = @()
foreach ($line in [System.IO.File]::ReadAllLines((Join-Path $Root '.env'))) {
    $m = [regex]::Match($line, '^([A-Z0-9_]+)=CHANGEME')
    if ($m.Success -and $m.Groups[1].Value -ne 'AUDIT_HMAC_KEY') { $otherChangeMe += $m.Groups[1].Value }
}
if ($otherChangeMe.Count -gt 0) { Write-Warn ('Valeurs encore à CHANGEME, sans effet sur la mise à jour : ' + ($otherChangeMe -join ' ')) }
if ($generateAuditKey) {
    $config = Invoke-Docker -Arguments @('compose', 'config', '-q') -ExtraEnv @{ AUDIT_HMAC_KEY = 'placeholder-for-config-check' }
} else {
    $config = Invoke-Docker -Arguments @('compose', 'config', '-q')
}
if ($config.Code -ne 0) { Stop-Update ("docker compose config refuse la configuration : " + ($config.Out + $config.Err).Trim()) }
Write-Ok 'Variables obligatoires présentes'

Write-Step 3 'Base de données et services'
$dbStatus = Get-ContainerHealth 'yggdrasil'
if ($dbStatus -ne 'healthy') {
    if ($DryRun) {
        Write-Warn "PostgreSQL (yggdrasil) est « $dbStatus » : la mise à jour réelle le démarrerait avec docker compose up -d db"
    } else {
        Write-Warn "PostgreSQL (yggdrasil) est « $dbStatus », démarrage de la base seule"
        $code = Invoke-DockerLive @('compose', 'up', '-d', 'db')
        if ($code -ne 0) { Stop-Update 'Impossible de démarrer PostgreSQL. Diagnostic : docker compose logs db' }
        if (-not (Wait-Healthy 'yggdrasil')) { Stop-Update "PostgreSQL n'est pas sain après ${HealthTimeout}s. Diagnostic : docker compose logs db" }
    }
}
$dbSize = [int64]0
if ($dbStatus -eq 'healthy' -or -not $DryRun) {
    $auth = Test-DbAuth
    if ($auth.Code -ne 0) {
        if ($auth.Err -match 'password authentication failed') {
            Write-Err 'PostgreSQL refuse le mot de passe DB_PASSWORD de .env.'
            Write-Info 'Le volume de la base garde le mot de passe défini à sa création ; il ne suit pas les changements de .env.'
            Write-Info 'Correction sans perte de données : aligner le rôle forensiclab sur .env, puis relancer la mise à jour.'
            Write-Info ''
            Write-Info '  .\update.ps1 -RealignDbPassword'
            Write-Info '  .\update.ps1'
            Show-State
            exit 1
        }
        Stop-Update ("Connexion à PostgreSQL impossible : " + ($auth.Out + $auth.Err).Trim())
    }
    Write-Ok 'PostgreSQL accepte le mot de passe de .env'
    $sizeResult = Invoke-Docker -Arguments @('compose', 'exec', '-T', 'db', 'psql', '-U', 'forensiclab', '-d', 'forensiclab', '-tAc', "SELECT pg_database_size('forensiclab')")
    $sizeDigits = ($sizeResult.Out -replace '[^0-9]', '')
    if ($sizeResult.Code -ne 0 -or -not $sizeDigits) { Stop-Update 'Impossible de mesurer la taille de la base.' }
    $dbSize = [int64]$sizeDigits
}
foreach ($name in @('odin', 'huginn')) {
    Write-Info "${name} : $(Get-ContainerHealth $name)"
}

Write-Step 4 'Espace disque'
$dbMb = [int64][math]::Floor(($dbSize + 1048575) / 1048576)
$needBackupMb = $dbMb + $BackupMarginMb
$backupFree = Get-FreeMb $BackupRoot
if ($null -eq $backupFree) { Stop-Update "Impossible de mesurer l'espace disque libre pour $BackupRoot." }
if ($backupFree -lt $needBackupMb) {
    Stop-Update "Espace disque insuffisant pour la sauvegarde : $backupFree Mo libres, $needBackupMb Mo nécessaires (base de $dbMb Mo)."
}
Write-Ok "Sauvegarde : $backupFree Mo libres, $needBackupMb Mo nécessaires"
$dockerRootResult = Invoke-Docker -Arguments @('info', '-f', '{{.DockerRootDir}}')
$dockerRoot = ''
if ($dockerRootResult.Code -eq 0) { $dockerRoot = $dockerRootResult.Out.Trim() }
$dockerFree = $null
if ($dockerRoot) { $dockerFree = Get-FreeMb $dockerRoot }
if ($null -eq $dockerFree) {
    $shown = $dockerRoot
    if (-not $shown) { $shown = 'inconnu' }
    Write-Warn "Espace libre de Docker non mesurable ($shown), contrôle ignoré"
} elseif ($dockerFree -lt $MinDockerFreeMb) {
    Stop-Update "Espace disque insuffisant pour construire les images : $dockerFree Mo libres dans $dockerRoot, $MinDockerFreeMb Mo demandés."
} else {
    Write-Ok "Images : $dockerFree Mo libres dans $dockerRoot"
}

$lastCommitPath = Join-Path (Resolve-RepoPath $BackupRoot) 'last-commit'
if (Test-Path -LiteralPath $lastCommitPath -PathType Leaf) {
    $rawCommit = (Get-Content -LiteralPath $lastCommitPath -Raw -ErrorAction SilentlyContinue)
    if ($rawCommit) {
        $cleanCommit = ($rawCommit -replace '[^0-9a-f]', '')
        if ($cleanCommit.Length -gt 40) { $cleanCommit = $cleanCommit.Substring(0, 40) }
        if ($cleanCommit -cmatch '^[0-9a-f]{7,40}$') { $FromCommit = $cleanCommit }
    }
}
$gitPath = ''
if (Get-Command git -CommandType Application -ErrorAction SilentlyContinue) {
    $gitPath = (Get-Command git -CommandType Application | Select-Object -First 1).Source
    $gitOut = & $gitPath rev-parse --short=12 HEAD 2>$null
    if ($LASTEXITCODE -eq 0 -and $gitOut) {
        $candidate = ([string]($gitOut | Select-Object -First 1)).Trim()
        if ($candidate -cmatch '^[0-9a-f]{7,40}$') { $ToCommit = $candidate }
    }
}
$dirty = 'false'
if ($ToCommit -ne 'unknown') {
    $statusOut = & $gitPath status --porcelain --untracked-files=no 2>$null
    if ($LASTEXITCODE -eq 0 -and $statusOut) { $dirty = 'true' }
}
if ($dirty -eq 'true') { Write-Warn 'L''arbre de travail contient des modifications non commitées : elles seront construites et signalées dans le journal d''audit' }
$operator = $env:USERNAME
if ([string]::IsNullOrEmpty($operator) -or $operator -cnotmatch '^[A-Za-z_][A-Za-z0-9_.-]{0,63}$') { $operator = 'unknown' }
$previousAnchor = ''
$lastAnchorPath = Join-Path (Resolve-RepoPath $BackupRoot) 'last-anchor'
if (Test-Path -LiteralPath $lastAnchorPath -PathType Leaf) {
    $rawAnchor = (Get-Content -LiteralPath $lastAnchorPath -Raw -ErrorAction SilentlyContinue)
    if ($rawAnchor) {
        $cleanAnchor = ($rawAnchor -replace '[^0-9a-f]', '')
        if ($cleanAnchor.Length -gt 64) { $cleanAnchor = $cleanAnchor.Substring(0, 64) }
        if ($cleanAnchor -cmatch '^[0-9a-f]{64}$') { $previousAnchor = $cleanAnchor }
    }
}
if ($previousAnchor) { Write-Info "Ancre de la mise à jour précédente à retrouver dans la chaîne : $previousAnchor" }
Write-Info "Version déployée : $FromCommit  →  version installée : $ToCommit"

if (-not $DryRun -and -not $Yes) {
    if ([Environment]::UserInteractive -and -not [Console]::IsInputRedirected) {
        Write-Host ''
        $answer = Read-Host '  Lancer la mise à jour ? Le backend et le worker seront arrêtés pendant la sauvegarde et les migrations. [o/N]'
        if ($answer -cnotmatch '^[oOyY]$') { Stop-Update 'Mise à jour annulée.' }
    } else {
        Stop-Update 'Pas de terminal pour confirmer : relance avec -Yes pour une mise à jour non interactive.'
    }
}

if ($generateAuditKey) {
    if ($DryRun) {
        Write-DryRun 'génération d''AUDIT_HMAC_KEY dans .env'
    } else {
        if (-not (Backup-Env)) { Stop-Update 'Impossible de sauvegarder .env avant de le modifier.' }
        Write-Ok "Copie de .env avant modification : $EnvBackup"
        $envPath = Join-Path $Root '.env'
        $tmpPath = Join-Path $Root ('.env.update.' + [guid]::NewGuid().ToString('N').Substring(0, 8))
        $rewriteOk = $false
        try {
            $buf = New-Object byte[] 64
            $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
            $rng.GetBytes($buf)
            $rng.Dispose()
            $newKey = (($buf | ForEach-Object { $_.ToString('x2') }) -join '')
            $buf = $null
            if ($newKey -cnotmatch '^[0-9a-f]{128}$') { throw 'clé invalide' }
            New-Item -ItemType File -Path $tmpPath -ErrorAction Stop | Out-Null
            $aclCopied = $false
            try {
                Set-Acl -LiteralPath $tmpPath -AclObject (Get-Acl -LiteralPath $envPath -ErrorAction Stop) -ErrorAction Stop
                $aclCopied = $true
            } catch {}
            if (-not $aclCopied) { [void](Set-OwnerOnlyAcl $tmpPath) }
            $raw = [System.IO.File]::ReadAllText($envPath, $Utf8)
            $nl = "`n"
            if ($raw.Contains("`r`n")) { $nl = "`r`n" }
            if ([regex]::IsMatch($raw, '(?m)^AUDIT_HMAC_KEY=')) {
                $updated = [regex]::Replace($raw, '(?m)^AUDIT_HMAC_KEY=[^\r\n]*', ('AUDIT_HMAC_KEY=' + $newKey))
            } else {
                $updated = $raw
                if ($updated.Length -gt 0 -and -not $updated.EndsWith("`n")) { $updated += $nl }
                $updated += 'AUDIT_HMAC_KEY=' + $newKey + $nl
            }
            [System.IO.File]::WriteAllText($tmpPath, $updated, $Utf8)
            $expectedLines = @((Get-EnvLineList $raw) | Where-Object { -not $_.StartsWith('AUDIT_HMAC_KEY=', [System.StringComparison]::Ordinal) }).Count
            $written = Get-EnvLineList ([System.IO.File]::ReadAllText($tmpPath, $Utf8))
            $otherLines = @($written | Where-Object { -not $_.StartsWith('AUDIT_HMAC_KEY=', [System.StringComparison]::Ordinal) }).Count
            $keyLines = @($written | Where-Object { $_ -ceq ('AUDIT_HMAC_KEY=' + $newKey) }).Count
            $anyKeyLines = @($written | Where-Object { $_.StartsWith('AUDIT_HMAC_KEY=', [System.StringComparison]::Ordinal) }).Count
            if ($otherLines -eq $expectedLines -and $keyLines -eq 1 -and $anyKeyLines -eq 1) { $rewriteOk = $true }
        } catch {
            $rewriteOk = $false
        }
        $newKey = $null
        $updated = $null
        $raw = $null
        if (-not $rewriteOk) {
            if (Test-Path -LiteralPath $tmpPath) { Remove-Item -LiteralPath $tmpPath -Force -ErrorAction SilentlyContinue }
            Stop-Update "La réécriture de .env n'a pas pu être contrôlée : .env est resté intact (copie : $EnvBackup)."
        }
        try {
            Move-Item -LiteralPath $tmpPath -Destination $envPath -Force -ErrorAction Stop
        } catch {
            if (Test-Path -LiteralPath $tmpPath) { Remove-Item -LiteralPath $tmpPath -Force -ErrorAction SilentlyContinue }
            Stop-Update "Impossible de mettre à jour .env (copie intacte : $EnvBackup)."
        }
        Write-Ok 'AUDIT_HMAC_KEY générée dans .env'
    }
}

Write-Step 5 'Construction des images'
if ((Invoke-Mutation @('compose', 'build')) -ne 0) { Stop-Update 'La construction des images a échoué.' }
$Phase = 'built'
Write-DoneOk 'Images construites'

Write-Step 6 'Vérification de la chaîne d''audit avant mise à jour'
$anchorBefore = ''
$auditBefore = ''
$verifyBefore = @('compose', 'run', '--rm', '--no-deps', '-T', '--user', 'node', '--entrypoint', 'node', 'backend', 'scripts/auditChain.js', 'verify')
if ($previousAnchor) { $verifyBefore += @('--anchor', $previousAnchor) }
if ($DryRun) {
    [void](Invoke-Mutation $verifyBefore)
} else {
    $auditRun = Invoke-Docker -Arguments $verifyBefore
    $auditBefore = Get-LastLine $auditRun.Out
    switch ($auditRun.Code) {
        0 {
            $anchorBefore = Get-JsonField $auditBefore 'last_hmac'
            Write-Ok "Chaîne intègre, ancre : $anchorBefore"
        }
        2 {
            Write-Err ("Chaîne d'audit en défaut avant la mise à jour : " + (Get-JsonObject $auditBefore 'problem_counts'))
            if (-not $AcceptAuditProblems) {
                Stop-Update 'Mise à jour arrêtée : examine l''intégrité dans Réglages → Audit, ou relance avec -AcceptAuditProblems pour poursuivre en connaissance de cause.'
            }
            $anchorBefore = Get-JsonField $auditBefore 'last_hmac'
            Write-Warn 'Défaut accepté explicitement (-AcceptAuditProblems)'
        }
        3 {
            Write-Warn 'Le schéma actuel ne permet pas encore de vérifier la chaîne : la mise à jour continue sans ancre préalable'
        }
        default {
            $shownAudit = $auditBefore
            if (-not $shownAudit) { $shownAudit = 'aucune réponse' }
            Stop-Update "Vérification de la chaîne impossible : $shownAudit"
        }
    }
}

Write-Step 7 'Arrêt du backend et du worker (base et volumes conservés)'
if ((Invoke-Mutation @('compose', 'stop', 'backend', 'worker')) -ne 0) { Stop-Update 'Impossible d''arrêter le backend et le worker.' }
$Phase = 'stopped'
Write-DoneOk 'backend et worker arrêtés'

Write-Step 8 'Sauvegarde vérifiée de la base'
if ($DryRun) {
    Write-DryRun "pg_dump vers $BackupRoot/$Stamp/heimdall-$Stamp.dump, puis pg_restore --list et SHA-256"
} else {
    $stampDir = Join-Path (Resolve-RepoPath $BackupRoot) $Stamp
    try {
        $backupRootFull = Resolve-RepoPath $BackupRoot
        if (-not (Test-Path -LiteralPath $backupRootFull -PathType Container)) {
            New-Item -ItemType Directory -Path $backupRootFull -ErrorAction Stop | Out-Null
        }
        if (Test-Path -LiteralPath $stampDir) { throw 'dossier existant' }
        New-Item -ItemType Directory -Path $stampDir -ErrorAction Stop | Out-Null
    } catch {
        Stop-Update "Impossible de créer un nouveau dossier de sauvegarde $BackupRoot/$Stamp."
    }
    if (-not (Set-OwnerOnlyAcl $stampDir)) { Write-Warn 'Droits du dossier de sauvegarde non restreints à l''utilisateur courant' }
    $BackupDir = (Resolve-Path -LiteralPath $stampDir).ProviderPath
    $DumpName = "heimdall-$Stamp.dump"
    $DumpFile = Join-Path $BackupDir $DumpName
    $dump = Invoke-Docker -Arguments @('compose', 'exec', '-T', 'db', 'pg_dump', '-U', 'forensiclab', '-d', 'forensiclab', '-Fc') -StdoutFile $DumpFile
    if ($dump.Code -ne 0) { Stop-Update 'pg_dump a échoué : pas de sauvegarde, pas de mise à jour.' }
    if (-not (Test-Path -LiteralPath $DumpFile) -or (Get-Item -LiteralPath $DumpFile).Length -le 0) { Stop-Update 'La sauvegarde est vide : pas de mise à jour.' }
    $list = Invoke-Docker -Arguments @('compose', 'exec', '-T', 'db', 'pg_restore', '--list') -StdinFile $DumpFile
    Write-TextFile (Join-Path $BackupDir 'dump-contents.txt') ($list.Out + $list.Err)
    if ($list.Code -ne 0) { Stop-Update 'La sauvegarde ne se relit pas avec pg_restore --list : pas de mise à jour.' }
    $DumpSha = (Get-FileHash -LiteralPath $DumpFile -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-TextFile (Join-Path $BackupDir "$DumpName.sha256") ("$DumpSha  $DumpName`n")
    if (-not (Backup-Env)) { Stop-Update 'Impossible de sauvegarder .env : pas de mise à jour.' }
    if ($auditBefore) { Write-TextFile (Join-Path $BackupDir 'audit-before.json') ($auditBefore + "`n") }
    Write-TextFile (Join-Path $BackupDir 'update.txt') ("from=$FromCommit`nto=$ToCommit`ndump=$DumpName`nsha256=$DumpSha`n")
    $dumpMb = [math]::Round((Get-Item -LiteralPath $DumpFile).Length / 1MB, 1)
    Write-Ok "Sauvegarde : $DumpFile ($dumpMb Mo, sha256 $DumpSha)"
}

Write-Step 9 'Migrations'
$Phase = 'migrating'
if (-not (Test-ManifestCoverage)) { Stop-Update 'Les migrations ont échoué.' }
if ($DryRun) {
    Write-DryRun 'application des migrations de db/migrations.manifest dans l''ordre, suivi dans schema_migrations'
} else {
    if (-not (Invoke-Migrations)) { Stop-Update 'Les migrations ont échoué.' }
}
Write-DoneOk 'Schéma à jour'

Write-Step 10 'Redémarrage, santé et inscription au journal d''audit'
if ((Invoke-Mutation @('compose', 'up', '-d')) -ne 0) {
    $Phase = 'started'
    Stop-Update 'docker compose up -d a échoué.'
}
$Phase = 'started'
if ($DryRun) {
    [void](Invoke-Mutation @('compose', 'exec', '-T', 'backend', 'node', 'scripts/auditChain.js', 'record', '--from', $FromCommit, '--to', $ToCommit))
    [void](Invoke-Mutation @('compose', 'exec', '-T', 'backend', 'node', 'scripts/auditChain.js', 'verify'))
    Write-Host "`nMode à blanc terminé : rien n'a été modifié." -ForegroundColor Green
    exit 0
}
foreach ($name in @('odin', 'huginn')) {
    if (-not (Wait-Healthy $name)) { Stop-Update "$name n'est pas sain après ${HealthTimeout}s (état : $script:LastHealthStatus)." }
    Write-Ok "$name sain"
}
$seed = Invoke-Docker -Arguments @('compose', 'exec', '-T', 'backend', 'node', 'scripts/seedDfiq.js')
if ($seed.Code -ne 0) { Write-Warn 'Chargement du catalogue DFIQ en échec, à relancer : docker exec odin node scripts/seedDfiq.js' }
$recordArgs = @('compose', 'exec', '-T', 'backend', 'node', 'scripts/auditChain.js', 'record', '--from', $FromCommit, '--to', $ToCommit, '--backup', $DumpName, '--backup-sha256', $DumpSha, '--operator', $operator, '--dirty', $dirty)
if ($anchorBefore) { $recordArgs += @('--anchor-before', $anchorBefore) }
$record = Invoke-Docker -Arguments $recordArgs
$recordOut = Get-LastLine $record.Out
if ($record.Code -ne 0) {
    $shownRecord = $recordOut
    if (-not $shownRecord) { $shownRecord = 'aucune réponse' }
    Stop-Update "La mise à jour n'a pas pu être inscrite au journal d'audit : $shownRecord"
}
$AnchorAfter = Get-JsonField $recordOut 'hmac'
if ($AnchorAfter -cnotmatch '^[0-9a-f]{64}$') { Stop-Update "Réponse d'inscription illisible : $recordOut" }
$resolvedBackupRoot = Resolve-RepoPath $BackupRoot
Write-TextFile (Join-Path $resolvedBackupRoot 'last-commit') ($ToCommit + "`n")
Write-TextFile (Join-Path $resolvedBackupRoot 'last-anchor') ($AnchorAfter + "`n")
[System.IO.File]::AppendAllText((Join-Path $BackupDir 'update.txt'), "anchor_after=$AnchorAfter`n", $Utf8)
Write-Ok 'Mise à jour inscrite au journal d''audit'
$verifyAfter = Invoke-Docker -Arguments @('compose', 'exec', '-T', 'backend', 'node', 'scripts/auditChain.js', 'verify', '--anchor', $AnchorAfter)
$auditAfter = Get-LastLine $verifyAfter.Out
Write-TextFile (Join-Path $BackupDir 'audit-after.json') ($auditAfter + "`n")
$afterCode = $verifyAfter.Code
$beforeCounts = Get-JsonObject $auditBefore 'problem_counts'
$afterCounts = Get-JsonObject $auditAfter 'problem_counts'
if ($afterCode -eq 2 -and $AcceptAuditProblems -and $afterCounts -and $beforeCounts -and (Test-CountsNotWorse $beforeCounts $afterCounts)) {
    Write-Warn "Chaîne toujours en défaut, sans problème nouveau ni aggravé depuis avant la mise à jour : $afterCounts (avant : $beforeCounts)"
    $afterCode = 0
}
if ($afterCode -ne 0) {
    Stop-Update ("Chaîne d'audit en défaut après la mise à jour : " + $afterCounts + "`n     Ne modifie rien dans audit_log ; examine Réglages → Audit et conserve $BackupDir.")
}

Write-Host ''
Write-Host '  Mise à jour terminée' -ForegroundColor Green
Write-Info "Sauvegarde et contrôles : $BackupDir"
Write-Info "Copie de .env (secrets, à garder à part du dump) : $EnvBackup"
Write-Info "Ancre d'audit de cette mise à jour (hmac de la ligne platform_update) : $AnchorAfter"
Write-Info 'Note cette ancre hors de la plateforme. La prochaine mise à jour vérifie qu''elle figure toujours dans la chaîne.'
