$ErrorActionPreference = 'Stop'
$root = 'D:\ddd'
$outFile = 'D:\ddd\_scan_sensitive.txt'

$files = @()
$files += Get-ChildItem -Path "$root\*.md" -File
$files += Get-ChildItem -Path "$root\evidence", "$root\sandbox", "$root\tests" -Recurse -File |
    Where-Object { $_.Extension -in '.md', '.py', '.js', '.txt', '.json', '.yml', '.sh', '.ps1', '.yml' }
$files = $files | Sort-Object FullName -Unique

$pats = [ordered]@{
    'package'   = 'com\.[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+'
    'winpath'   = '[A-Za-z]:\\[^\s"''|<>]*'
    'ipv4'      = '\b(?:\d{1,3}\.){3}\d{1,3}\b'
    'url'       = 'https?://[^\s"''<>)]+'
    'sha256'    = '\b[a-fA-F0-9]{64}\b'
    'md5'       = '\b[a-fA-F0-9]{32}\b'
    'email'     = '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
    'androidid' = '\b[a-fA-F0-9]{16}\b'
}

$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine("FILES SCANNED: $($files.Count)")
[void]$sb.AppendLine('=' * 100)

foreach ($k in $pats.Keys) {
    $pat = $pats[$k]
    $counts = @{}
    $hitsPerFile = @{}
    foreach ($f in $files) {
        $m = Select-String -LiteralPath $f.FullName -Pattern $pat -AllMatches -Encoding utf8
        if (-not $m) { continue }
        $vals = @()
        foreach ($x in $m) { foreach ($v in $x.Matches) { $vals += $v.Value } }
        if ($vals.Count -eq 0) { continue }
        $hitsPerFile[$f.FullName] = $vals.Count
        foreach ($v in $vals) {
            if ($counts.ContainsKey($v)) { $counts[$v]++ } else { $counts[$v] = 1 }
        }
    }
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine("### PATTERN: $k   (unique=$(($counts.Keys).Count), files=$($hitsPerFile.Count))")
    foreach ($kv in ($counts.GetEnumerator() | Sort-Object Value -Descending)) {
        [void]$sb.AppendLine(("  {0,5}  {1}" -f $kv.Value, $kv.Key))
    }
}

[void]$sb.AppendLine('')
[void]$sb.AppendLine('=' * 100)
[void]$sb.AppendLine('### CIPHER / SUSPECT FILE NAMES AND TOP-LEVEL NAMES')
Get-ChildItem -Path $root -File | ForEach-Object { [void]$sb.AppendLine("  FILE  $($_.Name)") }

[System.IO.File]::WriteAllText($outFile, $sb.ToString(), (New-Object System.Text.UTF8Encoding($false)))
Write-Output "WROTE $outFile"
