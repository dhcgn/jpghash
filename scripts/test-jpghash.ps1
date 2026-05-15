param(
    [string] $Root = 'D:\',
    [string] $Exe  = (Join-Path $PSScriptRoot '..' 'jpghash.exe'),
    [string] $Csv  = 'jpghash-errors.csv'
)

Write-Host "Building $Exe ..."
& go build -o $Exe (Join-Path $PSScriptRoot '..' 'cmd' 'jpghash')
if ($LASTEXITCODE -ne 0) { throw "go build failed (exit $LASTEXITCODE)" }

$resolved = Get-Command $Exe -ErrorAction Stop
Write-Host "Using: $($resolved.Source)"

$files = Get-ChildItem -LiteralPath $Root -Recurse -File -Include '*.jpg', '*.jpeg' |
    Sort-Object { Get-Random }
$total  = $files.Count
$i      = 0
$errors = 0
Write-Host "Found $total files. Writing errors to $Csv"

foreach ($f in $files) {
    $i++
    $out = & $Exe $f.FullName 2>&1
    if ($LASTEXITCODE -ne 0) {
        $errors++
        [pscustomobject]@{
            Path  = $f.FullName
            Error = ($out -join ' ')
        } | Export-Csv -LiteralPath $Csv -Append -NoTypeInformation -Encoding UTF8
    }
    Write-Progress -Activity 'jpghash' -Status "$i / $total  ($errors errors)" `
        -PercentComplete ([int](100 * $i / $total))
}

Write-Progress -Activity 'jpghash' -Completed
Write-Host "Done. $i files, $errors errors."
