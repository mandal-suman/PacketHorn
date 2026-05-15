param(
    [string]$Configuration = "Debug"
)

$repoRoot = Split-Path -Parent $PSCommandPath
$solutionPath = Join-Path $repoRoot "PacketHorn.sln"

Push-Location $repoRoot
try {
    dotnet build $solutionPath -c $Configuration -m:1
    exit $LASTEXITCODE
}
finally {
    Pop-Location
}
