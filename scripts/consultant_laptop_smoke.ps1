param(
    [string]$Image = "aethelgard:local",
    [string]$DemoOut = "reports/consultant-laptop-smoke",
    [string]$PublicDataOut = "reports/consultant-public-data-smoke"
)

$ErrorActionPreference = "Stop"

function Assert-CleanOutput {
    param([string[]]$Paths)

    $forbiddenLiterals = @(".env", "api_key", "Bearer", "Cookie", "C:/Users", "C:\Users", "/home/")
    foreach ($path in $Paths) {
        if (-not (Test-Path $path)) {
            throw "Expected output path was not created: $path"
        }
        Get-ChildItem -Path $path -Recurse -File -Include *.json, *.md, *.csv | ForEach-Object {
            $text = Get-Content -LiteralPath $_.FullName -Raw -Encoding UTF8
            foreach ($literal in $forbiddenLiterals) {
                if ($text.Contains($literal)) {
                    throw "Forbidden marker '$literal' found in $($_.FullName)"
                }
            }
            if ($text -match "[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}") {
                throw "Possible email address found in $($_.FullName)"
            }
        }
    }
}

docker version
docker build -t $Image .
docker run --rm $Image --help
docker run --rm --network none $Image ml --help
docker run --rm --network none `
    -v "${PWD}/examples:/workspace/examples:ro" `
    -v "${PWD}/reports:/workspace/reports:rw" `
    $Image demo-pilot --examples examples/pilot --out $DemoOut
docker run --rm --network none `
    -v "${PWD}/examples:/workspace/examples:ro" `
    -v "${PWD}/reports:/workspace/reports:rw" `
    $Image public-data validate `
        --manifest examples/public/public_data_manifest.json `
        --out "${PublicDataOut}/public_data_validation.json"

Assert-CleanOutput -Paths @($DemoOut, $PublicDataOut)
Write-Host "Consultant laptop smoke passed for $Image"
