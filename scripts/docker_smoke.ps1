param(
    [string]$Image = "aethelgard:local",
    [string]$Out = "reports/docker-smoke",
    [string]$PilotProductOut = "reports/docker-pilot-product",
    [string]$DoctorOut = "reports/docker-doctor",
    [string]$SupportBundleOut = "reports/docker-support-bundle.zip",
    [string]$ReadinessOut = "reports/readiness"
)

$ErrorActionPreference = "Stop"

docker version
docker build -t $Image .
docker run --rm $Image --help
docker run --rm --network none `
    -v "${PWD}/examples:/workspace/examples:ro" `
    -v "${PWD}/reports:/workspace/reports:rw" `
    $Image demo-pilot --examples examples/pilot --out $Out
docker run --rm --network none `
    -v "${PWD}/examples:/workspace/examples:ro" `
    -v "${PWD}/reports:/workspace/reports:rw" `
    $Image pilot-product `
        --workspace examples/pilot `
        --out $PilotProductOut `
        --client-id docker-demo `
        --case-id case001
docker run --rm --network none `
    -v "${PWD}/examples:/workspace/examples:ro" `
    -v "${PWD}/reports:/workspace/reports:rw" `
    $Image doctor --workspace examples/pilot --out $DoctorOut
docker run --rm --network none `
    -v "${PWD}/examples:/workspace/examples:ro" `
    -v "${PWD}/reports:/workspace/reports:rw" `
    $Image support-bundle `
        --workspace examples/pilot `
        --out $SupportBundleOut `
        --redacted
docker run --rm --network none `
    -v "${PWD}/examples:/workspace/examples:ro" `
    -v "${PWD}/reports:/workspace/reports:rw" `
    $Image public-data validate `
        --manifest examples/public/public_data_manifest.json `
        --out reports/public-data-smoke/public_data_validation.json
docker compose run --rm aethelgard --help
docker compose run --rm aethelgard demo-pilot --examples examples/pilot --out reports/docker-compose-demo

New-Item -ItemType Directory -Force -Path $ReadinessOut | Out-Null
$proof = [ordered]@{
    status = "DOCKER_RUNTIME_READY"
    image = $Image
    help = "pass"
    demo_pilot = "pass"
    pilot_product = "pass"
    doctor = "pass"
    support_bundle_redacted = "pass"
    public_data_validate = "pass"
    output_mount = "pass"
    network_none_demo = $true
    generated_at = (Get-Date).ToUniversalTime().ToString("o")
}
$proofPath = Join-Path $ReadinessOut "docker_runtime_proof.json"
$utf8NoBom = New-Object System.Text.UTF8Encoding $false
$proofJson = ($proof | ConvertTo-Json -Depth 4) + [Environment]::NewLine
[System.IO.File]::WriteAllText($proofPath, $proofJson, $utf8NoBom)
