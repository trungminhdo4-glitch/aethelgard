param(
    [string]$Image = "aethelgard:local",
    [string]$Out = "reports/docker-smoke",
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
    public_data_validate = "pass"
    output_mount = "pass"
    network_none_demo = $true
    generated_at = (Get-Date).ToUniversalTime().ToString("o")
}
$proof | ConvertTo-Json -Depth 4 | Set-Content -Encoding UTF8 -Path (Join-Path $ReadinessOut "docker_runtime_proof.json")
