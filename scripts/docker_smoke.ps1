param(
    [string]$Image = "aethelgard:local",
    [string]$Out = "reports/docker-smoke"
)

$ErrorActionPreference = "Stop"

docker version
docker build -t $Image .
docker run --rm $Image --help
docker run --rm --network none `
    -v "${PWD}/examples:/workspace/examples:ro" `
    -v "${PWD}/reports:/workspace/reports:rw" `
    $Image demo-pilot --examples examples/pilot --out $Out
docker compose run --rm aethelgard --help
docker compose run --rm aethelgard demo-pilot --examples examples/pilot --out reports/docker-compose-demo
