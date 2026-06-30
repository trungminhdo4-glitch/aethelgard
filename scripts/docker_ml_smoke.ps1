param(
    [string]$Image = "aethelgard:ml-smoke",
    [string]$Out = "reports/docker-ml-smoke",
    [string]$ReadinessOut = "reports/readiness",
    [string]$Scratch = ".tmp/docker-ml-smoke"
)

$ErrorActionPreference = "Stop"

function Invoke-AethelGardContainer {
    param([string[]]$CliArgs)

    docker run --rm --network none `
        -v "${PWD}/examples:/workspace/examples:ro" `
        -v "${PWD}/reports:/workspace/reports:rw" `
        -v "${PWD}/${Scratch}:/workspace/ml-input:ro" `
        $Image @CliArgs
}

function Assert-OutputFile {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Expected ML smoke output file was not created: $Path"
    }
}

function Assert-CleanMlOutput {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Expected ML smoke output path was not created: $Path"
    }
    $forbiddenLiterals = @(
        ".env",
        "api_key",
        "authorization",
        "Bearer",
        "Cookie",
        "token",
        "C:/Users",
        "C:\Users",
        "D:\",
        "/home/",
        "RAW_SNIPPET_SHOULD_NOT_EXPORT",
        "source_citation"
    )
    Get-ChildItem -LiteralPath $Path -Recurse -File -Include *.json, *.jsonl, *.md, *.csv | ForEach-Object {
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

New-Item -ItemType Directory -Force -Path $Out | Out-Null
New-Item -ItemType Directory -Force -Path $ReadinessOut | Out-Null
New-Item -ItemType Directory -Force -Path $Scratch | Out-Null

$trainingFixture = Join-Path $Scratch "doc_type_training.json"
@'
{
  "items": [
    {
      "item_id": "TRAIN-POLICY",
      "label": "policy_document",
      "text": "Policy owner review cadence and access procedure."
    },
    {
      "item_id": "TRAIN-AUDIT",
      "label": "audit_or_certificate",
      "text": "Audit certificate attestation and reviewed control evidence."
    }
  ]
}
'@ | Set-Content -Encoding UTF8 -Path $trainingFixture

$learningReviewCsv = Join-Path $Scratch "learning_review.csv"
@'
finding_id,review_status,review_note,reviewer
F-A,accepted,,
F-B,rejected,,
'@ | Set-Content -Encoding UTF8 -Path $learningReviewCsv

$learningPredictions = Join-Path $Scratch "learning_predictions.json"
@'
{
  "suggestions": [
    {
      "item_id": "F-A",
      "suggested_controls": [
        {
          "control_id": "NIS2-SCRM-04",
          "confidence": 0.74,
          "reason_codes": ["term_match:backup"]
        }
      ]
    }
  ],
  "ranked_findings": [
    {
      "finding_id": "F-B",
      "suggested_priority": "P2",
      "confidence": 0.61,
      "reason_codes": ["missing_restore_test"]
    }
  ]
}
'@ | Set-Content -Encoding UTF8 -Path $learningPredictions

$featuresOut = "$Out/features.jsonl"
$searchOut = "$Out/search_results.json"
$duplicatesOut = "$Out/duplicates.json"
$weakLabelsOut = "$Out/weak_labels.jsonl"
$modelOut = "$Out/models/doc_type_model.json"
$predictionsOut = "$Out/doc_predictions.json"
$controlsOut = "$Out/control_suggestions.json"
$severityOut = "$Out/ranked_findings.json"
$activeOut = "$Out/active_review_queue.json"
$learningOut = "$Out/learning_feedback.json"

docker version
docker build -t $Image .
docker run --rm --network none $Image --help
docker run --rm --network none $Image ml --help

Invoke-AethelGardContainer @("ml", "features", "--input", "examples/pilot/documents", "--out", $featuresOut)
Invoke-AethelGardContainer @("ml", "search", "--index", "examples/pilot/documents", "--query", "backup restore test", "--out", $searchOut)
Invoke-AethelGardContainer @("ml", "dedupe", "--input", "examples/pilot/documents", "--out", $duplicatesOut)
Invoke-AethelGardContainer @("ml", "weak-labels", "--input", "examples/pilot/documents", "--out", $weakLabelsOut)
Invoke-AethelGardContainer @("ml", "train-baselines", "--task", "doc-type", "--input", "ml-input/doc_type_training.json", "--out", $modelOut)
Invoke-AethelGardContainer @("ml", "classify-docs", "--model", $modelOut, "--input", "examples/pilot/documents", "--out", $predictionsOut)
Invoke-AethelGardContainer @("ml", "suggest-controls", "--input", "examples/pilot/documents", "--out", $controlsOut)
Invoke-AethelGardContainer @("ml", "rank-findings", "--input", $featuresOut, "--out", $severityOut)
Invoke-AethelGardContainer @("ml", "active-review", "--predictions", $predictionsOut, "--weak-labels", $weakLabelsOut, "--duplicates", $duplicatesOut, "--severity", $severityOut, "--out", $activeOut)
Invoke-AethelGardContainer @("ml", "export-learning-feedback", "--review-csv", "ml-input/learning_review.csv", "--predictions", "ml-input/learning_predictions.json", "--out", $learningOut)

@(
    $featuresOut,
    $searchOut,
    $duplicatesOut,
    $weakLabelsOut,
    $modelOut,
    $predictionsOut,
    $controlsOut,
    $severityOut,
    $activeOut,
    $learningOut
) | ForEach-Object { Assert-OutputFile -Path $_ }

Assert-CleanMlOutput -Path $Out

$proof = [ordered]@{
    status = "DOCKER_ML_RUNTIME_READY"
    image = $Image
    help = "pass"
    ml_help = "pass"
    features = "pass"
    search = "pass"
    dedupe = "pass"
    weak_labels = "pass"
    train_baselines = "pass"
    classify_docs = "pass"
    suggest_controls = "pass"
    rank_findings = "pass"
    active_review = "pass"
    export_learning_feedback = "pass"
    output_mount = "pass"
    network_none_ml = $true
    safety_scan = "pass"
    generated_at = (Get-Date).ToUniversalTime().ToString("o")
}
$proof | ConvertTo-Json -Depth 4 | Set-Content -Encoding UTF8 -Path (Join-Path $ReadinessOut "docker_ml_runtime_proof.json")

Write-Host "Docker ML smoke passed for $Image"
