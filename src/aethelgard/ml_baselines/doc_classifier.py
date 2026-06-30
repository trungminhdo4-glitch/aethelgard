"""Document-type baseline classifier with a dependency-free fallback model."""

from __future__ import annotations

import csv
import importlib.util
import json
import math
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Final, TypedDict, cast

from aethelgard.ml_baselines.features import IndexItem, collect_index_items, tokenize
from aethelgard.ml_baselines.model_registry import (
    ModelMetadata,
    attach_metadata,
    build_model_metadata,
    safe_training_ref,
    write_json,
)

DOC_TYPE_MODEL_NAME: Final[str] = "KeywordNaiveBayes"
DOC_TYPE_MODEL_TYPE: Final[str] = "pure_python_multinomial_nb"
MODEL_FORMAT_VERSION: Final[str] = "doc-type-json-v1"
CONFIDENCE_PRECISION: Final[int] = 4
MIN_TRAINING_EXAMPLES: Final[int] = 1


class TrainingExample(TypedDict):
    """Minimal document-type training example."""

    item_id: str
    text: str
    label: str


class DocTypeModel(TypedDict):
    """JSON-serializable fallback document classifier model."""

    model_format_version: str
    labels: list[str]
    label_priors: dict[str, float]
    label_token_counts: dict[str, dict[str, int]]
    label_token_totals: dict[str, int]
    vocabulary: list[str]
    model_metadata: ModelMetadata


class DocPrediction(TypedDict):
    """One metadata-only document prediction."""

    item_id: str
    predicted_label: str
    confidence: float
    needs_review: bool
    model: str
    model_version: str


class DocClassifierError(ValueError):
    """Raised when baseline training or prediction cannot continue."""


def train_doc_type_baseline(
    input_path: Path | str,
    out_path: Path | str,
    *,
    generated_at: str | None = None,
) -> DocTypeModel:
    """Train and write a tiny dependency-free document-type classifier."""
    examples = _load_training_examples(Path(input_path))
    if len(examples) < MIN_TRAINING_EXAMPLES:
        raise DocClassifierError("at least one labeled training example is required")
    metadata = build_model_metadata(
        model_name=DOC_TYPE_MODEL_NAME,
        model_type=DOC_TYPE_MODEL_TYPE,
        training_data_ref=safe_training_ref(input_path),
        generated_at=generated_at,
        experimental=True,
        sklearn_available=is_sklearn_available(),
    )
    model = _train_model(examples, metadata)
    write_json(out_path, model)
    return model


def classify_documents(
    model_path: Path | str,
    input_path: Path | str,
    *,
    project_root: Path | str | None = None,
) -> dict[str, object]:
    """Classify local documents with a JSON fallback model."""
    model = _load_model(Path(model_path))
    items = [
        item
        for item in collect_index_items(input_path, project_root=project_root)
        if item["item_type"] == "document"
    ]
    predictions = [
        _predict_item(model, item)
        for item in sorted(items, key=lambda value: (value["source_ref"], value["item_id"]))
    ]
    return attach_metadata({"predictions": predictions}, model["model_metadata"])


def is_sklearn_available() -> bool:
    """Return whether sklearn is importable without importing it."""
    return importlib.util.find_spec("sklearn") is not None


def _train_model(examples: Sequence[TrainingExample], metadata: ModelMetadata) -> DocTypeModel:
    labels = sorted({example["label"] for example in examples})
    label_examples = Counter(example["label"] for example in examples)
    label_token_counts: dict[str, dict[str, int]] = {label: {} for label in labels}
    label_token_totals: dict[str, int] = {label: 0 for label in labels}
    vocabulary: set[str] = set()
    for example in examples:
        label = example["label"]
        counts = Counter(tokenize(example["text"]))
        vocabulary.update(counts)
        for token, count in counts.items():
            label_token_counts[label][token] = label_token_counts[label].get(token, 0) + count
            label_token_totals[label] += count
    total_examples = len(examples)
    label_priors = {
        label: label_examples[label] / total_examples
        for label in labels
    }
    return {
        "model_format_version": MODEL_FORMAT_VERSION,
        "labels": labels,
        "label_priors": label_priors,
        "label_token_counts": label_token_counts,
        "label_token_totals": label_token_totals,
        "vocabulary": sorted(vocabulary),
        "model_metadata": metadata,
    }


def _predict_item(model: DocTypeModel, item: IndexItem) -> DocPrediction:
    labels = model["labels"]
    if not labels:
        return _prediction(item["item_id"], "unknown", 0.0, model)
    tokens = tokenize(item["text"])
    if not tokens:
        return _prediction(item["item_id"], labels[0], 0.0, model)
    scores = {label: _label_log_score(model, label, tokens) for label in labels}
    predicted_label = max(sorted(scores), key=lambda label: scores[label])
    confidence = _softmax_confidence(scores, predicted_label)
    return _prediction(item["item_id"], predicted_label, confidence, model)


def _prediction(
    item_id: str,
    predicted_label: str,
    confidence: float,
    model: DocTypeModel,
) -> DocPrediction:
    metadata = model["model_metadata"]
    return {
        "item_id": item_id,
        "predicted_label": predicted_label,
        "confidence": round(confidence, CONFIDENCE_PRECISION),
        "needs_review": True,
        "model": metadata["model_name"],
        "model_version": metadata["model_version"],
    }


def _label_log_score(model: DocTypeModel, label: str, tokens: Sequence[str]) -> float:
    vocabulary_size = max(len(model["vocabulary"]), 1)
    label_total = model["label_token_totals"].get(label, 0)
    token_counts = model["label_token_counts"].get(label, {})
    prior = max(model["label_priors"].get(label, 0.0), 1.0 / max(len(model["labels"]), 1))
    score = math.log(prior)
    denominator = label_total + vocabulary_size
    for token in tokens:
        score += math.log((token_counts.get(token, 0) + 1) / denominator)
    return score


def _softmax_confidence(scores: Mapping[str, float], predicted_label: str) -> float:
    max_score = max(scores.values())
    exponentials = {
        label: math.exp(score - max_score)
        for label, score in scores.items()
    }
    total = sum(exponentials.values())
    if total <= 0.0:
        return 0.0
    return exponentials[predicted_label] / total


def _load_training_examples(path: Path) -> tuple[TrainingExample, ...]:
    if path.suffix.casefold() == ".csv":
        return _load_training_examples_csv(path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    raw_items = payload.get("items", ()) if isinstance(payload, Mapping) else payload
    if not isinstance(raw_items, Sequence) or isinstance(raw_items, (str, bytes, bytearray)):
        raise DocClassifierError("training data must contain items")
    return tuple(
        _coerce_training_example(item, index)
        for index, item in enumerate(raw_items, start=1)
    )


def _load_training_examples_csv(path: Path) -> tuple[TrainingExample, ...]:
    with path.open(encoding="utf-8", newline="") as csv_file:
        reader = csv.DictReader(csv_file)
        rows = list(reader)
    return tuple(_coerce_training_example(row, index) for index, row in enumerate(rows, start=1))


def _coerce_training_example(value: object, index: int) -> TrainingExample:
    if not isinstance(value, Mapping):
        raise DocClassifierError("training example %d must be an object" % index)
    label = str(value.get("label", "")).strip()
    text = str(value.get("text", "")).strip()
    if not label or not text:
        raise DocClassifierError("training example %d requires label and text" % index)
    return {
        "item_id": str(value.get("item_id", "TRAIN-%d" % index)).strip(),
        "text": text,
        "label": label,
    }


def _load_model(path: Path) -> DocTypeModel:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, Mapping):
        raise DocClassifierError("model artifact must be a JSON object")
    if str(payload.get("model_format_version", "")) != MODEL_FORMAT_VERSION:
        raise DocClassifierError("unsupported document classifier model format")
    metadata = _coerce_metadata(payload.get("model_metadata", {}))
    return {
        "model_format_version": MODEL_FORMAT_VERSION,
        "labels": [str(label) for label in _sequence(payload.get("labels", ()))],
        "label_priors": _float_mapping(payload.get("label_priors", {})),
        "label_token_counts": _nested_int_mapping(payload.get("label_token_counts", {})),
        "label_token_totals": _int_mapping(payload.get("label_token_totals", {})),
        "vocabulary": [str(token) for token in _sequence(payload.get("vocabulary", ()))],
        "model_metadata": metadata,
    }


def _coerce_metadata(value: object) -> ModelMetadata:
    if not isinstance(value, Mapping):
        raise DocClassifierError("model metadata is missing")
    return cast(ModelMetadata, dict(value))


def _sequence(value: object) -> tuple[object, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return ()
    return tuple(value)


def _float_mapping(value: object) -> dict[str, float]:
    if not isinstance(value, Mapping):
        return {}
    return {str(key): float(item) for key, item in value.items()}


def _int_mapping(value: object) -> dict[str, int]:
    if not isinstance(value, Mapping):
        return {}
    return {str(key): int(item) for key, item in value.items()}


def _nested_int_mapping(value: object) -> dict[str, dict[str, int]]:
    if not isinstance(value, Mapping):
        return {}
    result: dict[str, dict[str, int]] = {}
    for key, item in value.items():
        result[str(key)] = _int_mapping(item)
    return result
