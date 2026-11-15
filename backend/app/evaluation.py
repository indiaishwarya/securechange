from pathlib import Path

from .security import scan_builtin


BENCHMARK_ROOT = Path(__file__).resolve().parents[2] / "benchmark" / "fixtures"


def evaluate_benchmark() -> dict:
    files = sorted(path.relative_to(BENCHMARK_ROOT).as_posix() for path in BENCHMARK_ROOT.rglob("*") if path.is_file())
    predictions = scan_builtin(BENCHMARK_ROOT, files)
    expected = {
        ("missing-authorization", "vulnerable_service.py"),
        ("hardcoded-credential", "vulnerable_service.py"),
        ("insecure-http-url", "vulnerable_service.py"),
    }
    predicted = {(item["rule"], item["path"]) for item in predictions}
    true_positives = len(predicted & expected)
    false_positives = len(predicted - expected)
    false_negatives = len(expected - predicted)
    negative_cases = 3
    true_negatives = max(negative_cases - false_positives, 0)
    precision = true_positives / max(true_positives + false_positives, 1)
    recall = true_positives / max(true_positives + false_negatives, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-9)
    ranked = [item for item in predictions if (item["rule"], item["path"]) in expected]
    recall_at_k = len({(item["rule"], item["path"]) for item in ranked[:3]} & expected) / len(expected)
    false_positive_rate = false_positives / max(false_positives + true_negatives, 1)
    return {
        "benchmark": "securechange-intentional-bugs-v1",
        "cases": len(expected) + negative_cases,
        "predictions": len(predictions),
        "metrics": {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "recall_at_k": round(recall_at_k, 4),
            "k": 3,
            "false_positive_rate": round(false_positive_rate, 4),
        },
        "expected_findings": [
            {"rule": rule, "path": path}
            for rule, path in sorted(expected)
        ],
        "predicted_findings": predictions,
    }
