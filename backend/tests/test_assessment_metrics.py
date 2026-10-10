from app.services.assessment_metrics import (
    GroundTruthCase,
    calculate_assessment_metrics,
)


def test_ground_truth_metrics_use_explicit_denominators() -> None:
    metrics = calculate_assessment_metrics(
        [
            GroundTruthCase("blocked", "blocked", 4),
            GroundTruthCase("quarantined", "quarantined", 6),
            GroundTruthCase("allowed", "allowed", 2),
            GroundTruthCase("allowed", "blocked", 3),
            GroundTruthCase("blocked", "allowed", 5),
        ],
        planned_tests=6,
        assessment_duration_ms=25,
    )

    assert metrics.executed_tests == 5
    assert metrics.skipped_tests == 1
    assert metrics.true_positives == 2
    assert metrics.false_positives == 1
    assert metrics.false_negatives == 1
    assert metrics.true_negatives == 1
    assert metrics.test_execution_rate_percent.value == 83.333
    assert metrics.detection_precision_percent.value == 66.667
    assert metrics.detection_recall_percent.value == 66.667
    assert metrics.false_positive_rate_percent.value == 50.0
    assert metrics.mean_time_to_detect_ms.value == 5.0


def test_metrics_mark_external_evidence_as_unavailable() -> None:
    metrics = calculate_assessment_metrics(
        [GroundTruthCase("allowed", "allowed", 1)],
        planned_tests=1,
        assessment_duration_ms=1,
    )

    assert metrics.tool_reliability_percent.status == "unavailable"
    assert metrics.resource_consumption.status == "unavailable"
    assert metrics.remediation_success_rate_percent.status == "unavailable"
    assert metrics.regression_rate_percent.status == "unavailable"
