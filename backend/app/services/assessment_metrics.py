"""Transparent calculations for controlled ground-truth assessments."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Verdict = Literal["allowed", "quarantined", "blocked"]


@dataclass(frozen=True)
class MetricValue:
    value: float | None
    status: Literal["available", "unavailable"]
    denominator: int | None = None
    reason: str | None = None

    def as_dict(self) -> dict[str, float | int | str | None]:
        return {
            "value": self.value,
            "status": self.status,
            "denominator": self.denominator,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class GroundTruthCase:
    expected_verdict: Verdict
    actual_verdict: Verdict
    elapsed_ms: int


@dataclass(frozen=True)
class AssessmentMetrics:
    planned_tests: int
    executed_tests: int
    skipped_tests: int
    unsupported_tests: int
    true_positives: int
    false_positives: int
    false_negatives: int
    true_negatives: int
    test_execution_rate_percent: MetricValue
    applicable_test_coverage_percent: MetricValue
    detection_precision_percent: MetricValue
    detection_recall_percent: MetricValue
    false_positive_rate_percent: MetricValue
    evaluation_engine_reliability_percent: MetricValue
    tool_reliability_percent: MetricValue
    mean_time_to_detect_ms: MetricValue
    assessment_duration_ms: MetricValue
    resource_consumption: MetricValue
    remediation_success_rate_percent: MetricValue
    regression_rate_percent: MetricValue

    def as_dict(self) -> dict[str, object]:
        return {
            "planned_tests": self.planned_tests,
            "executed_tests": self.executed_tests,
            "skipped_tests": self.skipped_tests,
            "unsupported_tests": self.unsupported_tests,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "true_negatives": self.true_negatives,
            "test_execution_rate_percent": self.test_execution_rate_percent.as_dict(),
            "applicable_test_coverage_percent": (
                self.applicable_test_coverage_percent.as_dict()
            ),
            "detection_precision_percent": self.detection_precision_percent.as_dict(),
            "detection_recall_percent": self.detection_recall_percent.as_dict(),
            "false_positive_rate_percent": self.false_positive_rate_percent.as_dict(),
            "evaluation_engine_reliability_percent": (
                self.evaluation_engine_reliability_percent.as_dict()
            ),
            "tool_reliability_percent": self.tool_reliability_percent.as_dict(),
            "mean_time_to_detect_ms": self.mean_time_to_detect_ms.as_dict(),
            "assessment_duration_ms": self.assessment_duration_ms.as_dict(),
            "resource_consumption": self.resource_consumption.as_dict(),
            "remediation_success_rate_percent": (
                self.remediation_success_rate_percent.as_dict()
            ),
            "regression_rate_percent": self.regression_rate_percent.as_dict(),
        }


def calculate_assessment_metrics(
    cases: list[GroundTruthCase],
    *,
    planned_tests: int,
    assessment_duration_ms: int,
) -> AssessmentMetrics:
    """Calculate only metrics whose labels and denominators are known.

    A case is ground-truth risky when its expected verdict is not ``allowed``.
    A detection occurs when the actual result is ``blocked`` or ``quarantined``.
    This measures the static policy engine against its committed benchmark; it
    does not measure an external security scanner or a production agent.
    """
    executed_tests = len(cases)
    skipped_tests = max(planned_tests - executed_tests, 0)
    true_positives = false_positives = false_negatives = true_negatives = 0
    detection_times: list[int] = []
    for case in cases:
        expected_risky = case.expected_verdict != "allowed"
        detected_risky = case.actual_verdict != "allowed"
        if expected_risky and detected_risky:
            true_positives += 1
            detection_times.append(case.elapsed_ms)
        elif expected_risky:
            false_negatives += 1
        elif detected_risky:
            false_positives += 1
        else:
            true_negatives += 1

    return AssessmentMetrics(
        planned_tests=planned_tests,
        executed_tests=executed_tests,
        skipped_tests=skipped_tests,
        unsupported_tests=0,
        true_positives=true_positives,
        false_positives=false_positives,
        false_negatives=false_negatives,
        true_negatives=true_negatives,
        test_execution_rate_percent=_percentage(executed_tests, planned_tests),
        applicable_test_coverage_percent=_percentage(executed_tests, planned_tests),
        detection_precision_percent=_percentage(
            true_positives,
            true_positives + false_positives,
        ),
        detection_recall_percent=_percentage(
            true_positives,
            true_positives + false_negatives,
        ),
        false_positive_rate_percent=_percentage(
            false_positives,
            false_positives + true_negatives,
        ),
        evaluation_engine_reliability_percent=_percentage(
            executed_tests, planned_tests
        ),
        tool_reliability_percent=_unavailable(
            "No external tool ran in this static policy assessment."
        ),
        mean_time_to_detect_ms=(
            MetricValue(
                value=round(sum(detection_times) / len(detection_times), 3),
                status="available",
                denominator=len(detection_times),
            )
            if detection_times
            else _unavailable("No ground-truth risky case was detected.")
        ),
        assessment_duration_ms=MetricValue(
            value=float(assessment_duration_ms),
            status="available",
            denominator=1,
        ),
        resource_consumption=_unavailable(
            "CPU, memory, storage, and execution cost are not collected yet."
        ),
        remediation_success_rate_percent=_unavailable(
            "No remediation retest evidence is linked to this assessment."
        ),
        regression_rate_percent=_unavailable(
            "No previously fixed finding was retested in this assessment."
        ),
    )


def _percentage(numerator: int, denominator: int) -> MetricValue:
    if denominator == 0:
        return _unavailable("The metric denominator is zero.")
    return MetricValue(
        value=round((numerator / denominator) * 100, 3),
        status="available",
        denominator=denominator,
    )


def _unavailable(reason: str) -> MetricValue:
    return MetricValue(value=None, status="unavailable", reason=reason)
