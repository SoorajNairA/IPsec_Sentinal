from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path

from ipsec_sentinel.artifacts import write_json_atomic
from ipsec_sentinel.dataset.manifest import Manifest


@dataclass(frozen=True)
class DatasetSummary:
    dataset_name: str
    schema_version: str
    matrix_fingerprint: str
    planned_runs: int
    successful_runs: int
    failed_runs: int
    pending_runs: int
    incomplete_runs: int
    attempts_by_state: dict[str, int]
    training_ready_runs: int
    class_distribution: dict[str, int]
    failures_by_class: dict[str, int]
    total_esp_packets: int
    total_capture_bytes: int
    total_duration_seconds: float
    created_at: str
    updated_at: str
    supervised_ready_runs: int
    ood_ready_runs: int
    supervised_class_distribution: dict[str, int]
    ood_class_distribution: dict[str, int]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def build_summary(manifest: Manifest) -> DatasetSummary:
    connection = manifest.connection
    dataset = connection.execute("SELECT * FROM datasets").fetchone()
    if dataset is None:
        raise ValueError("manifest is not initialized")
    slot_counts = {
        row["state"]: row["count"]
        for row in connection.execute(
            "SELECT state,COUNT(*) AS count FROM slots GROUP BY state"
        ).fetchall()
    }
    attempt_counts = {
        row["state"]: row["count"]
        for row in connection.execute(
            "SELECT state,COUNT(*) AS count FROM attempts GROUP BY state"
        ).fetchall()
    }
    class_distribution = {
        row["traffic_class"]: row["count"]
        for row in connection.execute(
            "SELECT s.traffic_class,COUNT(*) AS count FROM slots s "
            "JOIN attempts a ON a.attempt_id=s.successful_attempt_id "
            "WHERE a.state='PASS' AND a.training_ready=1 "
            "GROUP BY s.traffic_class ORDER BY s.traffic_class"
        ).fetchall()
    }
    supervised_distribution = {
        row["traffic_class"]: row["count"]
        for row in connection.execute(
            "SELECT s.traffic_class,COUNT(*) AS count FROM slots s "
            "JOIN attempts a ON a.attempt_id=s.successful_attempt_id "
            "WHERE a.state='PASS' AND a.training_ready=1 "
            "AND s.known_training_class=1 AND s.class_role='supervised' "
            "GROUP BY s.traffic_class ORDER BY s.traffic_class"
        ).fetchall()
    }
    ood_distribution = {
        row["traffic_class"]: row["count"]
        for row in connection.execute(
            "SELECT s.traffic_class,COUNT(*) AS count FROM slots s "
            "JOIN attempts a ON a.attempt_id=s.successful_attempt_id "
            "WHERE a.state='PASS' AND a.training_ready=1 "
            "AND s.known_training_class=0 AND s.class_role='ood' "
            "GROUP BY s.traffic_class ORDER BY s.traffic_class"
        ).fetchall()
    }
    failures = {
        row["failure_class"]: row["count"]
        for row in connection.execute(
            "SELECT failure_class,COUNT(*) AS count FROM attempts "
            "WHERE failure_class IS NOT NULL GROUP BY failure_class ORDER BY failure_class"
        ).fetchall()
    }
    totals = connection.execute(
        "SELECT COUNT(*) AS count,COALESCE(SUM(esp_packets),0) AS esp,"
        "COALESCE(SUM(capture_bytes),0) AS bytes,"
        "COALESCE(SUM(duration_seconds),0) AS duration FROM attempts "
        "WHERE state='PASS' AND training_ready=1"
    ).fetchone()
    planned = connection.execute("SELECT COUNT(*) FROM slots").fetchone()[0]
    latest = connection.execute(
        "SELECT MAX(COALESCE(finished_at,started_at)) FROM attempts"
    ).fetchone()[0]
    return DatasetSummary(
        dataset["name"],
        dataset["schema_version"],
        dataset["matrix_fingerprint"],
        planned,
        slot_counts.get("PASS", 0),
        slot_counts.get("FAILED", 0),
        slot_counts.get("PENDING", 0) + slot_counts.get("RUNNING", 0),
        slot_counts.get("INCOMPLETE", 0),
        dict(sorted(attempt_counts.items())),
        totals["count"],
        class_distribution,
        failures,
        totals["esp"],
        totals["bytes"],
        totals["duration"],
        dataset["created_at"],
        latest or dataset["updated_at"],
        sum(supervised_distribution.values()),
        sum(ood_distribution.values()),
        supervised_distribution,
        ood_distribution,
    )


def write_summary(path: Path, summary: DatasetSummary) -> None:
    write_json_atomic(path, summary.to_dict())


def render_summary(summary: DatasetSummary) -> str:
    lines = [
        f"Dataset: {summary.dataset_name}",
        f"Planned runs: {summary.planned_runs}",
        f"Successful runs: {summary.successful_runs}",
        f"Failed runs: {summary.failed_runs}",
        f"Incomplete runs: {summary.incomplete_runs}",
        f"Training-ready runs: {summary.training_ready_runs}",
        f"Supervised-ready runs: {summary.supervised_ready_runs}",
        f"OOD-ready runs: {summary.ood_ready_runs}",
        "Class distribution:",
    ]
    lines.extend(f"  {name}: {count}" for name, count in summary.class_distribution.items())
    lines.extend(
        (
            f"ESP packets: {summary.total_esp_packets}",
            f"Capture bytes: {summary.total_capture_bytes}",
            f"Duration seconds: {summary.total_duration_seconds:.6f}",
        )
    )
    if summary.failures_by_class:
        lines.append("Failures:")
        lines.extend(
            f"  {name}: {count}" for name, count in summary.failures_by_class.items()
        )
    return "\n".join(lines)
