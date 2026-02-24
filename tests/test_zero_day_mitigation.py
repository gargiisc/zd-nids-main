from dataclasses import dataclass, field
from datetime import datetime

from response.zero_day_mitigation import AttackTypeInference, ZeroDayMitigationEngine


@dataclass
class FakeSeverity:
    name: str


@dataclass
class FakeDetectionResult:
    attack_type: str = "Unknown"
    confidence: float = 0.95
    severity: FakeSeverity = field(default_factory=lambda: FakeSeverity(name="CRITICAL"))
    source_ip: str = "8.8.8.8"
    metadata: dict = field(default_factory=dict)
    raw_features: dict = field(default_factory=dict)
    is_attack: bool = True
    id: str = "T-1"


def test_attack_type_inference_ddos():
    inference = AttackTypeInference()
    assert inference.infer({"packets_per_second": 5000}) == "ddos"


def test_should_trigger_from_confidence_threshold():
    engine = ZeroDayMitigationEngine(dry_run=True)
    result = FakeDetectionResult(confidence=0.9)
    assert engine.should_trigger(result) is True


def test_critical_policy_executes_block_and_isolate(tmp_path):
    policy_file = tmp_path / "policies.yaml"
    policy_file.write_text(
        """
policies:
  critical:
    - block_ip
    - isolate_host
  low:
    - alert_only
""".strip()
    )

    engine = ZeroDayMitigationEngine(policy_path=str(policy_file), dry_run=True)
    result = FakeDetectionResult(
        confidence=0.99,
        severity=FakeSeverity(name="CRITICAL"),
        source_ip="9.9.9.9",
        metadata={"interface": "eth0"},
    )

    events = engine.process_detection(result)
    assert len(events) == 2
    assert events[0].action_taken == "block_ip"
    assert events[0].rollback_available is True


def test_allowlist_blocks_destructive_action(tmp_path):
    policy_file = tmp_path / "policies.yaml"
    policy_file.write_text(
        """
policies:
  critical:
    - block_ip
  low:
    - alert_only
""".strip()
    )

    engine = ZeroDayMitigationEngine(
        policy_path=str(policy_file),
        dry_run=True,
        allowlist_ips=["1.1.1.1"],
    )
    result = FakeDetectionResult(source_ip="1.1.1.1")

    events = engine.process_detection(result)
    assert events[0].status == "skipped"
