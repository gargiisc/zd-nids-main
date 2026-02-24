from datetime import datetime, timedelta

from collectors.flow_source_collector import MultiSourceFlowCollector
from collectors.streaming_pipeline import FlowBufferRateLimiter
from detection.alert_manager import Alert, AlertManager, AlertPriority, AlertStatus
from detection.detector import AlertCorrelator, DetectionResult, ThreatSeverity


def test_flow_buffer_rate_limiter_enqueue_dequeue():
    limiter = FlowBufferRateLimiter(max_queue_size=2, max_flows_per_second=100)
    assert limiter.enqueue({"id": 1}) is True
    assert limiter.enqueue({"id": 2}) is True
    assert limiter.enqueue({"id": 3}) is False
    drained = limiter.dequeue(timeout=0.01)
    assert drained in ({"id": 1}, {"id": 2})


def test_multi_source_collector_normalizes_ipfix_keys():
    collector = MultiSourceFlowCollector()
    flow = collector.normalize(
        {
            "sourceIPv4Address": "10.0.0.1",
            "destinationIPv4Address": "10.0.0.2",
            "sourceTransportPort": 1234,
            "destinationTransportPort": 443,
            "protocolIdentifier": 6,
            "packetDeltaCount": 10,
            "octetDeltaCount": 1000,
        },
        source_type="ipfix",
    )
    assert flow is not None
    assert flow.src_ip == "10.0.0.1"
    assert flow.dst_port == 443


def test_alert_correlation_groups_similar_results():
    correlator = AlertCorrelator()
    results = [
        DetectionResult(True, "DDoS", 0.8, ThreatSeverity.CRITICAL, "ensemble", source_ip="1.1.1.1"),
        DetectionResult(True, "DDoS", 0.9, ThreatSeverity.CRITICAL, "ensemble", source_ip="1.1.1.1"),
    ]
    correlated = correlator.correlate(results)
    assert len(correlated) == 1
    assert correlated[0].metadata["correlated_count"] == 2


def test_alert_manager_escalation_rules():
    manager = AlertManager(config={
        "escalation_rules": [
            {"after_minutes": 5, "channel": "pagerduty", "target": "https://example.invalid/hook"}
        ]
    })

    alert = Alert(
        id="A1",
        attack_type="DDoS",
        severity="HIGH",
        confidence=0.9,
        source_ip="1.1.1.1",
        destination_ip="2.2.2.2",
        source_port=123,
        destination_port=80,
        protocol="TCP",
        timestamp=datetime.utcnow() - timedelta(minutes=10),
        status=AlertStatus.NEW,
        priority=AlertPriority.HIGH,
    )
    manager._active_alerts[alert.id] = alert

    # monkeypatch notifier method with a successful lambda to avoid network calls
    manager.webhook_notifier.send = lambda *args, **kwargs: True
    escalated = manager.run_escalation_check()
    assert "A1" in escalated
