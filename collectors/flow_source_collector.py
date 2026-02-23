"""Multi-source flow collector for NetFlow/sFlow/IPFIX-like records."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Optional


@dataclass
class NormalizedFlow:
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packets: int
    bytes: int
    source_type: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "packets": self.packets,
            "bytes": self.bytes,
            "source_type": self.source_type,
        }


class MultiSourceFlowCollector:
    """Normalizes flow records from different telemetry systems."""

    def normalize(self, payload: Dict[str, Any], source_type: str) -> Optional[NormalizedFlow]:
        source_type = source_type.lower()
        if source_type == "netflow":
            return self._from_netflow(payload)
        if source_type == "sflow":
            return self._from_sflow(payload)
        if source_type == "ipfix":
            return self._from_ipfix(payload)
        raise ValueError(f"Unsupported source_type: {source_type}")

    def _from_netflow(self, payload: Dict[str, Any]) -> Optional[NormalizedFlow]:
        return self._build(payload, source_type="netflow")

    def _from_sflow(self, payload: Dict[str, Any]) -> Optional[NormalizedFlow]:
        return self._build(payload, source_type="sflow")

    def _from_ipfix(self, payload: Dict[str, Any]) -> Optional[NormalizedFlow]:
        return self._build(payload, source_type="ipfix")

    def _build(self, payload: Dict[str, Any], source_type: str) -> Optional[NormalizedFlow]:
        src_ip = payload.get("src_ip") or payload.get("sourceIPv4Address")
        dst_ip = payload.get("dst_ip") or payload.get("destinationIPv4Address")
        if not src_ip or not dst_ip:
            return None

        return NormalizedFlow(
            timestamp=datetime.utcnow(),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=int(payload.get("src_port") or payload.get("sourceTransportPort") or 0),
            dst_port=int(payload.get("dst_port") or payload.get("destinationTransportPort") or 0),
            protocol=str(payload.get("protocol") or payload.get("protocolIdentifier") or "unknown"),
            packets=int(payload.get("packets") or payload.get("packetDeltaCount") or 0),
            bytes=int(payload.get("bytes") or payload.get("octetDeltaCount") or 0),
            source_type=source_type,
        )
