"""
Log Collectors Package for AI-NIDS

This package provides comprehensive network traffic collection capabilities:
- Suricata: Signature-based IDS alert parsing
- Zeek: Network metadata and flow log parsing
- PCAP: Offline packet capture file processing
- Live Capture: Real-time packet sniffing with Scapy
"""

from .suricata_parser import SuricataParser, SuricataFlow, create_suricata_parser
from .zeek_parser import ZeekParser, ZeekConn, create_zeek_parser
from .pcap_handler import PCAPHandler, analyze_pcap
from .live_capture import LiveCapture, LiveCaptureManager

__all__ = [
    # Suricata Parser
    'SuricataParser', 'SuricataFlow', 'create_suricata_parser',
    # Zeek Parser
    'ZeekParser', 'ZeekConn', 'create_zeek_parser',
    # PCAP Handler
    'PCAPHandler', 'analyze_pcap',
    # Live Capture
    'LiveCapture', 'LiveCaptureManager', 'FlowBufferRateLimiter', 'KafkaFlowPublisher', 'KafkaFlowConsumer', 'LiveCaptureKafkaBridge', 'MultiSourceFlowCollector', 'NormalizedFlow'
]

from .streaming_pipeline import FlowBufferRateLimiter, KafkaFlowPublisher, KafkaFlowConsumer, LiveCaptureKafkaBridge
from .flow_source_collector import MultiSourceFlowCollector, NormalizedFlow
