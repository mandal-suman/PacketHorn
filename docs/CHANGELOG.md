# Changelog

All notable changes to PacketHorn are documented here.

## v1.1.0

### Added

- YAML-based signature and behavior rule files
- MITRE ATT&CK tactic and technique metadata in rule models
- Confidence scoring in detection results
- Rule-level response actions
- Threshold grouping modes for signature counters
- Payload pattern matching for regex and hex content
- Packet direction inference during normalization
- Named IP groups such as `@internal`, `@external`, and `@workstations`
- Extended behavior-state metrics
- Linear and exponential decay handling in behavior evaluation
- Static and adaptive baseline behavior thresholds

### Changed

- Replaced the earlier text-rule format with YAML rule loading
- Reworked signature evaluation around configurable rule metadata
- Reworked behavior evaluation around grouped in-memory state
- Expanded the packet normalization path to populate direction, payload, ports, and flags

### Improved

- Detection flexibility through richer YAML schema support
- Rule readability through explicit fields and metadata
- Behavioral analytics through more concrete grouped metrics
- Response orchestration through rule-driven decision handling

## v1.0.0

Initial repository baseline with:

- Live packet capture
- Terminal dashboard workflow
- Basic protocol-aware detection flow
- Windows Firewall integration
- PCAP export
- PDF report generation
