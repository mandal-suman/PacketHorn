# Release Notes

This document summarizes the current documented releases for PacketHorn.

## v1.1.0

`v1.1.0` represents the YAML-rule generation of the project and the current architecture reflected in this repository.

Key additions and refinements:

- YAML-based signature and behavior rule loading
- MITRE ATT&CK metadata in rule definitions and detection results
- Confidence scoring for signature and behavior detections
- Rule-driven response actions
- Threshold grouping for signature counters
- Payload matching in regex and hexadecimal form
- Direction inference during packet normalization
- Named IP groups such as `@internal`, `@external`, and `@workstations`
- Expanded behavior metrics, including unique ports, unique IPs, session counts, FQDN extraction, and decayed counters
- Static and adaptive baseline support in behavior evaluation

Operationally important notes:

- Packet normalization remains IPv4-focused
- Response execution remains Windows-specific
- The application is still centered on the terminal dashboard runtime

## v1.0.0

`v1.0.0` established the initial end-to-end prototype:

- Live packet capture
- TCP and UDP parsing
- Protocol-aware detection flow
- Windows Firewall response integration
- Terminal dashboard
- PCAP export
- PDF reporting

## Versioning Note

The documentation set in this repository is aligned to the code currently present in the workspace rather than to an external packaged release process.
