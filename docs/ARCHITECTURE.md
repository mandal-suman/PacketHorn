# Architecture

This document describes the architecture currently implemented in PacketHorn.

## System Overview

PacketHorn is organized as a layered, single-process pipeline:

```text
Capture
  -> Queue
  -> Parse and Normalize
  -> Signature Evaluation
  -> Behavior Evaluation
  -> Decision
  -> Response
  -> Analyst Outputs
```

The application is composed in the terminal dashboard layer and runs locally on Windows.

## Solution Structure

### `PacketHorn.CLI`

Responsibilities:

- Application entry point
- Project root and configuration loading
- Environment validation
- Terminal dashboard composition
- Wiring capture, detection, response, and output components together

Primary files:

- `src/PacketHorn.CLI/Program.cs`
- `src/PacketHorn.CLI/Tui/TerminalDashboardApp.cs`

### `PacketHorn.Capture`

Responsibilities:

- Interface enumeration through SharpPcap
- Capture device selection
- Live packet capture from the selected interface
- Optional BPF capture filter application

Primary files:

- `src/PacketHorn.Capture/Common/InterfaceEnumerator.cs`
- `src/PacketHorn.Capture/Windows/WindowsCaptureEngine.cs`

### `PacketHorn.Core`

Responsibilities:

- Shared models and enums
- Configuration types and config parsing
- Pipeline abstractions and queue management
- Shared interfaces across projects

Primary files:

- `src/PacketHorn.Core/Configuration/*`
- `src/PacketHorn.Core/Models/*`
- `src/PacketHorn.Core/Interfaces/*`
- `src/PacketHorn.Core/Pipeline/*`

### `PacketHorn.Processing`

Responsibilities:

- Ethernet frame inspection
- IPv4 header parsing
- TCP and UDP transport parsing
- Payload extraction
- Direction inference
- Construction of normalized `StructuredPacket` instances

Primary files:

- `src/PacketHorn.Processing/Builders/StructuredPacketBuilder.cs`
- `src/PacketHorn.Processing/Parsers/*`

Current implementation notes:

- IPv4 is parsed explicitly
- TCP and UDP ports and flags are normalized
- ICMP is classified at the IP protocol level but not deeply decoded by a dedicated parser

### `PacketHorn.Detection`

Responsibilities:

- Loading signature and behavior rules from YAML
- Signature matching against packet fields and payloads
- Stateful behavior analysis over sliding windows
- Threshold tracking and rule result generation

Primary files:

- `src/PacketHorn.Detection/Rules/RuleLoader.cs`
- `src/PacketHorn.Detection/Evaluators/SignatureEvaluator.cs`
- `src/PacketHorn.Detection/Evaluators/BehaviorEvaluator.cs`
- `src/PacketHorn.Detection/Engine/RuleEngine.cs`

Current behavior-state features:

- Per-rule state keys using `group_by`
- Unique destination port tracking
- Unique source and destination IP tracking
- Session tracking
- DNS FQDN extraction for UDP port 53 traffic
- Failed connection heuristics based on SYN-only traffic
- Error heuristics based on TCP resets and ICMP traffic
- Static and adaptive baseline thresholds
- Linear and exponential decay support

### `PacketHorn.Response`

Responsibilities:

- Translating rule outcomes into runtime decisions
- Respecting rule-level actions in the configured runtime mode
- Executing temporary Windows Firewall blocks
- Automatically removing temporary blocks after the configured TTL

Primary files:

- `src/PacketHorn.Response/Decision/DecisionEngine.cs`
- `src/PacketHorn.Response/Engine/WindowsResponseEngine.cs`
- `src/PacketHorn.Response/Firewall/WindowsFirewallController.cs`

Current implementation notes:

- Responses are executed through `netsh advfirewall`
- Firewall rules are created for both inbound and outbound directions
- Temporary unblock is scheduled asynchronously after the configured duration

### `PacketHorn.Output`

Responsibilities:

- Writing PCAP files
- Generating PDF session reports
- Resolving artifact paths
- Providing a runtime file logger component

Primary files:

- `src/PacketHorn.Output/PCAP/PcapWriter.cs`
- `src/PacketHorn.Output/Reports/PdfReportGenerator.cs`
- `src/PacketHorn.Output/Logging/RuntimeFileLogger.cs`

Important note:

- The runtime file logger component exists, but the current dashboard flow does not actively write session events into that logger.

### `PacketHorn.Platform`

Responsibilities:

- Windows platform detection
- Administrator privilege checks
- Npcap validation hints

Primary files:

- `src/PacketHorn.Platform/EnvironmentValidator.cs`
- `src/PacketHorn.Platform/PlatformDetector.cs`
- `src/PacketHorn.Platform/PrivilegeChecker.cs`

## Runtime Flow

The active runtime flow is:

1. `Program` resolves the repository root and loads `config/packethorn.conf`
2. `EnvironmentValidator` checks Windows support, administrator access, and Npcap presence
3. `TerminalDashboardApp` enumerates interfaces and initializes the dashboard
4. Starting a session creates rule evaluators, response services, output writers, and the capture engine
5. `WindowsCaptureEngine` emits `RawPacket` instances into `PacketPipeline`
6. `PacketPipeline` normalizes each packet into `StructuredPacket`
7. `RuleEngine` runs signature and behavior evaluators
8. `DecisionEngine` maps detections to runtime actions according to mode and rule action
9. `WindowsResponseEngine` performs alerting or firewall operations
10. The dashboard updates session views, PCAP output continues, and reports can be generated on demand

## Core Design Choices

### Local-First Execution

All capture, detection, and response behavior runs locally with no external service dependency.

### Readable Rule Definitions

Rules are kept in YAML to make them easier to review and maintain than hardcoded detection logic.

### Clear Separation of Concerns

Each project has a focused responsibility, which makes the codebase easier to navigate and evolve.

### Operator-Controlled Response

Runtime mode selection provides a progression from observation to interactive blocking to automatic blocking.

## Limitations

The documentation aligns with the code currently present in the repository:

- Windows is the only supported platform
- Packet normalization is centered on IPv4 traffic
- The application is an interactive terminal program, not a background service
- Distributed collection, centralized management, and kernel-assisted capture are not implemented
- Event logging to files is not fully wired into the dashboard flow
- No automated test suite is currently included in the repository
