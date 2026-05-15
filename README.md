<div align="center">

![PacketHorn Banner](docs/assets/banner.svg)

# PacketHorn

Terminal-native network detection and response for Windows, built with .NET 10.

PacketHorn captures live traffic through Npcap, normalizes packets into internal models, evaluates them with YAML-based signature and behavior rules, and can apply temporary Windows Firewall blocks based on rule-driven decisions.

<p>
  <img src="https://img.shields.io/badge/platform-Windows%2010%2F11-0078d4?style=flat-square&logo=windows&logoColor=white" alt="Platform" />
  <img src="https://img.shields.io/badge/.NET-10.0-512bd4?style=flat-square&logo=dotnet&logoColor=white" alt=".NET" />
  <img src="https://img.shields.io/badge/language-C%23-239120?style=flat-square&logo=csharp&logoColor=white" alt="Language" />
  <img src="https://img.shields.io/badge/capture-Npcap-1a6fc4?style=flat-square" alt="Npcap" />
  <img src="https://img.shields.io/badge/UI-Terminal.Gui-0a0f1e?style=flat-square" alt="Terminal.Gui" />
  <img src="https://img.shields.io/badge/reports-QuestPDF-e85d24?style=flat-square" alt="QuestPDF" />
  <img src="https://img.shields.io/badge/rules-YAML-2563eb?style=flat-square" alt="YAML Rules" />
  <img src="https://img.shields.io/badge/license-MIT-334155?style=flat-square" alt="MIT License" />
</p>

</div>

## Why PacketHorn

PacketHorn is a Windows-focused security engineering project designed to make packet capture, rule-driven detection, and controlled response visible in one operator-facing terminal workflow.

It is currently best understood as:

- a hands-on detection engineering platform
- a network systems learning project
- a local-first response prototype for controlled environments

## At a Glance

| Area | Current Implementation |
|---|---|
| Capture | Live Windows capture through Npcap and SharpPcap |
| Interface | Terminal dashboard built with Terminal.Gui |
| Rules | YAML-based signature and behavior rule sets |
| Detection | Hybrid signature and stateful behavior evaluation |
| Response | Rule-driven alerting and temporary Windows Firewall blocking |
| Exports | PCAP capture files and PDF session reports |
| Platform | Windows only |

## Feature Snapshot

### Capture

- Live interface capture on Windows
- Optional BPF filter support
- Promiscuous mode support
- Timestamped PCAP export

### Detection

- YAML-driven signature and behavior rules
- Direction inference during normalization
- Named IP groups such as `@internal`, `@external`, and `@workstations`
- TCP flag matching, payload matching, and threshold grouping
- Stateful behavior metrics including unique ports, unique IPs, sessions, DNS FQDN extraction, failed-connection heuristics, and decayed counters
- MITRE ATT&CK metadata and confidence scoring

### Response

- `AlertOnly`, `InteractiveBlock`, and `AutoBlock` modes
- Rule-level action handling with `ALERT`, `BLOCK`, `ALERT_AND_BLOCK`, and `NONE`
- Temporary Windows Firewall blocking through `netsh`

### Analyst Outputs

- Live packet and detection views in the dashboard
- PCAP capture output under `outputs/pcap`
- PDF session reports under `outputs/reports`

## Quick Start

### Requirements

- Windows 10 or Windows 11
- .NET SDK 10.x
- Npcap installed locally
- Administrator privileges for reliable capture and firewall operations

Recommended Npcap installer options:

- WinPcap compatibility mode
- Loopback traffic support

### Build

```powershell
dotnet restore
dotnet build PacketHorn.slnx
```

### Run

```powershell
dotnet run --project src/PacketHorn.CLI/PacketHorn.CLI.csproj
```

Run the terminal as Administrator before starting PacketHorn.

## Runtime Flow

```text
Capture
  -> Queue
  -> Parse and Normalize
  -> Signature Evaluation
  -> Behavior Evaluation
  -> Decision
  -> Response
  -> Outputs
```

When a session is started from the dashboard, PacketHorn:

1. Loads `config/packethorn.conf`
2. Validates the environment and privilege state
3. Enumerates and selects a capture interface
4. Loads YAML rules from `rules`
5. Captures raw packets into a bounded in-memory queue
6. Builds normalized `StructuredPacket` instances
7. Evaluates signature and behavior rules
8. Converts rule results into runtime decisions
9. Optionally applies Windows Firewall blocks
10. Writes PCAP output and supports on-demand PDF report generation

## Project Layout

- `src/PacketHorn.CLI`: application entry point and terminal dashboard
- `src/PacketHorn.Capture`: interface enumeration and live packet capture
- `src/PacketHorn.Core`: shared models, enums, interfaces, configuration, and pipeline utilities
- `src/PacketHorn.Processing`: packet normalization and protocol parsing
- `src/PacketHorn.Detection`: rule loading and detection evaluators
- `src/PacketHorn.Response`: decisioning and Windows Firewall response execution
- `src/PacketHorn.Output`: PCAP writing, PDF reports, and output helpers
- `src/PacketHorn.Platform`: environment and privilege validation
- `rules`: YAML detection rules
- `config`: runtime configuration
- `outputs`: generated PCAP and report artifacts

## Configuration

Primary runtime configuration file:

- `config/packethorn.conf`

Current configuration surface includes:

- Capture interface selection
- Promiscuous mode
- Read timeout
- Optional BPF filter
- Queue size
- Detection mode
- Firewall block duration
- UI row limits
- Rules, PCAP, report, and log directories

## Current Boundaries

PacketHorn currently reflects the following implementation scope:

- Windows-only runtime support
- IPv4-focused normalization
- TCP and UDP transport parsing, with ICMP protocol classification at the IP layer
- Local, single-process execution
- In-memory behavioral state tracking
- No distributed coordination or central management console

Important implementation note:

- The repository includes a runtime file logger component, but the current terminal dashboard flow does not actively persist dashboard events into log files.

## Documentation

- [Onboarding](docs/ONBOARDING.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Rules](docs/RULES.md)
- [Operations](docs/OPERATIONS.md)
- [Contributing](docs/CONTRIBUTING.md)
- [Changelog](docs/CHANGELOG.md)
- [Release Notes](docs/RELEASE_NOTES.md)

## Security Notice

PacketHorn can apply live firewall blocks. Start with `AlertOnly`, validate rules in a controlled environment, and review false positives before enabling automated blocking.

## License

PacketHorn is released under the MIT License. See [LICENSE](LICENSE).
