# Operations

This document provides runtime guidance for operating PacketHorn safely.

## Intended Operating Model

PacketHorn is currently an operator-driven terminal application. It is best suited for:

- Labs
- Isolated networks
- Evaluation environments
- Controlled internal testing

It should be treated as an experimental defensive tool, not as a fully hardened enterprise platform.

## Runtime Modes

| Mode | Description | Operational Impact |
|---|---|---|
| `AlertOnly` | Detect only | Safest starting point |
| `InteractiveBlock` | Ask before blocking | Useful for supervised response testing |
| `AutoBlock` | Block automatically when rules request it | Highest operational risk |

## Recommended Rollout Sequence

1. Start with `AlertOnly`
2. Validate packet visibility and rule quality
3. Tune noisy rules
4. Test `InteractiveBlock`
5. Move to `AutoBlock` only after repeated validation

## Response Behavior

PacketHorn can create temporary Windows Firewall rules through `netsh`.

Current characteristics:

- Blocking is source-IP based
- Both inbound and outbound block rules are created
- Temporary unblock is scheduled automatically after the configured duration
- Blocking only occurs when both the runtime mode and the matched rule permit it

## Safe Operation Practices

- Begin with alerting only
- Validate high-severity rules in a non-production environment
- Review rules that use broad internal or external IP groups
- Protect infrastructure addresses such as gateways, domain controllers, and DNS services from accidental blocking
- Keep block durations short until behavior is well understood

## Performance Considerations

PacketHorn processes traffic in a single application process with an in-memory queue and a background worker.

Operational implications:

- High traffic volume can increase queue pressure
- Complex or numerous rules can increase evaluation latency
- Stateful behavior rules require memory for active rule state
- PCAP writing adds additional I/O during capture sessions

## Artifact Handling

During operation, PacketHorn may create:

- PCAP files in `outputs/pcap`
- PDF reports in `outputs/reports`

The codebase also includes a runtime file logger component, but the current dashboard path does not actively persist event logs to files.

## Incident Review Workflow

Recommended review flow:

1. Observe a detection in the dashboard
2. Review the rule name, severity, and confidence
3. Confirm the current runtime mode
4. Inspect the related PCAP file if packet-level review is needed
5. Generate a PDF report for session-level summary
6. Decide whether the rule needs tuning or escalation

## Operational Risks

### False Positives

Behavior rules are heuristic and can be environment-sensitive.

### Blocking the Wrong Host

Firewall response is IP-based and should be treated carefully in shared or dynamic environments.

### Misreading Capability

PacketHorn currently does not provide:

- Distributed coordination
- Central management
- Deep encrypted traffic analysis
- A production-grade persistent logging pipeline

## Environment Validation

The startup validator checks:

- Platform support
- Administrator privileges
- Likely Npcap presence

Warnings do not always stop execution, so operators should review the startup validation report before beginning capture.
