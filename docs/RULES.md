# Rules

PacketHorn supports two rule families:

- Signature rules
- Behavior rules

Rules are stored in YAML and loaded from the `rules` directory at runtime.

## Rule Files

```text
rules/
  signatures.yaml
  behaviors.yaml
```

## Signature Rules

Signature rules evaluate individual normalized packets and optional threshold windows.

Supported concepts:

- Protocol matching
- Direction matching
- Named IP groups
- Exact ports, port lists, and port ranges
- TCP flag matching with mask support
- Optional payload matching
- Threshold counting over time windows
- Rule-level actions
- MITRE metadata

### Signature Example

```yaml
signatures:
  - name: SMB_LATERAL_PROBE
    version: 1
    protocol: TCP
    direction: LATERAL
    src_ip: "@internal"
    src_port: "*"
    dst_ip: "@internal"
    dst_port: "445"
    flag_match: "0x02"
    flag_mask: "0xFF"
    payload_pattern: ""
    count: 1
    window_sec: 0
    threshold_mode: PER_SRC
    mitre_tactic: Lateral Movement
    mitre_technique: T1021.002
    tags: smb,lateral
    severity: HIGH
    confidence: HIGH
    action: ALERT_AND_BLOCK
    description: >
      Example lateral SMB probe rule.
```

### Signature Fields

| Field | Description |
|---|---|
| `name` | Rule identifier |
| `version` | Rule version number |
| `protocol` | `TCP`, `UDP`, `ICMP`, or `ANY` |
| `direction` | `INBOUND`, `OUTBOUND`, `LATERAL`, `ANY`, or `BOTH` |
| `src_ip` | Source IP matcher, CIDR, wildcard, or named group |
| `src_port` | Source port matcher |
| `dst_ip` | Destination IP matcher, CIDR, wildcard, or named group |
| `dst_port` | Destination port matcher |
| `flag_match` | Expected TCP flag byte |
| `flag_mask` | Mask applied before comparison |
| `payload_pattern` | Regex or hex pattern |
| `payload_pattern_type` | Empty or `HEX` |
| `count` | Threshold count for repeated matches |
| `window_sec` | Threshold window length |
| `threshold_mode` | `PER_SRC`, `PER_DST`, `PER_PAIR`, or `GLOBAL` |
| `mitre_tactic` | MITRE tactic label |
| `mitre_technique` | MITRE technique identifier |
| `tags` | Free-form tag string |
| `severity` | `INFO`, `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL` |
| `confidence` | `LOW`, `MEDIUM`, or `HIGH` |
| `action` | `ALERT`, `BLOCK`, `ALERT_AND_BLOCK`, or `NONE` |
| `description` | Human-readable explanation |

## Behavior Rules

Behavior rules evaluate grouped traffic behavior over time.

Supported concepts:

- Protocol and direction filtering
- Source and destination IP matching
- Destination port matching
- Grouped rule state
- Sliding-window thresholds
- Linear and exponential decay
- Static and adaptive baselines
- Rule-level actions
- MITRE metadata

### Behavior Example

```yaml
behaviors:
  - name: PORT_SCAN_SLOW
    version: 1
    protocol: TCP
    direction: OUTBOUND
    src_ip: "*"
    dst_ip: "@external"
    dst_port: "1:1024"
    window_sec: 60
    threshold: 30
    metric: UNIQUE_PORTS
    group_by: SRC_IP
    decay: LINEAR
    baseline_mode: STATIC
    mitre_tactic: Reconnaissance
    mitre_technique: T1046
    tags: scan,recon
    severity: MEDIUM
    confidence: MEDIUM
    action: ALERT
    description: >
      Example slow port-scan rule.
```

### Behavior Fields

| Field | Description |
|---|---|
| `name` | Rule identifier |
| `version` | Rule version number |
| `protocol` | `TCP`, `UDP`, `ICMP`, or `ANY` |
| `direction` | `INBOUND`, `OUTBOUND`, `LATERAL`, `ANY`, or `BOTH` |
| `src_ip` | Source IP matcher |
| `dst_ip` | Destination IP matcher |
| `dst_port` | Destination port matcher |
| `window_sec` | Time window for state evaluation |
| `threshold` | Trigger threshold |
| `metric` | Metric to measure |
| `group_by` | Grouping key for state |
| `decay` | `NONE`, `LINEAR`, or `EXPONENTIAL` |
| `baseline_mode` | `STATIC` or `ADAPTIVE` |
| `mitre_tactic` | MITRE tactic label |
| `mitre_technique` | MITRE technique identifier |
| `tags` | Free-form tag string |
| `severity` | `INFO`, `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL` |
| `confidence` | `LOW`, `MEDIUM`, or `HIGH` |
| `action` | `ALERT`, `BLOCK`, `ALERT_AND_BLOCK`, or `NONE` |
| `description` | Human-readable explanation |

## Named IP Groups

The current code recognizes:

| Group | Runtime Meaning |
|---|---|
| `@internal` | RFC1918 IPv4 address |
| `@external` | Non-RFC1918, non-loopback IPv4 address |
| `@workstations` | Same runtime treatment as `@internal` in the current implementation |

## Supported Metrics

The current behavior evaluator supports these runtime metric families:

| Metric | Current Runtime Meaning |
|---|---|
| `PACKET_COUNT` | Packet count in the active window |
| `BYTE_COUNT` | Byte-weighted volume across the active window |
| `UNIQUE_PORTS` | Unique destination ports seen |
| `UNIQUE_SRC_IPS` | Unique source IPs seen |
| `UNIQUE_DST_IPS` | Unique destination IPs seen |
| `CONNECTION_COUNT` | Unique session keys seen |
| `CONNECTION_RATE` | Unique session count over the window |
| `PACKET_RATE` | Decayed packet count per second |
| `COUNT` | Decayed packet count |
| `UNIQUE_FQDNS` | Unique DNS names extracted from UDP port 53 traffic |
| `UNIQUE_SESSIONS` | Unique session keys seen |
| `FAILED_CONNECTIONS` | Heuristic SYN-without-ACK count |
| `ERROR_RATE` | Heuristic reset/ICMP error activity per second |

## Rule Actions

Supported rule actions:

| Action | Meaning |
|---|---|
| `ALERT` | Generate an alert only |
| `BLOCK` | Request blocking without separate alert semantics |
| `ALERT_AND_BLOCK` | Generate an alert and request blocking |
| `NONE` | Suppress runtime response generation |

Important runtime rule:

- Blocking only occurs when both the rule action requests it and the current dashboard mode allows it.

## Rule Design Guidance

- Prefer specific matchers over broad wildcards
- Start new rules in `AlertOnly`
- Validate environment-specific behavior thresholds before enabling automatic blocking
- Use tags and MITRE fields consistently
- Avoid assuming that `@workstations` is currently distinct from all internal hosts

## Current Limitations

- IP grouping is IPv4-focused
- Behavior metrics are heuristic rather than protocol-complete telemetry models
- DNS name extraction is limited to UDP port 53 payload parsing in the current evaluator
