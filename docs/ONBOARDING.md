# Onboarding

This guide explains how to set up, build, and run PacketHorn for the first time.

## Requirements

### Operating System

- Windows 10 or Windows 11

### SDK

- .NET SDK 10.x

### Capture Driver

- Npcap

Download:

- <https://npcap.com/>

Recommended installer options:

- WinPcap compatibility mode
- Support loopback traffic

### Privileges

- Administrator privileges are strongly recommended for packet capture and required for reliable firewall response operations

## Get the Source

```powershell
git clone https://github.com/mandal-suman/PacketHorn.git
cd PacketHorn
```

## Restore Dependencies

```powershell
dotnet restore
```

## Build

```powershell
dotnet build PacketHorn.sln -m:1
```
You can also run the repository helper:

```powershell
.\build.ps1
```

## Run

```powershell
dotnet run --project src/PacketHorn.CLI/PacketHorn.CLI.csproj
```

Launch the terminal as Administrator before running the application.

## First Run Experience

On startup, PacketHorn:

1. Resolves the repository root
2. Loads `config/packethorn.conf`
3. Prints an environment validation report
4. Enumerates available capture interfaces
5. Opens the terminal dashboard

When you start a capture session from the dashboard:

1. The selected interface is opened
2. Rules are loaded from the `rules` directory
3. A PCAP writer is created
4. Detection and response services are initialized
5. Live capture begins

## Runtime Modes

| Mode | Description |
|---|---|
| `AlertOnly` | Generates detections without blocking |
| `InteractiveBlock` | Prompts the operator before a block action |
| `AutoBlock` | Applies allowed block actions automatically |

Rule actions still matter. `AutoBlock` or `InteractiveBlock` only block when the rule requests blocking.

## Key Files and Directories

Configuration:

- `config/packethorn.conf`

Rules:

- `rules/signatures.yaml`
- `rules/behaviors.yaml`

Default outputs:

- `outputs/pcap`
- `outputs/reports`
- `logs`

Important note:

- The `logs` directory is configured and created, but the current dashboard flow does not actively persist runtime dashboard events into log files.

## Recommended First Session

1. Start in `AlertOnly`
2. Select the intended interface
3. Confirm packets are appearing in the dashboard
4. Observe detections before enabling blocking modes
5. Generate a PDF report after the session
6. Inspect the PCAP file in Wireshark if needed

## Common Issues

### No Interfaces Are Listed

Possible causes:

- Npcap is not installed
- The terminal is not running with sufficient privileges
- The capture driver is unavailable

Recommended actions:

- Reinstall Npcap
- Relaunch the terminal as Administrator
- Confirm a usable network interface is present

### Firewall Blocking Does Not Work

Possible causes:

- The terminal is not running as Administrator
- The selected runtime mode does not permit blocking
- The matched rule is alert-only

Recommended actions:

- Relaunch as Administrator
- Confirm the mode is `InteractiveBlock` or `AutoBlock`
- Check the rule action in the YAML file

### Reports or Captures Are Missing

Possible causes:

- No session was started
- No report was generated explicitly
- Output paths were changed in configuration

Recommended actions:

- Start a session before expecting a PCAP output
- Use the dashboard `Report` action to generate a PDF
- Review the configured directories in `config/packethorn.conf`
