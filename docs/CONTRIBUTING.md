# Contributing

This document describes the recommended contribution workflow for PacketHorn.

## Development Expectations

Contributions should preserve three priorities:

- Technical correctness
- Detection clarity
- Operational safety

Changes that affect capture, detection, or firewall behavior should be reviewed especially carefully.

## Repository Structure

Before making changes, review the project boundaries:

- `PacketHorn.CLI`: application wiring and dashboard behavior
- `PacketHorn.Capture`: interface enumeration and live capture
- `PacketHorn.Core`: shared contracts, config, models, and pipeline utilities
- `PacketHorn.Processing`: normalization and parsing
- `PacketHorn.Detection`: rule loading and evaluators
- `PacketHorn.Response`: decisioning and blocking behavior
- `PacketHorn.Output`: PCAP and PDF generation
- `PacketHorn.Platform`: runtime environment validation

## Recommended Workflow

1. Create a focused branch for the change
2. Keep edits scoped to the smallest affected area
3. Validate that documentation matches the code after the change
4. Build the affected projects before opening a pull request
5. Include any operational caveats when changing detection or response logic

## Branching

Suggested branch naming:

- `feature/<name>`
- `fix/<name>`
- `docs/<name>`
- `refactor/<name>`

If your team already follows a different convention, use the project standard for that repository workflow.

## Commit Messages

Use clear, conventional commit messages where possible.

Examples:

```text
feat(detection): add adaptive threshold handling
fix(processing): correct UDP header offset parsing
docs(readme): align feature list with current implementation
refactor(response): simplify block decision flow
```

## Code Standards

### General

- Keep responsibilities well separated
- Prefer small, readable changes over broad rewrites
- Preserve operator safety when changing response behavior
- Avoid overstating capabilities in code comments or documentation

### Detection Changes

When changing detection logic:

- Document assumptions clearly
- Prefer explainable heuristics over opaque behavior
- Consider false-positive impact
- Keep rule semantics aligned with runtime implementation

### Response Changes

When changing firewall or response logic:

- Favor reversible behavior
- Preserve safe defaults
- Confirm that operator-facing wording remains accurate

## Documentation Standards

Documentation updates are required when changes affect:

- Features
- Architecture
- Runtime behavior
- Configuration
- Rule schema
- Operational guidance

The repository should not contain README or docs content that contradicts the codebase.

## Validation

At minimum, contributors should:

- Build the affected project or solution
- Review the relevant docs for accuracy
- Check whether example commands, paths, and filenames still match the repository

If a full solution build is blocked by the environment, document what was validated and what remained blocked.

## Security Considerations

Do not:

- Hardcode secrets or credentials
- Merge unreviewed firewall behavior
- Introduce documentation that implies unsupported security guarantees

Be explicit about risk when a change affects traffic blocking, operator approval, or environmental assumptions.
