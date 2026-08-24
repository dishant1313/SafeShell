# Blast Radius Score (BRS)

BRS is a numerical score [0-1000+] representing the destructiveness of a command.

## Scoring Factors
- Target breadth (wildcards, recursive flags).
- Target sensitivity (system paths like `/etc`, `/dev`).
- Data destructiveness (overwrite vs delete).
- Reversibility (can we invert this?).

## Use
Policy engine uses BRS to auto-approve, block, or require human intervention.
