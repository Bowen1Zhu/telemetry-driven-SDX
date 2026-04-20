# Telemetry-Driven SDX

## 3-IXP / 3-path topology

Build:
```bash
make build
```

Run 3-IXP closed loop (Mode 1):
```bash
make run-3ixp
```

Run 3-IXP closed loop (Mode 2):
```bash
make run-3ixp-mode2
```

Run 3-IXP closed loop (Mode 3):
```bash
make run-3ixp-mode3
```

Validate fixed assignments across the three paths:
```bash
make run-3ixp-validate
```

## For this topology:

- Topology name: `sdx_3ixp`
- IXP1 and IXP3 perform steering for the four traffic classes.
- IXP2 is the middle exchange fabric that carries the three path chains.
- The three end-to-end paths are: `slow`, `medium`, and `fast`.
