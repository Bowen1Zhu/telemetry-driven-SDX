# CS6204 Project: Telemetry-Driven SDX

## To run:

```bash
make build
make run
```

For fixed baselines:

```bash
make run-fixed-slow
make run-fixed-fast
```

To store separate result:

```bash
sudo /opt/p4/p4dev-python-venv/bin/python3 scripts/run_sdx.py --mode fixed --fixed-path slow --results-dir results/fixed_slow

sudo /opt/p4/p4dev-python-venv/bin/python3 scripts/run_sdx.py --mode fixed --fixed-path fast --results-dir results/fixed_fast

sudo /opt/p4/p4dev-python-venv/bin/python3 scripts/run_sdx.py --mode closed-loop --results-dir results/closed_loop
```



## This is a 4-IXP ring experiment

```bash
make run-ring4
```

This topology forms a 4-IXP cycle: IXP1 ↔ IXP2 ↔ IXP3 ↔ IXP4 ↔ IXP1.
Traffic from AS100 at IXP1 to AS300 at IXP3 can go either clockwise via IXP2 or counter-clockwise via IXP4.
The default config starts on `via_ixp2`, injects extra delay on that direction at 20s, and removes it at 40s.

Fixed baselines:

```bash
make run-ring4-fixed-via-ixp2
make run-ring4-fixed-via-ixp4
```
