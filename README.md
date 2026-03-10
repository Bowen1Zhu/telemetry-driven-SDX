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

