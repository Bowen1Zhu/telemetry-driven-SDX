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

## To run different telemetry modes:

Mode 1 (active probes):
```bash
make run
```

Mode 2 (sampled telemetry):
```bash
make run-mode2
```

Mode 3 (INT):
```bash
make run-mode3
```

## To run directly and save results separately
Mode 1:
```bash
sudo /opt/p4/p4dev-python-venv/bin/python3 scripts/run_sdx.py --mode closed-loop --config config/run_config.json --results-dir results/mode1
```

Mode 2:
```bash
sudo /opt/p4/p4dev-python-venv/bin/python3 scripts/run_sdx.py --mode closed-loop --config config/run_config_mode2.json --telemetry-mode mode2 --results-dir results/mode2
```

Mode 3:
```bash
sudo /opt/p4/p4dev-python-venv/bin/python3 scripts/run_sdx.py --mode closed-loop --config config/run_config_mode3.json --telemetry-mode mode3 --results-dir results/mode3
```

## Output files
- `results/latest_run.csv`
- `results/latest_summary.json`

