# CS6204 Project: Telemetry-Driven SDX

## Build
```bash
make build
```

## Single-pair runs
```bash
make run
make run-mode2
make run-mode3
make run-fixed-slow
make run-fixed-fast
```

## Generalized runs
```bash
make run-generalized
make run-generalized-validate
make run-generalized-closed-loop
make run-generalized-closed-loop-mode2
make run-generalized-closed-loop-mode3
```

## Queue-aware generalized runs
```bash
make run-generalized-queue-mode1
make run-generalized-queue-mode2
make run-generalized-queue-mode3
```

## Output
Each run writes `latest_run.csv` and `latest_summary.json` under the relevant `results/` subdirectory.


## Using BGP

```bash
make run-bgp-diagnose
```

