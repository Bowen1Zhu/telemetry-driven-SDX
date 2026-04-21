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



## Larger loop with BGP and middle transit fabric

A larger topology named `sdx_bgp_loop`. I keep the same end-host sessions as the BGP-aware model, but expands the middle of the network to three IXPs:

- IXP1: left steering IXP
- IXP2: shared middle exchange / loop-capable transit fabric
- IXP3: right steering IXP

Two end-to-end path classes remain visible to the SDX controller:

- `slow = slow12 -> slow23`
- `fast = fast12 -> fast23`

BGP reachability validation:
```bash
make run-bgp-loop-reachability-validate
```

Closed-loop BGP-aware runs:
```bash
make run-bgp-loop-generalized
make run-bgp-loop-generalized-mode2
make run-bgp-loop-generalized-mode3
```

Diagnose:
```bash
make run-bgp-loop-diagnose
```


## Largest superloop with BGP

I tried a even larger one `sdx_bgp_superloop`, with:
- 4 edge routers (AS100/200/500/600)
- 6 transit routers (slow12/23/34 and fast12/23/34)
- 4 IXPs (outer P4 IXPs at 1 and 4; shared fabrics at 2 and 3)

Commands:
```bash
make run-bgp-superloop-reachability-validate
make run-bgp-superloop-generalized
make run-bgp-superloop-generalized-mode2
make run-bgp-superloop-generalized-mode3
```

# Segmented local steering

We make all 4 IXPs programmable and can make local segment choices (not relying on a single end-to-end fast/slow decision).

Topology name:
- `sdx_bgp_superloop_segmented`

Commands:
- `make run-bgp-superloop-segmented-reachability-validate`
- `make run-bgp-superloop-segmented-local`
- `make run-bgp-superloop-segmented-local-mode2`
- `make run-bgp-superloop-segmented-local-mode3`

Notes:
- `ixp1` chooses segment 12 locally
- `ixp2` chooses segment 23 locally (forward) and segment 12 locally (reverse)
- `ixp3` chooses segment 34 locally (forward) and segment 23 locally (reverse)
- `ixp4` chooses segment 34 locally (reverse)
- outer edge-exit choices at `ixp1` and `ixp4` remain static based on destination edge AS

(BGP still determines which sessions are globally legal for `slow`, `fast`, or both.
Sessions with only one legal class are forced at every stage.
Dual-legal sessions can become mixed, e.g. `fast-slow-fast`.)
