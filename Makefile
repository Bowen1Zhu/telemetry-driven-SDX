BUILD_DIR = build
BUILD_P4_DIR = $(BUILD_DIR)/p4
TEMP_DIR = temp

P4_COMPILER = p4c-bm2-ss
PYTHON_INTERPRETER = /opt/p4/p4dev-python-venv/bin/python3

P4_PROGRAM = p4/sdx_ixp.p4
P4_PROGRAM_NAME = sdx_ixp
P4_COMPILE_ARGS += --p4v 16
P4_COMPILE_ARGS += --p4runtime-files $(BUILD_P4_DIR)/$(P4_PROGRAM_NAME).p4info.txtpb
P4_COMPILE_ARGS += -o $(BUILD_P4_DIR)/$(P4_PROGRAM_NAME).json

.PHONY: build run run-mode2 run-mode3 run-fixed-slow run-fixed-fast run-generalized run-generalized-validate run-generalized-closed-loop run-generalized-closed-loop-mode2 run-generalized-closed-loop-mode3 run-generalized-queue-mode1 run-generalized-queue-mode2 run-generalized-queue-mode3 run-bgp-generalized run-bgp-generalized-mode2 run-bgp-generalized-mode3 run-bgp-reachability-validate run-bgp-diagnose run-bgp-loop-generalized run-bgp-loop-generalized-mode2 run-bgp-loop-generalized-mode3 run-bgp-loop-reachability-validate run-bgp-loop-diagnose run-bgp-superloop-generalized run-bgp-superloop-generalized-mode2 run-bgp-superloop-generalized-mode3 run-bgp-superloop-reachability-validate run-bgp-superloop-diagnose run-bgp-superloop-segmented-local run-bgp-superloop-segmented-local-mode2 run-bgp-superloop-segmented-local-mode3 run-bgp-superloop-segmented-reachability-validate clean

all: build

build:
	mkdir -p $(BUILD_P4_DIR)
	$(P4_COMPILER) $(P4_COMPILE_ARGS) $(P4_PROGRAM)

run:
	$(MAKE) clean
	$(MAKE) build
	sudo $(PYTHON_INTERPRETER) scripts/run_sdx.py --mode closed-loop --config config/run_config.json

run-mode2:
	$(MAKE) clean
	$(MAKE) build
	sudo $(PYTHON_INTERPRETER) scripts/run_sdx.py --mode closed-loop --config config/run_config_mode2.json --telemetry-mode mode2

run-mode3:
	$(MAKE) clean
	$(MAKE) build
	sudo $(PYTHON_INTERPRETER) scripts/run_sdx.py --mode closed-loop --config config/run_config_mode3.json --telemetry-mode mode3

run-fixed-slow:
	$(MAKE) clean
	$(MAKE) build
	sudo $(PYTHON_INTERPRETER) scripts/run_sdx.py --mode fixed --fixed-path slow --config config/run_config.json

run-fixed-fast:
	$(MAKE) clean
	$(MAKE) build
	sudo $(PYTHON_INTERPRETER) scripts/run_sdx.py --mode fixed --fixed-path fast --config config/run_config.json

run-generalized:
	$(MAKE) clean
	$(MAKE) build
	sudo $(PYTHON_INTERPRETER) scripts/run_sdx.py --mode closed-loop --config config/run_config_generalized.json

run-generalized-validate:
	$(MAKE) clean
	$(MAKE) build
	sudo $(PYTHON_INTERPRETER) scripts/run_generalized_validation.py --config config/run_config_generalized.json

run-generalized-closed-loop:
	$(MAKE) clean
	$(MAKE) build
	sudo $(PYTHON_INTERPRETER) scripts/run_generalized_closed_loop.py --config config/run_config_generalized.json

run-generalized-closed-loop-mode2:
	$(MAKE) clean
	$(MAKE) build
	sudo $(PYTHON_INTERPRETER) scripts/run_generalized_closed_loop.py --config config/run_config_generalized_mode2.json --telemetry-mode mode2

run-generalized-closed-loop-mode3:
	$(MAKE) clean
	$(MAKE) build
	sudo $(PYTHON_INTERPRETER) scripts/run_generalized_closed_loop.py --config config/run_config_generalized_mode3.json --telemetry-mode mode3


run-generalized-queue-mode1:
	$(MAKE) clean
	$(MAKE) build
	sudo $(PYTHON_INTERPRETER) scripts/run_generalized_closed_loop.py --config config/run_config_generalized_queue_mode1.json --telemetry-mode mode1

run-generalized-queue-mode2:
	$(MAKE) clean
	$(MAKE) build
	sudo $(PYTHON_INTERPRETER) scripts/run_generalized_closed_loop.py --config config/run_config_generalized_queue_mode2.json --telemetry-mode mode2

run-generalized-queue-mode3:
	$(MAKE) clean
	$(MAKE) build
	sudo $(PYTHON_INTERPRETER) scripts/run_generalized_closed_loop.py --config config/run_config_generalized_queue_mode3.json --telemetry-mode mode3


run-bgp-generalized:
	$(MAKE) clean
	$(MAKE) build
	sudo $(PYTHON_INTERPRETER) scripts/run_bgp_generalized_closed_loop.py --config config/run_config_bgp_generalized.json --telemetry-mode mode1

run-bgp-generalized-mode2:
	$(MAKE) clean
	$(MAKE) build
	sudo $(PYTHON_INTERPRETER) scripts/run_bgp_generalized_closed_loop.py --config config/run_config_bgp_generalized_mode2.json --telemetry-mode mode2

run-bgp-generalized-mode3:
	$(MAKE) clean
	$(MAKE) build
	sudo $(PYTHON_INTERPRETER) scripts/run_bgp_generalized_closed_loop.py --config config/run_config_bgp_generalized_mode3.json --telemetry-mode mode3

run-bgp-reachability-validate:
	$(MAKE) clean
	$(MAKE) build
	sudo $(PYTHON_INTERPRETER) scripts/run_bgp_reachability_validation.py --config config/run_config_bgp_generalized.json


run-bgp-diagnose:
	$(MAKE) clean
	$(MAKE) build
	sudo $(PYTHON_INTERPRETER) scripts/run_bgp_diagnose.py --config config/run_config_bgp_generalized.json


run-bgp-loop-generalized:
	$(MAKE) clean
	$(MAKE) build
	sudo $(PYTHON_INTERPRETER) scripts/run_bgp_generalized_closed_loop.py --config config/run_config_bgp_loop.json --telemetry-mode mode1

run-bgp-loop-generalized-mode2:
	$(MAKE) clean
	$(MAKE) build
	sudo $(PYTHON_INTERPRETER) scripts/run_bgp_generalized_closed_loop.py --config config/run_config_bgp_loop_mode2.json --telemetry-mode mode2

run-bgp-loop-generalized-mode3:
	$(MAKE) clean
	$(MAKE) build
	sudo $(PYTHON_INTERPRETER) scripts/run_bgp_generalized_closed_loop.py --config config/run_config_bgp_loop_mode3.json --telemetry-mode mode3

run-bgp-loop-reachability-validate:
	$(MAKE) clean
	$(MAKE) build
	sudo $(PYTHON_INTERPRETER) scripts/run_bgp_reachability_validation.py --config config/run_config_bgp_loop.json

run-bgp-loop-diagnose:
	$(MAKE) clean
	$(MAKE) build
	sudo $(PYTHON_INTERPRETER) scripts/run_bgp_diagnose.py --config config/run_config_bgp_loop.json


run-bgp-superloop-generalized:
	$(MAKE) clean
	$(MAKE) build
	sudo $(PYTHON_INTERPRETER) scripts/run_bgp_generalized_closed_loop.py --config config/run_config_bgp_superloop.json --telemetry-mode mode1

run-bgp-superloop-generalized-mode2:
	$(MAKE) clean
	$(MAKE) build
	sudo $(PYTHON_INTERPRETER) scripts/run_bgp_generalized_closed_loop.py --config config/run_config_bgp_superloop_mode2.json --telemetry-mode mode2

run-bgp-superloop-generalized-mode3:
	$(MAKE) clean
	$(MAKE) build
	sudo $(PYTHON_INTERPRETER) scripts/run_bgp_generalized_closed_loop.py --config config/run_config_bgp_superloop_mode3.json --telemetry-mode mode3

run-bgp-superloop-reachability-validate:
	$(MAKE) clean
	$(MAKE) build
	sudo $(PYTHON_INTERPRETER) scripts/run_bgp_reachability_validation.py --config config/run_config_bgp_superloop.json

run-bgp-superloop-diagnose:
	$(MAKE) clean
	$(MAKE) build
	sudo $(PYTHON_INTERPRETER) scripts/run_bgp_diagnose.py --config config/run_config_bgp_superloop.json


run-bgp-superloop-segmented-local:
	$(MAKE) clean
	$(MAKE) build
	sudo $(PYTHON_INTERPRETER) scripts/run_bgp_superloop_segmented_local.py --config config/run_config_bgp_superloop_segmented.json --telemetry-mode mode1

run-bgp-superloop-segmented-local-mode2:
	$(MAKE) clean
	$(MAKE) build
	sudo $(PYTHON_INTERPRETER) scripts/run_bgp_superloop_segmented_local.py --config config/run_config_bgp_superloop_segmented_mode2.json --telemetry-mode mode2

run-bgp-superloop-segmented-local-mode3:
	$(MAKE) clean
	$(MAKE) build
	sudo $(PYTHON_INTERPRETER) scripts/run_bgp_superloop_segmented_local.py --config config/run_config_bgp_superloop_segmented_mode3.json --telemetry-mode mode3

run-bgp-superloop-segmented-reachability-validate:
	$(MAKE) clean
	$(MAKE) build
	sudo $(PYTHON_INTERPRETER) scripts/run_bgp_reachability_validation.py --config config/run_config_bgp_superloop_segmented.json


clean:
	sudo mn -c >/dev/null 2>&1 || true
	sudo rm -rf $(TEMP_DIR) $(BUILD_DIR)
