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

.PHONY: build run run-mode2 run-mode3 run-fixed-slow run-fixed-fast run-generalized run-generalized-validate run-generalized-closed-loop run-generalized-closed-loop-mode2 run-generalized-closed-loop-mode3 clean

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

clean:
	sudo mn -c >/dev/null 2>&1 || true
	sudo rm -rf $(TEMP_DIR) $(BUILD_DIR)
