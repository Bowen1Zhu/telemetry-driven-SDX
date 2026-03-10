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

.PHONY: build run run-fixed-slow run-fixed-fast clean

all: build

build:
	mkdir -p $(BUILD_P4_DIR)
	$(P4_COMPILER) $(P4_COMPILE_ARGS) $(P4_PROGRAM)

run:
	$(MAKE) clean
	$(MAKE) build
	sudo $(PYTHON_INTERPRETER) scripts/run_sdx.py --mode closed-loop

run-fixed-slow:
	$(MAKE) clean
	$(MAKE) build
	sudo $(PYTHON_INTERPRETER) scripts/run_sdx.py --mode fixed --fixed-path slow

run-fixed-fast:
	$(MAKE) clean
	$(MAKE) build
	sudo $(PYTHON_INTERPRETER) scripts/run_sdx.py --mode fixed --fixed-path fast

clean:
	sudo mn -c >/dev/null 2>&1 || true
	sudo rm -rf $(TEMP_DIR) $(BUILD_DIR)
