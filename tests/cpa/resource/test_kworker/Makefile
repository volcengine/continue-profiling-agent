# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 ByteDance Inc.

# Makefile for cpu_hogger kernel module

obj-m += cpu_hogger.o

# Default to the running kernel's build directory.
# KDIR can be overridden from the command line if needed.
KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

# Target to copy the .ko file to a common output directory if needed by tests
# This assumes an 'output' directory exists at ../output relative to this Makefile's location
# Adjust the path as necessary for your project structure.
# This step is optional and depends on how your test framework expects to find the .ko file.
# For example, if conftest.py's RESOURCE_DIR points to tests/resource, then output/ would be tests/resource/output/
# If your compile_workloads fixture already handles placing .ko files, this might be redundant.
copy_to_output:
	@if [ -f cpu_hogger.ko ]; then \
	    mkdir -p $(PWD)/../output; \
	    cp cpu_hogger.ko $(PWD)/../output/cpu_hogger.ko; \
	    echo "cpu_hogger.ko copied to $(PWD)/../output/"; \
	else \
	    echo "cpu_hogger.ko not found, build first."; \
	fi

.PHONY: all clean copy_to_output

EXTRA_CFLAGS+=-O0
