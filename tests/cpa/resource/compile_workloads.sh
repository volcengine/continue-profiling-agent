# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 ByteDance

set +e

# Logging functions
log_info() {
    echo "[INFO] $1"
}

log_warn() {
    echo "[WARN] $1"
}

log_error() {
    echo "[ERROR] $1" >&2
}

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
RESOURCE_DIR="$SCRIPT_DIR" # Resource dir is where the script is
OUTPUT_DIR="$RESOURCE_DIR/output"

# Ensure output directory exists
mkdir -p "$OUTPUT_DIR"

echo "Resource directory: $RESOURCE_DIR"
echo "Output directory: $OUTPUT_DIR"

# Compile C workloads directly in RESOURCE_DIR
echo "Compiling C workloads (sym_c, no_sym_c)..."
if [ -f "$RESOURCE_DIR/sym_c.c" ]; then
    # Compile sym_c with debug symbols
    gcc -O0 -g "$RESOURCE_DIR/sym_c.c" -o "$OUTPUT_DIR/sym_c"
    if [ $? -ne 0 ]; then log_warn "Failed to compile sym_c"; fi
    
    # Compile no_sym_c from the same source file but stripped
    gcc -O0 "$RESOURCE_DIR/sym_c.c" -o "$OUTPUT_DIR/no_sym_c"
    strip "$OUTPUT_DIR/no_sym_c" 2>/dev/null
    if [ $? -ne 0 ]; then log_warn "Failed to compile or strip no_sym_c"; fi
else
    echo "Warning: $RESOURCE_DIR/sym_c.c not found."
fi

# Compile offcpu_sym_c
echo "Compiling C workloads (offcpu_sym_c)..."
if [ -f "$RESOURCE_DIR/offcpu_sym_c.c" ]; then
    # Compile offcpu_sym_c with debug symbols
    gcc -O0 -g "$RESOURCE_DIR/offcpu_sym_c.c" -o "$OUTPUT_DIR/offcpu_sym_c"
    if [ $? -ne 0 ]; then log_warn "Failed to compile offcpu_sym_c"; fi
else
    echo "Warning: $RESOURCE_DIR/offcpu_sym_c.c not found."
fi

# Compile Go workloads directly in RESOURCE_DIR
echo "Compiling Go workloads (sym_go, no_sym_go, sym_go_anon)..."
if ! command -v go >/dev/null 2>&1; then
    log_warn "go not found, skipping Go compilation."
elif [ -f "$RESOURCE_DIR/sym_go.go" ]; then
    # Compile sym_go with full symbols
    go build -o "$OUTPUT_DIR/sym_go" "$RESOURCE_DIR/sym_go.go"
    if [ $? -ne 0 ]; then log_warn "Failed to compile sym_go"; fi
    
    # Compile no_sym_go from the same source file but stripped
    go build -ldflags="-s -w" -o "$OUTPUT_DIR/no_sym_go" "$RESOURCE_DIR/sym_go.go"
    if [ $? -ne 0 ]; then log_warn "Failed to compile no_sym_go"; fi
else
    echo "Warning: $RESOURCE_DIR/sym_go.go not found."
fi

if command -v go >/dev/null 2>&1 && [ -f "$RESOURCE_DIR/sym_go_anon.go" ]; then
    # Compile sym_go_anon with full symbols
    go build -o "$OUTPUT_DIR/sym_go_anon" "$RESOURCE_DIR/sym_go_anon.go"
    if [ $? -ne 0 ]; then log_warn "Failed to compile sym_go_anon"; fi
else
    echo "Warning: $RESOURCE_DIR/sym_go_anon.go not found."
fi

# Compile Rust project (assuming it's in a subdirectory 'rust_project')
echo "Compiling Rust workload (rust_project)..."
if [ -d "$RESOURCE_DIR/rust_project" ]; then
    if command -v cargo >/dev/null 2>&1; then
        (cd "$RESOURCE_DIR/rust_project" && cargo build --release)
        if [ $? -ne 0 ]; then log_warn "Failed to compile rust_workload with Cargo"; fi
        if [ -f "$RESOURCE_DIR/rust_project/target/release/rust_workload" ]; then
            cp "$RESOURCE_DIR/rust_project/target/release/rust_workload" "$OUTPUT_DIR/rust_workload"
        else
            log_warn "rust_workload binary not found after cargo build"
        fi
    else
        echo "Warning: cargo not found, skipping Rust compilation."
    fi
else
    echo "Directory $RESOURCE_DIR/rust_project not found. Skipping Rust compilation."
fi

# Compile kernel modules
log_info "Compiling test_irq_disable kernel module..."
if [ -d "${RESOURCE_DIR}/test_irq_disable" ]; then
    (cd "${RESOURCE_DIR}/test_irq_disable" && make clean && make)
    if [ -f "${RESOURCE_DIR}/test_irq_disable/test_irq_disable.ko" ]; then
        cp "${RESOURCE_DIR}/test_irq_disable/test_irq_disable.ko" "${OUTPUT_DIR}/"
        log_info "test_irq_disable.ko copied to ${OUTPUT_DIR}/"
    else
        log_warn "test_irq_disable.ko not found after compilation."
    fi
else
    log_warn "test_irq_disable directory not found, skipping compilation."
fi

log_info "Compiling test_kworker kernel module..."
if [ -d "${RESOURCE_DIR}/test_kworker" ]; then
    (cd "${RESOURCE_DIR}/test_kworker" && make clean && make && make copy_to_output)
    if [ -f "${OUTPUT_DIR}/cpu_hogger.ko" ]; then
        log_info "cpu_hogger.ko compiled and copied to ${OUTPUT_DIR}/"
    else
        log_warn "cpu_hogger.ko not found after compilation or copy."
    fi
else
    log_warn "test_kworker directory not found, skipping compilation."
fi

# Set executable permissions for all binaries in the output directory
if [ -d "$OUTPUT_DIR" ] && [ "$(ls -A $OUTPUT_DIR)" ]; then
    chmod +x $OUTPUT_DIR/* 2>/dev/null
else
    echo "Warning: Output directory $OUTPUT_DIR is empty or does not exist. No permissions set."
fi

echo "All specified workloads compiled successfully (or skipped if source not found)."
