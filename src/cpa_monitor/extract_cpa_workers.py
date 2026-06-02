# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 ByteDance


import re
import sys

def extract_worker_definitions(c_files):
    worker_definitions = []
    for c_file in c_files:
        with open(c_file, 'r') as f:
            content = f.read()
            # Extract worker registrations from active monitor sources.
            matches = re.findall(r'struct cpa_worker\s+(\w+_worker)\s*=', content)
            for worker_name in matches:
                worker_definitions.append(f'WORKER_DEFINE({worker_name})')
    return worker_definitions

def generate_header(output_file, definitions):
    with open(output_file, 'w') as f:
        f.write('#ifndef WORKER_DEFINE\n')
        f.write('#define WORKER_DEFINE(worker_name) extern struct cpa_worker worker_name;\n')
        f.write('#endif\n\n')
        for definition in definitions:
            f.write(f'{definition}\n')

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python extract_cpa_workers.py <output_header> <c_file1> <c_file2> ...")
        sys.exit(1)
    
    output_header = sys.argv[1]
    c_files = sys.argv[2:]
    
    definitions = extract_worker_definitions(c_files)
    generate_header(output_header, definitions)
