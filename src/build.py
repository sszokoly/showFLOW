#!/usr/bin/env python
# -*- encoding: utf-8 -*-

import os

MODULES = [
    "flow_parser",
    "sbce",
]

def read_file(filepath):
    with open(filepath, "r", encoding="utf-8") as f:
        return f.read()

def read_module_doc(module_name, folder="src"):
    doc_path = f"{folder}/{module_name}.py"
    if os.path.exists(doc_path):
        return read_file(doc_path)
    return ""

def extract_marker_indexes(marker_name, content):
    marker_name = marker_name.upper()   
    start_marker = f"### BEGIN {marker_name}"
    end_marker = f"### END {marker_name} "

    lines = content.splitlines()
    start_lines = [x for x in range(len(lines)) if start_marker in lines[x]]
    end_lines = [x for x in range(len(lines)) if end_marker in lines[x]]

    if start_lines and end_lines:
        return start_lines[0], end_lines[0]
    return -1, -1

def extract_lines(marker_name, content):
    start_idx, end_idx = extract_marker_indexes(marker_name, content)
    if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
        lines = content.splitlines()
        return lines[start_idx:end_idx + 1]

def extract_module(module_name):
    module_doc = read_module_doc(module_name)
    if not module_doc:
        return ""
    extracted_lines = extract_lines(module_name, module_doc)
    if extracted_lines:
        return extracted_lines
    return ""

def build_python_script(main_module="main", output_file="showFLOW.py"):
    module_doc = read_module_doc(main_module)
    
    import_marker_indexes = extract_marker_indexes("IMPORTS", module_doc)
    module_marker_indexes = extract_marker_indexes("MODULES", module_doc)

    if module_marker_indexes == (-1, -1):
        print("No MODULES markers found in main.py")
        return

    _, imports_end_idx = import_marker_indexes
    _, module_end_idx = module_marker_indexes
    main_module_lines = module_doc.splitlines()
    imports = main_module_lines[:imports_end_idx + 1]
    after_modules = main_module_lines[module_end_idx + 1:]

    with open(output_file, "w", encoding="utf-8") as out_file:
        for line in imports:
            out_file.write(line + "\n")
        for module in MODULES:
            module_doc = read_module_doc(module)
            if module_doc:
                extracted_content = extract_module(module)
                if extracted_content:
                    for line in extracted_content:
                        out_file.write(line + "\n")
        for line in after_modules:
            out_file.write(line + "\n")

    os.chmod(output_file, 0o755)


if __name__ == "__main__":
    build_python_script()
