#!/usr/bin/env python3

import os
import sys
from pathlib import Path

print(f"Current working directory: {os.getcwd()}")
print(f"Python path: {sys.path}")

# Add current directory to path
sys.path.insert(0, '.')

from mcp_server.util import load_schema, SCHEMA_DIR

print(f"\nSCHEMA_DIR: {SCHEMA_DIR}")
print(f"SCHEMA_DIR exists: {SCHEMA_DIR.exists()}")
print(f"SCHEMA_DIR is directory: {SCHEMA_DIR.is_dir()}")

# List files in schema directory
if SCHEMA_DIR.exists():
    print(f"\nFiles in SCHEMA_DIR:")
    for file in SCHEMA_DIR.iterdir():
        print(f"  {file.name} - exists: {file.exists()}")

# Test specific file
target_file = SCHEMA_DIR / "net.scan_basic.json"
print(f"\nTarget file: {target_file}")
print(f"Target file exists: {target_file.exists()}")
print(f"Target file is file: {target_file.is_file()}")

if target_file.exists():
    try:
        with open(target_file, 'r', encoding='utf-8') as f:
            content = f.read()
            print(f"File size: {len(content)} characters")
            print(f"First 100 chars: {content[:100]}")
    except Exception as e:
        print(f"Error reading file: {e}")

# Test schema loading
print(f"\nTesting schema loading:")
schema = load_schema("net.scan_basic")
print(f"Schema loaded: {schema is not None}")
if schema:
    print(f"Schema title: {schema.get('title', 'N/A')}")