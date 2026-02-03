# New Project Integration Guide: OSS-Fuzz + FuzzIntrospector + LogicFuzz

This document provides detailed instructions on how to integrate a new C/C++ project into OSS-Fuzz, generate a FuzzIntrospector database, and run LogicFuzz for automated fuzz target generation.

> **Verified**: This guide has been fully validated with the `gejingquan-project`, successfully generating 5 fuzz targets with 100% build success rate and maximum coverage of 68.8%.

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Creating an OSS-Fuzz Project](#2-creating-an-oss-fuzz-project)
3. [Building the Project and Generating FI Data](#3-building-the-project-and-generating-fi-data)
4. [Importing the FI Database](#4-importing-the-fi-database)
5. [Creating Benchmark Configuration](#5-creating-benchmark-configuration)
6. [Running LogicFuzz](#6-running-logicfuzz)

---

## 1. Prerequisites

### 1.1 Environment Requirements

- Docker installed and running
- Python 3.10+
- LogicFuzz repository cloned
- Git
- LLM API key (DeepSeek, OpenAI, or Claude)

### 1.2 Directory Structure

```
logicfuzz/
├── oss-fuzz/                # Full OSS-Fuzz repository needs to be cloned
│   ├── infra/               # OSS-Fuzz build infrastructure (required)
│   ├── projects/
│   │   └── your-project/    # New projects go here
│   └── build/out/           # Build output directory
├── conti-benchmark/
│   └── your-project.yaml    # Benchmark configuration
└── fuzz-introspector/       # Needs to be cloned separately
    └── tools/web-fuzzing-introspection/app/static/assets/db/
        ├── all-functions-db-your-project.json
        ├── all-constructors-db-your-project.json
        ├── all-project-current.json
        ├── all-project-timestamps.json
        └── db-timestamps.json
```

### 1.3 Clone OSS-Fuzz (First-time Setup, Required)

**Important**: You must clone the complete OSS-Fuzz repository, as build tools like `infra/helper.py` are required.

```bash
cd /path/to/logicfuzz

# If the oss-fuzz directory is empty or only has the projects subdirectory, re-clone it
rm -rf oss-fuzz
git clone --depth 1 https://github.com/google/oss-fuzz.git oss-fuzz

# Verify the clone was successful
ls oss-fuzz/infra/helper.py  # This file should exist
```

### 1.4 Clone FuzzIntrospector (First-time Setup)

If the `fuzz-introspector/` directory is empty or doesn't exist, clone it first:

```bash
cd /path/to/logicfuzz
git clone https://github.com/ossf/fuzz-introspector fuzz-introspector

# Install dependencies
cd fuzz-introspector/tools/web-fuzzing-introspection
pip install -r requirements.txt
```

---

## 2. Creating an OSS-Fuzz Project

This section uses the `gejingquan-project` as an example to demonstrate how to create a complete OSS-Fuzz project.

### 2.1 Create Project Directory

```bash
cd /path/to/logicfuzz
mkdir -p oss-fuzz/projects/gejingquan-project
cd oss-fuzz/projects/gejingquan-project
```

### 2.2 Create Source Code Files

Using the `gejingquan-project` string parsing library as an example, this library provides various string parsing functions: hex decoding, URL decoding, integer list parsing, string splitting, key-value pair parsing, etc.

**strparser.h**
```c
#ifndef STRPARSER_H
#define STRPARSER_H

#include <stdint.h>
#include <stddef.h>

// Token structure for split operations
typedef struct {
    const char *start;
    size_t length;
} strparser_token_t;

// Key-value pair structure
typedef struct {
    const char *key_start;
    size_t key_length;
    const char *value_start;
    size_t value_length;
} strparser_kv_t;

// Integer list structure
typedef struct {
    int *values;
    size_t count;
    size_t capacity;
} strparser_int_list_t;

// Function declarations

// Check if character is a hex digit
int is_hex_digit(char c);

// Convert hex character to integer value
int hex_to_int(char c);

// Parse a comma-separated list of integers
// Returns 0 on success, -1 on error
int strparser_parse_int_list(const char *input, size_t input_len, strparser_int_list_t *result);

// Free memory allocated for integer list
void strparser_free_int_list(strparser_int_list_t *list);

// Split string by delimiter
// Returns number of tokens found, or -1 on error
int strparser_split(const char *input, size_t input_len, char delimiter,
                    strparser_token_t *tokens, size_t max_tokens, size_t *token_count);

// Parse a single key=value pair
// Returns 0 on success, -1 on error
int strparser_parse_kv(const char *input, size_t input_len, strparser_kv_t *result);

// Parse a list of key=value pairs separated by delimiter
// Returns 0 on success, -1 on error
int strparser_parse_kv_list(const char *input, size_t input_len, char delimiter,
                            strparser_kv_t *kvs, size_t max_kvs, size_t *kv_count);

// URL decode a string
// Returns 0 on success, -1 on error
int strparser_url_decode(const char *input, size_t input_len,
                         char *output, size_t output_size, size_t *output_len);

// Hex decode a string
// Returns 0 on success, -1 on error
int strparser_hex_decode(const char *input, size_t input_len,
                         uint8_t *output, size_t output_size, size_t *output_len);

#endif // STRPARSER_H
```

**strparser.c**
```c
#include "strparser.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

// Check if character is a hex digit
int is_hex_digit(char c) {
    return (c >= '0' && c <= '9') ||
           (c >= 'a' && c <= 'f') ||
           (c >= 'A' && c <= 'F');
}

// Convert hex character to integer value
int hex_to_int(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// Parse a comma-separated list of integers
int strparser_parse_int_list(const char *input, size_t input_len, strparser_int_list_t *result) {
    if (!input || !result) return -1;

    result->values = NULL;
    result->count = 0;
    result->capacity = 0;

    if (input_len == 0) return 0;

    size_t i = 0;
    while (i < input_len) {
        // Skip whitespace
        while (i < input_len && isspace((unsigned char)input[i])) i++;
        if (i >= input_len) break;

        // Check for negative sign
        int negative = 0;
        if (input[i] == '-') {
            negative = 1;
            i++;
        }

        // Parse number
        if (i >= input_len || !isdigit((unsigned char)input[i])) {
            // Invalid format
            free(result->values);
            result->values = NULL;
            result->count = 0;
            return -1;
        }

        int value = 0;
        while (i < input_len && isdigit((unsigned char)input[i])) {
            value = value * 10 + (input[i] - '0');
            i++;
        }
        if (negative) value = -value;

        // Add to result
        if (result->count >= result->capacity) {
            size_t new_capacity = result->capacity == 0 ? 8 : result->capacity * 2;
            int *new_values = realloc(result->values, new_capacity * sizeof(int));
            if (!new_values) {
                free(result->values);
                result->values = NULL;
                result->count = 0;
                return -1;
            }
            result->values = new_values;
            result->capacity = new_capacity;
        }
        result->values[result->count++] = value;

        // Skip whitespace
        while (i < input_len && isspace((unsigned char)input[i])) i++;

        // Expect comma or end
        if (i < input_len) {
            if (input[i] == ',') {
                i++;
            } else {
                // Invalid character
                free(result->values);
                result->values = NULL;
                result->count = 0;
                return -1;
            }
        }
    }

    return 0;
}

// Free memory allocated for integer list
void strparser_free_int_list(strparser_int_list_t *list) {
    if (list && list->values) {
        free(list->values);
        list->values = NULL;
        list->count = 0;
        list->capacity = 0;
    }
}

// Split string by delimiter
int strparser_split(const char *input, size_t input_len, char delimiter,
                    strparser_token_t *tokens, size_t max_tokens, size_t *token_count) {
    if (!input || !tokens || !token_count || max_tokens == 0) return -1;

    *token_count = 0;

    if (input_len == 0) {
        return 0;
    }

    size_t start = 0;
    for (size_t i = 0; i <= input_len; i++) {
        if (i == input_len || input[i] == delimiter) {
            if (*token_count >= max_tokens) {
                return -1; // Buffer too small
            }
            tokens[*token_count].start = input + start;
            tokens[*token_count].length = i - start;
            (*token_count)++;
            start = i + 1;
        }
    }

    return 0;
}

// Parse a single key=value pair
int strparser_parse_kv(const char *input, size_t input_len, strparser_kv_t *result) {
    if (!input || !result) return -1;

    result->key_start = NULL;
    result->key_length = 0;
    result->value_start = NULL;
    result->value_length = 0;

    if (input_len == 0) return -1;

    // Find the '=' character
    size_t eq_pos = 0;
    int found = 0;
    for (size_t i = 0; i < input_len; i++) {
        if (input[i] == '=') {
            eq_pos = i;
            found = 1;
            break;
        }
    }

    if (!found) return -1;

    // Extract key (trim whitespace)
    size_t key_start = 0;
    size_t key_end = eq_pos;
    while (key_start < key_end && isspace((unsigned char)input[key_start])) key_start++;
    while (key_end > key_start && isspace((unsigned char)input[key_end - 1])) key_end--;

    // Extract value (trim whitespace)
    size_t value_start = eq_pos + 1;
    size_t value_end = input_len;
    while (value_start < value_end && isspace((unsigned char)input[value_start])) value_start++;
    while (value_end > value_start && isspace((unsigned char)input[value_end - 1])) value_end--;

    result->key_start = input + key_start;
    result->key_length = key_end - key_start;
    result->value_start = input + value_start;
    result->value_length = value_end - value_start;

    return 0;
}

// Parse a list of key=value pairs separated by delimiter
int strparser_parse_kv_list(const char *input, size_t input_len, char delimiter,
                            strparser_kv_t *kvs, size_t max_kvs, size_t *kv_count) {
    if (!input || !kvs || !kv_count || max_kvs == 0) return -1;

    *kv_count = 0;

    if (input_len == 0) return 0;

    // First split by delimiter
    strparser_token_t *tokens = malloc(max_kvs * sizeof(strparser_token_t));
    if (!tokens) return -1;

    size_t token_count;
    if (strparser_split(input, input_len, delimiter, tokens, max_kvs, &token_count) != 0) {
        free(tokens);
        return -1;
    }

    // Parse each token as key=value
    for (size_t i = 0; i < token_count; i++) {
        if (*kv_count >= max_kvs) {
            free(tokens);
            return -1;
        }
        if (strparser_parse_kv(tokens[i].start, tokens[i].length, &kvs[*kv_count]) == 0) {
            (*kv_count)++;
        }
    }

    free(tokens);
    return 0;
}

// URL decode a string
int strparser_url_decode(const char *input, size_t input_len,
                         char *output, size_t output_size, size_t *output_len) {
    if (!input || !output || !output_len || output_size == 0) return -1;

    *output_len = 0;

    for (size_t i = 0; i < input_len; i++) {
        if (*output_len >= output_size - 1) return -1; // Buffer too small

        if (input[i] == '%' && i + 2 < input_len &&
            is_hex_digit(input[i + 1]) && is_hex_digit(input[i + 2])) {
            // Decode hex sequence
            int high = hex_to_int(input[i + 1]);
            int low = hex_to_int(input[i + 2]);
            output[*output_len] = (char)((high << 4) | low);
            (*output_len)++;
            i += 2;
        } else if (input[i] == '+') {
            // '+' represents space
            output[*output_len] = ' ';
            (*output_len)++;
        } else {
            output[*output_len] = input[i];
            (*output_len)++;
        }
    }

    output[*output_len] = '\0';
    return 0;
}

// Hex decode a string
int strparser_hex_decode(const char *input, size_t input_len,
                         uint8_t *output, size_t output_size, size_t *output_len) {
    if (!input || !output || !output_len) return -1;

    *output_len = 0;

    // Input length must be even for valid hex
    if (input_len % 2 != 0) return -1;

    size_t expected_output_len = input_len / 2;
    if (expected_output_len > output_size) return -1;

    for (size_t i = 0; i < input_len; i += 2) {
        if (!is_hex_digit(input[i]) || !is_hex_digit(input[i + 1])) {
            return -1;
        }
        int high = hex_to_int(input[i]);
        int low = hex_to_int(input[i + 1]);
        output[*output_len] = (uint8_t)((high << 4) | low);
        (*output_len)++;
    }

    return 0;
}
```

### 2.3 Create Dockerfile

```dockerfile
FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update && apt-get install -y \
    make \
    gcc \
    libjpeg-dev \
    zlib1g-dev \
    libyaml-dev

COPY strparser.h strparser.c $SRC/gejingquan-project/
WORKDIR $SRC/gejingquan-project
COPY build.sh $SRC/
```

### 2.4 Create build.sh

**Important**: build.sh must create a fuzzer that calls library functions, otherwise FuzzIntrospector cannot capture function information.

```bash
#!/bin/bash -eu

cd $SRC/gejingquan-project

# Compile the library
$CC $CFLAGS -c strparser.c -o strparser.o
ar rcs libstrparser.a strparser.o

# Create fuzzer source that calls library functions
cat > $SRC/fuzzer.c << 'EOF'
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "strparser.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) return 0;

    // Create null-terminated string
    char *input = (char *)malloc(size + 1);
    if (!input) return 0;
    memcpy(input, data, size);
    input[size] = '\0';

    // Test hex decode
    uint8_t hex_output[256];
    size_t hex_decoded_len;
    strparser_hex_decode(input, size, hex_output, sizeof(hex_output), &hex_decoded_len);

    // Test URL decode
    char url_output[512];
    size_t url_decoded_len;
    strparser_url_decode(input, size, url_output, sizeof(url_output), &url_decoded_len);

    // Test integer list parsing
    strparser_int_list_t int_list;
    if (strparser_parse_int_list(input, size, &int_list) == 0) {
        strparser_free_int_list(&int_list);
    }

    // Test split
    strparser_token_t tokens[32];
    size_t token_count;
    strparser_split(input, size, ',', tokens, 32, &token_count);

    // Test key-value parsing
    strparser_kv_t kv;
    strparser_parse_kv(input, size, &kv);

    // Test key-value list parsing
    strparser_kv_t kvs[16];
    size_t kv_count;
    strparser_parse_kv_list(input, size, '&', kvs, 16, &kv_count);

    free(input);
    return 0;
}
EOF

# Compile fuzzer
$CC $CFLAGS -I$SRC/gejingquan-project -c $SRC/fuzzer.c -o $WORK/fuzzer.o
$CXX $CXXFLAGS $LIB_FUZZING_ENGINE $WORK/fuzzer.o \
    $SRC/gejingquan-project/libstrparser.a -o $OUT/gejingquan_project_fuzzer

# Copy source files for coverage
cp $SRC/gejingquan-project/strparser.h $OUT/
cp $SRC/gejingquan-project/strparser.c $OUT/
```

**Note**: Add execute permission after creation:
```bash
chmod +x build.sh
```

#### 2.4.1 Understanding the Stub Fuzzer (fuzzer.c)

The `fuzzer.c` created in build.sh is a **Stub Fuzzer** that serves two key purposes:

**1. Enabling FuzzIntrospector to Capture Function Information (Required)**

FuzzIntrospector discovers library functions by analyzing the call relationships of the fuzzer. Without a fuzzer calling the library functions, FuzzIntrospector **cannot capture** information about these functions.

The stub fuzzer must call all target functions that need to be analyzed by LogicFuzz, as shown in the example above:
```c
// Call all target functions in fuzzer.c
strparser_hex_decode(...);
strparser_url_decode(...);
strparser_parse_int_list(...);
strparser_split(...);
strparser_parse_kv(...);
strparser_parse_kv_list(...);
```

This allows FuzzIntrospector to capture function signatures, parameter types, source code locations, and other information when building with `--sanitizer introspector`, generating the `all-fuzz-introspector-functions.json` database.

**2. Providing Basic Fuzzing Capability**

This fuzzer is also a functional libFuzzer target that:
- Receives random input data (`data`, `size`)
- Passes data to various library functions for testing
- Can discover crashes and vulnerabilities in the library

**Stub Fuzzer vs LogicFuzz-generated Fuzz Target**

| Feature | fuzzer.c (Stub Fuzzer) | LogicFuzz-generated Fuzz Target |
|---------|------------------------|--------------------------------|
| **Purpose** | Enable FI to capture function info | Deep testing of specific functions |
| **Input Construction** | Simple (passes raw data directly) | Smart (uses FuzzedDataProvider) |
| **Parameter Handling** | Fixed buffer sizes | Dynamic allocation, boundary checks |
| **Function Coverage** | One fuzzer covers all functions | Dedicated fuzzer for each function |
| **Code Quality** | Hand-written, simpler | LLM-generated, considers preconditions |

> **Important**: `fuzzer.c` is a **prerequisite** for FuzzIntrospector data collection. Without it, the function database cannot be generated, and LogicFuzz will not work.

### 2.5 Create project.yaml

```yaml
homepage: "https://github.com/gejingquan/gejingquan-project"
language: c
primary_contact: "gejingquan@example.com"
main_repo: "https://github.com/gejingquan/gejingquan-project"
fuzzing_engines:
  - libfuzzer
sanitizers:
  - address
  - undefined
```

---

## 3. Building the Project and Generating FI Data

### 3.1 Build with Introspector Sanitizer

```bash
cd /path/to/logicfuzz/oss-fuzz

# Build Docker image (enter 'n' to skip pulling base image)
echo "n" | python infra/helper.py build_image gejingquan-project

# Build with introspector sanitizer (generates FI data)
python infra/helper.py build_fuzzers --sanitizer introspector gejingquan-project
```

### 3.2 Verify Build Results

```bash
# Check the generated fuzzer and inspector data
ls -la build/out/gejingquan-project/
ls -la build/out/gejingquan-project/inspector/

# You should see files like:
# build/out/gejingquan-project/
#   gejingquan_project_fuzzer
#   strparser.c
#   strparser.h
# build/out/gejingquan-project/inspector/
#   all-fuzz-introspector-functions.json
#   source-code/
```

### 3.3 Verify Captured Functions

```bash
# View captured functions
cat build/out/gejingquan-project/inspector/all-fuzz-introspector-functions.json | python3 -m json.tool | head -50
```

---

## 4. Importing the FI Database

### 4.1 Create Database Directory

```bash
mkdir -p fuzz-introspector/tools/web-fuzzing-introspection/app/static/assets/db
cd fuzz-introspector/tools/web-fuzzing-introspection/app/static/assets/db
```

### 4.2 Convert FI Data to Webapp Format

```bash
python3 << 'EOF'
import json
import os

PROJECT = "gejingquan-project"  # Change to your project name
OSS_FUZZ_DIR = "/path/to/logicfuzz/oss-fuzz"  # Change to actual path

# Read function data generated by introspector
inspector_dir = os.path.join(OSS_FUZZ_DIR, "build", "out", PROJECT, "inspector")
functions_file = os.path.join(inspector_dir, "all-fuzz-introspector-functions.json")

with open(functions_file, 'r') as f:
    functions_data = json.load(f)

# Convert to FI webapp format (note: field names differ from original data)
converted = []
for func in functions_data:
    converted.append({
        "name": func.get("Func name", ""),
        "file": func.get("Functions filename", ""),
        "sig": func.get("function_signature", ""),
        "cov": 0.0,
        "fuzzers": func.get("Reached by Fuzzers", []),
        "cov_fuzzers": func.get("Runtime reached by Fuzzers", []),
        "comb_fuzzers": func.get("Combined reached by Fuzzers", []),
        "cov_url": "",
        "icount": func.get("I Count", 0),
        "acc_cc": func.get("Accumulated cyclomatic complexity", 0),
        "u-cc": func.get("Undiscovered complexity", 0),
        "args": func.get("Args", []),
        "args-names": func.get("ArgNames", []),
        "rtn": func.get("return_type", ""),
        "raw-name": func.get("raw-function-name", ""),
        "src_begin": func.get("source_line_begin", -1),
        "src_end": func.get("source_line_end", -1),
        "debug": func.get("debug_function_info", {}),
        "access": func.get("is_accessible", True),
        "asserts": func.get("asserts", [])
    })

# Write database file
with open(f"all-functions-db-{PROJECT}.json", "w") as f:
    json.dump(converted, f, indent=2)

# Create empty constructors database
with open(f"all-constructors-db-{PROJECT}.json", "w") as f:
    json.dump([], f)

print(f"Created all-functions-db-{PROJECT}.json with {len(converted)} functions")
EOF
```

### 4.3 Register Project in FI Database

**Important**: New projects must be added to FI's project configuration files, otherwise FI cannot recognize the project.

```bash
python3 << 'EOF'
import json
import os
from datetime import date

PROJECT_NAME = "gejingquan-project"  # Change to your project name
FUNCTION_COUNT = 9  # Change to actual function count

def load_or_create(filename, default_content):
    """Load file or create new file"""
    if os.path.exists(filename):
        with open(filename, 'r') as f:
            return json.load(f)
    return default_content

# Add to all-project-current.json
projects = load_or_create('all-project-current.json', [])

if not any(p.get('project_name') == PROJECT_NAME for p in projects):
    projects.append({
        "project_name": PROJECT_NAME,
        "date": str(date.today()),
        "language": "c",
        "coverage-data": {"coverage_url": "", "line_coverage": {"count": 0, "covered": 0, "percent": 0.0}},
        "per-fuzzer-coverage-data": {},
        "introspector-data": {
            "introspector_report_url": "",
            "coverage_lines": 0.0,
            "static_reachability": 0.0,
            "fuzzer_count": 1,
            "function_count": FUNCTION_COUNT,
            "functions_covered_estimate": 0.0,
            "annotated_cfg": [],
            "optimal_targets": [],
            "project_name": PROJECT_NAME,
            "typedef_list": [],
            "macro_block": []
        },
        "fuzzer-count": 1,
        "project_repository": f"https://github.com/example/{PROJECT_NAME}",
        "light-introspector": {"test-files": [], "all-files": [], "all-pairs": []},
        "recent_results": {}
    })
    with open('all-project-current.json', 'w') as f:
        json.dump(projects, f, indent=2)
    print(f"Added {PROJECT_NAME} to all-project-current.json")
else:
    print(f"{PROJECT_NAME} already exists in all-project-current.json")

# Add to all-project-timestamps.json
timestamps = load_or_create('all-project-timestamps.json', [])

if not any(p.get('project_name') == PROJECT_NAME for p in timestamps):
    timestamps.append({
        "date": str(date.today()),
        "project_name": PROJECT_NAME,
        "language": "c",
        "coverage-data": True,
        "introspector-data": True,
        "fuzzer-count": 1,
        "introspector_url": "",
        "project_url": "",
        "project_repository": f"https://github.com/example/{PROJECT_NAME}"
    })
    with open('all-project-timestamps.json', 'w') as f:
        json.dump(timestamps, f, indent=2)
    print(f"Added {PROJECT_NAME} to all-project-timestamps.json")
else:
    print(f"{PROJECT_NAME} already exists in all-project-timestamps.json")

print("Done!")
EOF
```

### 4.4 Create db-timestamps.json (Required)

**Important**: The FI webapp requires this file to start.

```bash
cat > db-timestamps.json << 'EOF'
[
  {
    "date": "2026-01-27",
    "project_count": 1,
    "fuzzer_count": 1,
    "function_count": 9,
    "function_coverage_estimate": 0.0,
    "accummulated_lines_total": 100,
    "accummulated_lines_covered": 0
  }
]
EOF
```

### 4.5 Start FI Local Service

**Key**: You must set the `FUZZ_INTROSPECTOR_LOCAL_OSS_FUZZ` environment variable pointing to the OSS-Fuzz directory, so FI can read the locally built source code.

```bash
cd /path/to/logicfuzz/fuzz-introspector/tools/web-fuzzing-introspection/app

# Set local mode environment variable (important!)
export FUZZ_INTROSPECTOR_LOCAL_OSS_FUZZ=/path/to/logicfuzz/oss-fuzz

# Start Flask application (foreground)
python3 main.py

# Or run in background
nohup python3 main.py > /tmp/fi_server.log 2>&1 &
```

After the service starts, you should see:
```
Local webapp is set
Loading db
 * Running on http://0.0.0.0:8080
```

**Note**: If you don't see "Local webapp is set", the environment variable was not set correctly, and source code lookup will not work.

### 4.6 Verify API

```bash
# Get all functions for the project
curl -s "http://localhost:8080/api/all-functions?project=gejingquan-project" | python3 -m json.tool | head -30

# Get specific function signature
curl -s "http://localhost:8080/api/function-signature?project=gejingquan-project&function=strparser_hex_decode" | python3 -m json.tool

# Test source code retrieval (key test)
curl -s "http://localhost:8080/api/function-source-code?project=gejingquan-project&function_signature=int%20strparser_hex_decode(const%20char%20*,%20size_t,%20uint8_t%20*,%20size_t,%20size_t%20*)" | python3 -m json.tool
```

If the service is running properly, it will return JSON data. If it returns `{"msg":"No source code","result":"error"}`, it means:
1. The `FUZZ_INTROSPECTOR_LOCAL_OSS_FUZZ` environment variable was not set correctly
2. Or the project was not added to `all-project-current.json`

---

## 5. Creating Benchmark Configuration

Create `gejingquan-project.yaml` in the `conti-benchmark/` directory:

**Important**: Types in the `signature` field must use space separation (e.g., `const char *` instead of `const char*`), matching the signature format returned by the FI API.

```yaml
"functions":
- "name": "strparser_hex_decode"
  "params":
  - "name": "input"
    "type": "const char*"
  - "name": "input_len"
    "type": "size_t"
  - "name": "output"
    "type": "uint8_t*"
  - "name": "output_size"
    "type": "size_t"
  - "name": "output_len"
    "type": "size_t*"
  "return_type": "int"
  "signature": "int strparser_hex_decode(const char *, size_t, uint8_t *, size_t, size_t *)"

"language": "c"
"project": "gejingquan-project"
"target_name": "gejingquan_project_fuzzer"
"target_path": "/src/gejingquan-project/fuzzer.c"
```

**Tip**: You can get the correct signature format via FI API:
```bash
curl -s "http://localhost:8080/api/function-signature?project=gejingquan-project&function=strparser_hex_decode" | python3 -c "import sys,json; print(json.load(sys.stdin)['signature'])"
```

---

## 6. Running LogicFuzz

### 6.1 Set Environment Variables

```bash
# Disable OSS-Fuzz cleanup (prevents custom projects from being deleted)
export OFG_CLEAN_UP_OSS_FUZZ=0

# Set LLM API key (choose based on model used)
export DEEPSEEK_API_KEY=your-api-key
# Or
export OPENAI_API_KEY=your-api-key
```

### 6.2 Run LogicFuzz

```bash
cd /path/to/logicfuzz

python run_logicfuzz.py \
  -y conti-benchmark/gejingquan-project.yaml \
  --model deepseek-chat \
  -n 1 \
  --run-timeout 60 \
  -e http://localhost:8080/api \
  -of oss-fuzz
```

### 6.3 Parameter Description

| Parameter | Description |
|-----------|-------------|
| `-y` | Benchmark YAML configuration file path |
| `--model` | LLM model (deepseek-chat, gpt-4o, claude-3-5-sonnet, etc.) |
| `-n` | Number of trials |
| `--run-timeout` | Fuzzer run timeout in seconds |
| `-e` | FuzzIntrospector API endpoint |
| `-of` | OSS-Fuzz directory path |
| `--enable-source-filter` | Enable source code filtering |
| `--source-filter-min-lines` | Minimum lines threshold for source code filtering |

### 6.4 Run Example

```bash
# Complete command with source code filtering
python run_logicfuzz.py \
  -y conti-benchmark/gejingquan-project.yaml \
  --model deepseek-chat \
  -n 1 \
  --run-timeout 60 \
  -e http://localhost:8080/api \
  -of oss-fuzz \
  --enable-source-filter \
  --source-filter-min-lines 50
```

### 6.5 View Results

```bash
# Generated fuzz target
cat results/output-gejingquan-project-strparser_hex_decode/fuzz_targets/01.fuzz_target

# Coverage report
ls results/output-gejingquan-project-strparser_hex_decode/code-coverage-reports/

# Log files
ls results/output-gejingquan-project-strparser_hex_decode/logs/

# Benchmark configuration
cat results/output-gejingquan-project-strparser_hex_decode/benchmark.yaml
```

### 6.6 Expected Output

After a successful run, the log should show something like:
```
**** FINAL RESULTS: ****

================================================================================
*gejingquan-project, int strparser_hex_decode(const char *, size_t, uint8_t *, size_t, size_t *)*
build success rate: 1.0, crash rate: 0.0, found bug: 0, max coverage: 0.6880733944954128, max line coverage diff: 0.9086021505376344

**** TOTAL COVERAGE GAIN: ****
*gejingquan-project: 0.9941176470588236
```

**Key Metrics Description**:
| Metric | Description | Ideal Value |
|--------|-------------|-------------|
| build success rate | Build success rate | 1.0 (100%) |
| crash rate | Crash rate | 0.0 (0%) |
| max coverage | Maximum code coverage | > 0.5 |
| max line coverage diff | Maximum line coverage increase | > 0.8 |
| TOTAL COVERAGE GAIN | Total coverage gain | > 0.9 |
